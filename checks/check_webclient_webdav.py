""" checks/check_webclient_webdav.py -- WebClient (WebDAV) Coercion Surface

The Windows WebClient service (the WebDAV redirector) lets an attacker coerce a
host into authenticating over HTTP. Unlike SMB coercion, HTTP authentication is
not signed, so the captured NTLM auth can be relayed to high-value endpoints:
  - AD CS HTTP Web Enrollment (ESC8) to obtain a certificate for the victim, or
  - LDAP to configure resource-based constrained delegation (RBCD).
A machine account coerced via WebClient and relayed to ADCS/LDAP can lead to
takeover of that host or domain escalation.

WebClient is the HTTP half of the coercion story that pairs with the Print
Spooler (PrinterBug) check and ESC8. It is off by default on servers but is
frequently present on workstations (and is pulled in by features such as
"Map network drive"). Any host running it is a ready coercion-and-relay target.

Two-phase approach, mirroring check_smb.py:
  Phase 1 -- enumerate computer objects via the connector's LDAP connection and
             write them to Reports/Artifacts/computers_<ts>.txt
  Phase 2 -- nxc smb <targets> -M webdav, parsing for hosts where the WebClient
             service is enabled.

Findings:
  Any WebClient-enabled host -> HIGH, -15 points
  None enabled               -> INFO / PASS, 0 points

Prerequisites:
  nxc (uv tool install netexec or python adscan.py --setup-tools)
  Active LDAP connection on the connector (for the Phase 1 computer list)
"""

import os
import re
import subprocess  # nosec B404 - subprocess is required to invoke netexec
from datetime import datetime

from lib.tools import ensure_tool

CHECK_NAME     = "WebClient (WebDAV) Coercion Surface"
CHECK_ORDER    = 27  # runs right after Print Spooler (26)
CHECK_CATEGORY = ["Protocol Security"]
CHECK_WEIGHT   = 15   # max deduction at stake for this check module

_PW_FLAGS = {"-p", "--password", "-P", "--secret", "--hashes", "--hash", "-H"}
_CRED_RE = re.compile(r'([A-Za-z0-9._-]+\\[A-Za-z0-9._-]+):(\S+)')


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run_cmd(cmd, timeout=300):
    """Run a subprocess command, return (returncode, stdout, stderr)."""
    result = subprocess.run(  # nosec B603 - cmd is a fully validated list, no shell interpolation
        cmd, capture_output=True, text=True, timeout=timeout,
    )
    return result.returncode, result.stdout, result.stderr


def _enumerate_computers_via_ldap(connector):
    """Enumerate computer objects via the connector's existing LDAP connection.

    Returns a list of unique hostnames (dNSHostName preferred, cn fallback).
    """
    log = connector.log
    if not getattr(connector, "ldap_conn", None):
        log.warning(" [WebDAV] No active LDAP connection on connector — cannot enumerate computers.")
        return []

    entries = connector.ldap_search(
        search_filter="(objectClass=computer)",
        attributes=["dNSHostName", "cn"],
    ) or []

    targets, seen = [], set()
    for entry in entries:
        dns = (entry.get("dNSHostName") or "").strip()
        cn  = (entry.get("cn") or "").strip()
        host = dns or cn
        if host and host not in seen:
            seen.add(host)
            targets.append(host)

    log.debug(" [WebDAV] Enumerated %d computer(s) via LDAP.", len(targets))
    return targets


def _build_nxc_smb_auth_args(connector):
    """Return the nxc SMB authentication arguments as a list."""
    username = getattr(connector, "username", None)
    password = getattr(connector, "password", None)
    nt_hash  = getattr(connector, "nt_hash", None)
    lm_hash  = getattr(connector, "lm_hash", "") or ""
    domain   = getattr(connector, "domain", "")

    args = ["-u", username or ""]
    if nt_hash:
        args += ["-H", f"{lm_hash}:{nt_hash}" if lm_hash else nt_hash]
    elif password:
        args += ["-p", password]
    else:
        args += ["-p", ""]
    if domain:
        args += ["-d", domain]
    return args


def _redact_cmd(cmd):
    """Return a log-safe command string with secret-flag values masked."""
    out, skip = [], False
    for tok in cmd:
        if skip:
            out.append("REDACTED")
            skip = False
        elif tok in _PW_FLAGS:
            out.append(tok)
            skip = True
        else:
            out.append(tok)
    return " ".join(out)


def _redact_output(text):
    return _CRED_RE.sub(r"\1:REDACTED", text or "")


def _parse_webdav_results(nxc_output):
    """Parse 'nxc smb -M webdav' output.

    Returns (enabled_hosts, reachable_count).

    The webdav module highlights enabled hosts with a line containing
    'WebClient Service enabled on: <host>'. The standard nxc SMB connection
    line ('SMB <ip> 445 <host> ...') is emitted for every reachable host and
    is used to count how many hosts were actually contacted.
    """
    enabled, reachable = [], set()

    smb_re = re.compile(r"^SMB\s+(\S+)\s+\d+\s+(\S+)", re.IGNORECASE)
    host_prefix_re = re.compile(r"^\S+\s+(\S+)\s+\d+\s+(\S+)")
    enabled_on_re = re.compile(r"enabled on:\s*(\S+)", re.IGNORECASE)

    for line in nxc_output.splitlines():
        sm = smb_re.search(line)
        if sm:
            reachable.add(sm.group(1))

        if "webclient" in line.lower() and "enabled" in line.lower():
            pm = host_prefix_re.search(line)
            if pm:
                ip, hostname = pm.group(1), pm.group(2)
                label = f"{hostname} ({ip})" if hostname != ip else ip
            else:
                em = enabled_on_re.search(line)
                label = em.group(1) if em else line.strip()
            if label not in enabled:
                enabled.append(label)

    return enabled, len(reachable)


# ---------------------------------------------------------------------------
# Main check entry point
# ---------------------------------------------------------------------------

def run_check(connector, verbose=False):
    findings = []
    log      = connector.log

    nxc_exe = ensure_tool("nxc")
    if nxc_exe is None:
        findings.append({
            "title": "WebClient (WebDAV) Coercion Surface -- NetExec Not Found",
            "severity": "info",
            "deduction": 0,
            "description": (
                "NetExec (nxc) is required for the WebDAV sweep but was not found on PATH. "
                "Install with: uv tool install netexec"
            ),
            "recommendation": "Run: python adscan.py --setup-tools",
            "details": ["nxc not found on PATH.", "Or: python adscan.py --setup-tools"],
        })
        return findings

    artifacts_dir = getattr(connector, "artifacts_dir", "Reports/Artifacts")
    dbg           = getattr(connector, "debug_log", None)

    # ---- Phase 1: enumerate computers via LDAP ----
    targets = _enumerate_computers_via_ldap(connector)
    if not targets:
        findings.append({
            "title": "WebClient (WebDAV) Coercion Surface -- No Computers Found via LDAP",
            "severity": "info",
            "deduction": 0,
            "description": (
                "The LDAP computer enumeration returned no results. Ensure the connector "
                "has an active LDAP connection and the account can read computer objects."
            ),
            "recommendation": "Verify LDAP connectivity and account permissions.",
            "details": ["connector.ldap_search(objectClass=computer) returned 0 entries."],
        })
        return findings

    os.makedirs(artifacts_dir, exist_ok=True)
    run_ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    targets_file = os.path.join(artifacts_dir, f"computers_{run_ts}.txt")
    with open(targets_file, "w", encoding="utf-8") as fh:
        fh.write("\n".join(targets) + "\n")
    log.debug(" [WebDAV] Found %d computer(s). List saved to: %s", len(targets), targets_file)

    # ---- Phase 2: WebDAV sweep via NetExec ----
    cmd = [nxc_exe, "smb", targets_file] + _build_nxc_smb_auth_args(connector) + ["-M", "webdav"]
    if getattr(connector, "dns_server", None):
        cmd += ["--dns-server", connector.dns_server]
    if getattr(connector, "dns_tcp", False):
        cmd += ["--dns-tcp"]

    cmd_log = _redact_cmd(cmd)
    log.debug(" [WebDAV] Phase 2: sweeping %d host(s) for the WebClient service ...", len(targets))
    log.debug(" [WebDAV] Command: %s", cmd_log)

    try:
        rc, out, err = _run_cmd(cmd, timeout=300)
    except subprocess.TimeoutExpired:
        findings.append({
            "title": "WebClient (WebDAV) Coercion Surface -- Sweep Timed Out",
            "severity": "info",
            "deduction": 0,
            "description": "NetExec WebDAV sweep timed out after 300 seconds.",
            "recommendation": "Check network connectivity or reduce the number of targets.",
            "details": ["nxc smb -M webdav sweep timed out."],
        })
        return findings
    except Exception as e:
        findings.append({
            "title": "WebClient (WebDAV) Coercion Surface -- Sweep Failed",
            "severity": "info",
            "deduction": 0,
            "description": f"nxc smb -M webdav sweep raised an exception: {e}",
            "recommendation": "Verify nxc is installed and credentials are valid.",
            "details": [str(e)],
        })
        return findings

    if dbg:
        dbg.log_subprocess(cmd=cmd, cwd=None, returncode=rc, stdout=out, stderr=err)

    raw_output = cmd_log + "\n\n" + _redact_output(out).rstrip()
    enabled_hosts, reachable = _parse_webdav_results(out or "")

    if enabled_hosts:
        detail_lines = [
            f"Computer list: {targets_file}",
            f"Reachable: {reachable} host(s) | WebClient enabled: {len(enabled_hosts)}",
            "",
            "Hosts with the WebClient (WebDAV) service enabled:",
        ] + [f"  {h}" for h in sorted(enabled_hosts)]
        findings.append({
            "title": f"WebClient (WebDAV) Service Enabled: {len(enabled_hosts)} host(s)",
            "severity": "high",
            "deduction": 15,
            "description": (
                f"{len(enabled_hosts)} host(s) are running the WebClient (WebDAV) service. "
                "Any authenticated user can coerce these hosts into authenticating over HTTP "
                "(e.g. via PetitPotam or the Print Spooler bug targeting a WebDAV path). Because "
                "HTTP authentication is unsigned, the captured machine-account auth can be relayed "
                "to AD CS Web Enrollment (ESC8) to obtain a certificate for the victim, or to LDAP "
                "to configure RBCD — leading to host takeover or domain escalation."
            ),
            "recommendation": (
                "Disable and stop the WebClient service on hosts that do not require WebDAV, and "
                "enforce it centrally via GPO (set the WebClient service Startup type to Disabled). "
                "Where WebDAV is genuinely needed, break the relay chain: enforce SMB signing, LDAP "
                "signing and LDAP channel binding, and require HTTPS with Extended Protection for "
                "Authentication (EPA) on the AD CS Web Enrollment endpoint to mitigate ESC8."
            ),
            "affected_count": len(enabled_hosts),
            "details": detail_lines,
            "raw_output": raw_output,
        })
    elif reachable > 0:
        findings.append({
            "title": "WebClient (WebDAV) Service Not Enabled on Reachable Hosts",
            "severity": "info",
            "deduction": 0,
            "description": (
                f"None of the {reachable} reachable host(s) reported the WebClient service as "
                "enabled. HTTP coercion via WebDAV is not available on these systems."
            ),
            "recommendation": "Keep the WebClient service disabled via GPO on all systems.",
            "details": [
                f"Computer list: {targets_file}",
                f"Reachable: {reachable} host(s) | WebClient enabled: 0",
            ],
            "raw_output": raw_output,
        })
    else:
        findings.append({
            "title": "WebClient (WebDAV) Coercion Surface -- No Results Parsed",
            "severity": "info",
            "deduction": 0,
            "description": (
                "nxc completed but no host status lines were parsed. The hosts may be "
                "unreachable, or the module output format may have changed."
            ),
            "recommendation": (
                "Review the debug log for raw nxc output. "
                f"Computer list: {targets_file}"
            ),
            "details": [f"nxc exit code: {rc}"],
            "raw_output": raw_output,
        })

    return findings
