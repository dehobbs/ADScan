""" checks/check_smb.py -- SMB Signing Enforcement & SMBv1 Detection

Two-phase approach:

Phase 1 -- LDAP computer enumeration (via connector.ldap_search)
    Uses the already-established LDAP connection on the connector object,
    which handles LDAP signing and LDAPS channel binding automatically.
    Queries (objectClass=computer) for dNSHostName / cn attributes and
    writes one hostname per line to: Reports/Artifacts/computers.txt

Phase 2 -- SMB sweep (NetExec)
    nxc smb Reports/Artifacts/computers.txt -u <user> -p <pass> [-H <hash>]
    Parses each output line for:
        (signing:False)  -> hosts that do NOT require SMB message signing
        (SMBv1:True)     -> hosts that still support the deprecated SMBv1 protocol

Findings (from Phase 2 output):
    SMB Signing:  Any signing:False -> HIGH finding, -15 points
                  All signing:True  -> INFO / PASS finding, 0 points
    SMBv1:        Any SMBv1:True    -> HIGH finding, -15 points
                  All SMBv1:False   -> INFO / PASS finding, 0 points

Prerequisites:
    nxc (pip install netexec or pipx install netexec)
    Active LDAP connection on the connector (required for Phase 1 computer list)
"""

import os
import re
import shutil
import subprocess
from datetime import datetime  # nosec B404 - subprocess is required to invoke netexec

CHECK_NAME     = "SMB Signing Enforcement"
CHECK_ORDER    = 22  # runs right after Legacy Protocols (21)
CHECK_CATEGORY = ["Protocol Security"]
CHECK_WEIGHT   = 15   # max deduction at stake for this check module


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _nxc_available():
    return shutil.which("nxc") is not None


def _run_cmd(cmd, timeout=120):
    """Run a subprocess command, return (returncode, stdout, stderr)."""
    result = subprocess.run(  # nosec B603 - cmd is a fully validated list, no shell interpolation
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return result.returncode, result.stdout, result.stderr


def _enumerate_computers_via_ldap(connector):
    """
    Enumerate computer objects via the connector's existing LDAP connection.

    Uses connector.ldap_search() which already has LDAP signing / LDAPS
    channel binding negotiated correctly, avoiding the 00002028
    strongerAuthRequired error that ldapsearch -x raises on hardened DCs.

    Returns a list of unique hostnames (dNSHostName preferred, cn fallback).
    """
    log = connector.log
    if not getattr(connector, 'ldap_conn', None):
        log.warning(" [SMB] No active LDAP connection on connector — cannot enumerate computers.")
        return []

    entries = connector.ldap_search(
        search_filter='(objectClass=computer)',
        attributes=['dNSHostName', 'cn'],
    )

    targets = []
    seen = set()
    for entry in entries:
        # connector.ldap_search returns flat dicts from _entry_to_dict()
        dns = (entry.get('dNSHostName') or '').strip()
        cn  = (entry.get('cn') or '').strip()
        host = dns or cn
        if host and host not in seen:
            seen.add(host)
            targets.append(host)

    log.debug(" [SMB] Enumerated %d computer(s) via LDAP.", len(targets))
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


def _parse_smb_results(nxc_output):
    """
    Parse 'nxc smb' output and return three lists:
        (unsigned_hosts, signed_hosts, smbv1_hosts)

    NetExec SMB output format:
        SMB <ip> 445 <hostname> [*] Windows ... (name:<host>) (domain:<dom>)
            (signing:True/False) (SMBv1:True/False)

    signing: and SMBv1: are parsed independently so that a line missing
    one token does not discard the other.
    """
    unsigned = []
    signed   = []
    smbv1    = []

    host_re  = re.compile(r'^SMB\s+(\S+)\s+\d+\s+(\S+)', re.IGNORECASE)
    sign_re  = re.compile(r'\(signing:(True|False)\)',         re.IGNORECASE)
    smbv1_re = re.compile(r'\(SMBv1:(True|False)\)',           re.IGNORECASE)

    for line in nxc_output.splitlines():
        hm = host_re.search(line)
        if not hm:
            continue
        ip       = hm.group(1)
        hostname = hm.group(2)
        label    = f"{hostname} ({ip})" if hostname != ip else ip

        sm = sign_re.search(line)
        if sm:
            if sm.group(1).lower() == "false":
                unsigned.append(label)
            else:
                signed.append(label)

        vm = smbv1_re.search(line)
        if vm and vm.group(1).lower() == "true":
            smbv1.append(label)

    return unsigned, signed, smbv1


# ---------------------------------------------------------------------------
# Main check entry point
# ---------------------------------------------------------------------------

def run_check(connector, verbose=False):
    findings = []
    log      = connector.log

    # ----------------------------------------------------------------------
    # Pre-flight: check nxc
    # ----------------------------------------------------------------------
    if not _nxc_available():
        findings.append({
            "title": "SMB Signing Enforcement -- NetExec Not Found",
            "severity": "info",
            "deduction": 0,
            "description": (
                "NetExec (nxc) is required for the SMB sweep "
                "but was not found on PATH. "
                "Install with: pip install netexec"
            ),
            "recommendation": (
                "Install NetExec and re-run ADScan to get automated "
                "per-host SMB signing and SMBv1 results."
            ),
            "details": [
                "nxc not found on PATH.",
                "Install with: pip install netexec",
                "Or: pipx install netexec",
            ],
        })
        return findings

    # ----------------------------------------------------------------------
    # Gather connection info
    # ----------------------------------------------------------------------
    dc_host      = getattr(connector, "dc_host", None) or getattr(connector, "server", None)
    artifacts_dir = getattr(connector, "artifacts_dir", "Reports/Artifacts")
    dbg          = getattr(connector, "debug_log", None)

    if not dc_host:
        findings.append({
            "title": "SMB Signing Enforcement -- No DC Host Available",
            "severity": "info",
            "deduction": 0,
            "description": "Could not determine the Domain Controller address from the connector.",
            "recommendation": "Ensure the connector is initialised with a valid dc_host.",
            "details": ["dc_host not available on connector object."],
        })
        return findings

    os.makedirs(artifacts_dir, exist_ok=True)
    run_ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    targets_file = os.path.join(artifacts_dir, f"computers_{run_ts}.txt")

    # ----------------------------------------------------------------------
    # Phase 1: Computer enumeration via connector.ldap_search()
    # Uses the already-established signed/encrypted LDAP connection —
    # avoids ldapsearch -x which fails with 00002028 on hardened DCs.
    # ----------------------------------------------------------------------
    log.debug(" [SMB] Phase 1: enumerating computers via connector LDAP ...")
    targets = _enumerate_computers_via_ldap(connector)

    if not targets:
        findings.append({
            "title": "SMB Signing Enforcement -- No Computers Found via LDAP",
            "severity": "info",
            "deduction": 0,
            "description": (
                "The LDAP computer enumeration returned no results. "
                "Ensure the connector has an active LDAP connection and "
                "the account has read access to computer objects."
            ),
            "recommendation": "Verify LDAP connectivity and account permissions.",
            "details": ["connector.ldap_search(objectClass=computer) returned 0 entries."],
        })
        return findings

    with open(targets_file, "w", encoding="utf-8") as fh:
        fh.write("\n".join(targets) + "\n")
    log.debug(" [SMB] Found %d computer(s). List saved to: %s", len(targets), targets_file)

    # ----------------------------------------------------------------------
    # Phase 2: SMB sweep via NetExec
    # ----------------------------------------------------------------------
    smb_auth = _build_nxc_smb_auth_args(connector)
    smb_cmd  = ["nxc", "smb", targets_file] + smb_auth

    log.debug(" [SMB] Phase 2: sweeping %d host(s) for signing and SMBv1 ...", len(targets))
    # Redact password before logging the command
    _smb_cmd_log = []
    _skip_next = False
    _pw_flags = {"-p", "--password", "-P", "--secret", "--hashes", "--hash"}
    for _tok in smb_cmd:
        if _skip_next:
            _smb_cmd_log.append("REDACTED")
            _skip_next = False
        elif _tok in _pw_flags:
            _smb_cmd_log.append(_tok)
            _skip_next = True
        else:
            _smb_cmd_log.append(_tok)
    log.debug(" [SMB] Command: %s", ' '.join(_smb_cmd_log))

    try:
        rc2, out2, err2 = _run_cmd(smb_cmd, timeout=300)
    except subprocess.TimeoutExpired:
        findings.append({
            "title": "SMB Signing Enforcement -- SMB Sweep Timed Out",
            "severity": "info",
            "deduction": 0,
            "description": "NetExec SMB sweep timed out after 300 seconds.",
            "recommendation": "Check network connectivity or reduce the number of targets.",
            "details": ["nxc smb sweep timed out."],
        })
        return findings
    except Exception as e:
        findings.append({
            "title": "SMB Signing Enforcement -- SMB Sweep Failed",
            "severity": "info",
            "deduction": 0,
            "description": f"nxc smb sweep raised an exception: {e}",
            "recommendation": "Verify nxc is installed and credentials are valid.",
            "details": [str(e)],
        })
        return findings

    if dbg:
        dbg.log_subprocess(
            cmd=smb_cmd, cwd=None, returncode=rc2, stdout=out2, stderr=err2,
        )
    if out2:
        log.debug(" [SMB] nxc smb output (first 30 lines):")
        import re as _re_smb_out
        for line in out2.splitlines()[:30]:
            _safe = _re_smb_out.sub(
                r'([A-Za-z0-9._-]+\\[A-Za-z0-9._-]+):(\S+)',
                r'\1:REDACTED',
                line,
            )
            log.debug("  %s", _safe)

    # Build redacted raw output string for DOCX report evidence
    import re as _re_raw
    _cmd_str = ' '.join(_smb_cmd_log)
    _out_redacted = _re_raw.sub(
        r'([A-Za-z0-9._-]+\\[A-Za-z0-9._-]+):(\S+)',
        r'\1:REDACTED',
        out2 or "",
    )
    _raw_output = _cmd_str + "\n\n" + _out_redacted.rstrip()

    unsigned_hosts, signed_hosts, smbv1_hosts = _parse_smb_results(out2)
    total_scanned = len(unsigned_hosts) + len(signed_hosts)

    # ----------------------------------------------------------------------
    # Finding 1: SMB Signing
    # ----------------------------------------------------------------------
    if unsigned_hosts:
        detail_lines = [
            f"Computer list: {targets_file}",
            f"Scanned: {total_scanned} host(s) | Unsigned: {len(unsigned_hosts)} | Signed: {len(signed_hosts)}",
            "",
            "Hosts with SMB signing NOT enforced (signing:False):",
        ] + [f"  {h}" for h in sorted(unsigned_hosts)]
        findings.append({
            "title": f"SMB Signing Not Enforced: {len(unsigned_hosts)} host(s) vulnerable",
            "severity": "high",
            "deduction": 15,
            "description": (
                f"{len(unsigned_hosts)} of {total_scanned} scanned host(s) do not require "
                "SMB message signing. Without signing, NTLM relay attacks "
                "(e.g. Responder + ntlmrelayx) can be used to authenticate to "
                "these systems as any user whose credentials are captured."
            ),
            "recommendation": (
                "Enable and require SMB signing on all systems via GPO: "
                "Computer Configuration > Windows Settings > Security Settings > "
                "Local Policies > Security Options > "
                "Microsoft network server: Digitally sign communications (always) = Enabled. "
                "Also set the client-side policy: "
                "Microsoft network client: Digitally sign communications (always) = Enabled."
            ),
            "affected_count": len(unsigned_hosts),
            "details": detail_lines,
            "raw_output": _raw_output,
        })
    elif total_scanned > 0:
        findings.append({
            "title": "SMB Signing Enforced on All Scanned Hosts",
            "severity": "info",
            "deduction": 0,
            "description": (
                f"All {total_scanned} scanned host(s) require SMB message signing. "
                "NTLM relay attacks via SMB are not possible on these systems."
            ),
            "recommendation": "Continue enforcing SMB signing via GPO for all new systems.",
            "details": [
                f"Computer list: {targets_file}",
                f"Scanned: {total_scanned} host(s) | All have signing:True",
            ],
            "raw_output": _raw_output,
        })
    else:
        findings.append({
            "title": "SMB Signing Enforcement -- No SMB Results Parsed",
            "severity": "info",
            "deduction": 0,
            "description": (
                "nxc smb completed but no SMB status lines were parsed. "
                "The hosts may be unreachable or the output format may have changed."
            ),
            "recommendation": (
                "Review the debug log for raw nxc smb output. "
                f"Computer list: {targets_file}"
            ),
            "details": [f"nxc smb exit code: {rc2}"] + [
                __import__("re").sub(
                    r'([A-Za-z0-9._-]+\\[A-Za-z0-9._-]+):(\S+)',
                    r'\1:REDACTED', ln
                )
                for ln in out2.splitlines()[:20]
            ],
            "raw_output": _raw_output,
        })

    # ----------------------------------------------------------------------
    # Finding 2: SMBv1
    # ----------------------------------------------------------------------
    if smbv1_hosts:
        smbv1_detail_lines = [
            f"Computer list: {targets_file}",
            f"Scanned: {total_scanned} host(s) | SMBv1 enabled: {len(smbv1_hosts)}",
            "",
            "Hosts with SMBv1 enabled (SMBv1:True):",
        ] + [f"  {h}" for h in sorted(smbv1_hosts)]
        findings.append({
            "title": f"SMBv1 Enabled: {len(smbv1_hosts)} host(s) vulnerable",
            "severity": "high",
            "deduction": 15,
            "description": (
                f"{len(smbv1_hosts)} of {total_scanned} scanned host(s) still support "
                "SMB version 1 (SMBv1). SMBv1 is a deprecated protocol with known "
                "critical vulnerabilities including EternalBlue (MS17-010) which was "
                "exploited by WannaCry and NotPetya ransomware. SMBv1 should be "
                "disabled on all systems."
            ),
            "recommendation": (
                "Disable SMBv1 via PowerShell: "
                "Set-SmbServerConfiguration -EnableSMB1Protocol $false. "
                "Also disable via GPO: "
                "Computer Configuration > Administrative Templates > "
                "MS Security Guide > Configure SMBv1 Server = Disabled. "
                "Verify with: Get-SmbServerConfiguration | Select EnableSMB1Protocol."
            ),
            "affected_count": len(smbv1_hosts),
            "details": smbv1_detail_lines,
            "raw_output": _raw_output,
        })
    elif total_scanned > 0:
        findings.append({
            "title": "SMBv1 Disabled on All Scanned Hosts",
            "severity": "info",
            "deduction": 0,
            "description": (
                f"All {total_scanned} scanned host(s) have SMBv1 disabled. "
                "These systems are not vulnerable to EternalBlue and similar SMBv1 exploits."
            ),
            "recommendation": "Continue enforcing SMBv1 disabled via GPO for all new systems.",
            "details": [
                f"Computer list: {targets_file}",
                f"Scanned: {total_scanned} host(s) | All have SMBv1:False",
            ],
            "raw_output": _raw_output,
        })

    return findings
