"""
checks/check_print_spooler.py - Print Spooler Service on Domain Controllers (PrinterBug)

The Windows Print Spooler service exposes the MS-RPRN RPC interface. Any
authenticated domain user can call RpcRemoteFindFirstPrinterChangeNotificationEx
to coerce the host into authenticating to an attacker-controlled machine — the
"PrinterBug" / SpoolSample primitive.

When the Spooler is running on a Domain Controller, that coerced DC machine
authentication can be:
  - relayed to AD CS HTTP Web Enrollment (ESC8) to obtain a DC certificate, or
  - relayed to LDAP to configure RBCD, or
  - captured by a host configured for unconstrained delegation,
any of which leads to full domain compromise. The Spooler is enabled by default
on Windows Server, so DCs are frequently affected.

Uses NetExec's built-in spooler module to test each Domain Controller. All DCs
are enumerated via LDAP and tested individually.

Risk Criteria:
  - Print Spooler enabled on any DC -> high (-15 pts)
"""

CHECK_NAME     = "Print Spooler Service on Domain Controllers"
CHECK_ORDER    = 26
CHECK_CATEGORY = ["Protocol Security"]
CHECK_WEIGHT   = 15

import re
import subprocess  # nosec B404 — required to invoke nxc; calls use validated arg lists

from lib.tools import ensure_tool

_DC_FILTER = "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"


def _get_dc_hosts(connector):
    """Return a list of DC hostnames/IPs to scan.

    Queries LDAP for computer accounts with the SERVER_TRUST_ACCOUNT bit set
    (0x2000). Falls back to connector.dc_host if the query returns nothing.
    """
    try:
        entries = connector.ldap_search(
            search_filter=_DC_FILTER,
            attributes=["dNSHostName", "cn"],
        )
        hosts = []
        for entry in entries or []:
            host = entry.get("dNSHostName") or entry.get("cn")
            if host:
                hosts.append(host)
        if hosts:
            return hosts
    except Exception:
        pass

    fallback = getattr(connector, "dc_host", None)
    return [fallback] if fallback else []


def _build_auth_args(connector):
    domain   = getattr(connector, "domain", "") or ""
    username = getattr(connector, "username", "") or ""
    password = getattr(connector, "password", None)
    nt_hash  = getattr(connector, "nt_hash", None)
    lm_hash  = getattr(connector, "lm_hash", "") or ""

    args = ["-d", domain, "-u", username]
    if nt_hash:
        args += ["-H", f"{lm_hash}:{nt_hash}" if lm_hash else nt_hash]
    elif password:
        args += ["-p", password]
    else:
        args += ["-p", ""]
    return args


def _build_dns_args(connector):
    """Forward ADScan's DNS overrides to nxc, mirroring the other nxc checks."""
    args = []
    dns_server = getattr(connector, "dns_server", None)
    if dns_server:
        args += ["--dns-server", dns_server]
    if getattr(connector, "dns_tcp", False):
        args += ["--dns-tcp"]
    return args


def _parse_spooler_status(output):
    """Interpret nxc spooler module output for a single host.

    The NetExec spooler module highlights 'Spooler service enabled' when the
    MS-RPRN interface is reachable, and 'Spooler service disabled' otherwise.

    Returns 'enabled', 'disabled', or None when the result is inconclusive.
    """
    if re.search(r"spooler service enabled", output, re.IGNORECASE):
        return "enabled"
    if re.search(r"spooler service disabled", output, re.IGNORECASE):
        return "disabled"
    return None


def _scan_dc(nxc_exe, auth_args, dns_args, dc_ip, log):
    """Run `nxc smb <dc> -M spooler` against a single DC.

    Returns 'enabled', 'disabled', or None (error / inconclusive).
    """
    cmd = [nxc_exe, "smb", dc_ip] + auth_args + dns_args + ["-M", "spooler"]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=60
        )  # nosec B603 — validated list, no shell interpolation
        output = result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        log.warning("  [WARN] nxc spooler module timed out for DC: %s", dc_ip)
        return None
    except Exception as exc:
        log.warning("  [WARN] nxc spooler module error for DC %s: %s", dc_ip, exc)
        return None

    status = _parse_spooler_status(output)
    if status is None:
        log.debug("  nxc spooler output for %s was inconclusive.", dc_ip)
    else:
        log.debug("  %s — Print Spooler: %s", dc_ip, status)
    return status


def run_check(connector, verbose=False):
    findings = []
    log      = connector.log

    nxc_exe = ensure_tool("nxc")
    if nxc_exe is None:
        findings.append({
            "title": "Print Spooler Check — NetExec Not Found",
            "severity": "info",
            "deduction": 0,
            "description": (
                "nxc (NetExec) is required for this check but was not found. "
                "Install it with: uv tool install netexec"
            ),
            "recommendation": "Run: python adscan.py --setup-tools",
            "details": [],
        })
        return findings

    dc_hosts = _get_dc_hosts(connector)
    if not dc_hosts:
        log.warning("  [WARN] No domain controllers found — skipping Print Spooler check.")
        return findings

    auth_args = _build_auth_args(connector)
    dns_args  = _build_dns_args(connector)

    enabled = []
    errors  = []

    for dc in dc_hosts:
        log.debug("  Scanning DC for Print Spooler: %s", dc)
        status = _scan_dc(nxc_exe, auth_args, dns_args, dc, log)
        if status == "enabled":
            enabled.append(dc)
        elif status == "disabled":
            pass  # clean — no finding needed
        else:
            errors.append(dc)

    log.debug("  Print Spooler enabled on : %d / %d DC(s)", len(enabled), len(dc_hosts))

    if enabled:
        findings.append({
            "title": f"Print Spooler Service Enabled on Domain Controller(s): {len(enabled)} DC(s)",
            "severity": "high",
            "deduction": 15,
            "description": (
                f"The Print Spooler service is running on {len(enabled)} Domain Controller(s), "
                "exposing the MS-RPRN RPC interface. Any authenticated domain user can use the "
                "PrinterBug (SpoolSample) technique to coerce the affected DC into authenticating "
                "to an attacker-controlled host. That coerced DC machine authentication can then "
                "be relayed to AD CS Web Enrollment (ESC8) to obtain a DC certificate, relayed to "
                "LDAP to configure resource-based constrained delegation, or captured by a host "
                "with unconstrained delegation — each path leading to full domain compromise. "
                "The Print Spooler is rarely required on a Domain Controller."
            ),
            "recommendation": (
                "Disable the Print Spooler service on all Domain Controllers unless it is "
                "explicitly required:\n"
                "Stop-Service Spooler -Force; Set-Service Spooler -StartupType Disabled\n"
                "Enforce centrally via Group Policy: Computer Configuration > Policies > "
                "Administrative Templates > Printers > 'Allow Print Spooler to accept client "
                "connections' = Disabled. Pair with SMB/LDAP signing and channel binding "
                "enforcement to break any coercion-to-relay chain."
            ),
            "details": enabled,
        })

    if errors and not enabled:
        findings.append({
            "title": "Print Spooler Scan — Inconclusive Results for Some Domain Controllers",
            "severity": "info",
            "deduction": 0,
            "description": (
                "The nxc spooler module did not return a clear result for one or more "
                "Domain Controllers. This may indicate a network timeout, authentication "
                "failure, or that the module output format was not recognised."
            ),
            "recommendation": (
                "Re-run the check manually against the affected DCs: "
                "nxc smb <DC_IP> -d <domain> -u <user> -p <pass> -M spooler"
            ),
            "details": errors,
        })

    return findings
