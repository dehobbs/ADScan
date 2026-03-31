"""
checks/check_nopac.py - NoPac (CVE-2021-42278/42287) Vulnerability Check

NoPac exploits two vulnerabilities in combination:
  - CVE-2021-42278: machine account sAMAccountName spoofing
  - CVE-2021-42287: Kerberos PAC validation bypass

Uses NetExec's built-in nopac module to test each Domain Controller.
NetExec requests a TGT with and without a PAC and compares ticket sizes —
a smaller PAC-less ticket confirms the DC is unpatched and exploitable.

All domain controllers are enumerated via LDAP and tested individually.

Risk Criteria:
  - Any DC issues a TGT without a PAC -> critical (-20 pts)
"""

CHECK_NAME     = "NoPac (CVE-2021-42278/42287) Vulnerability"
CHECK_ORDER    = 25
CHECK_CATEGORY = ["Kerberos"]
CHECK_WEIGHT   = 20

import re
import subprocess

from lib.tools import ensure_tool

_DC_FILTER = "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"


def _get_dc_hosts(connector):
    """Return a list of DC hostnames/IPs to scan.

    Queries LDAP for all computer accounts with the SERVER_TRUST_ACCOUNT
    bit set (0x2000). Falls back to connector.dc_host if the query returns
    nothing.
    """
    try:
        entries = connector.ldap_search(
            search_filter=_DC_FILTER,
            attributes=["dNSHostName", "cn"],
        )
        hosts = []
        for entry in entries:
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


def _parse_tgt_sizes(output):
    """Extract TGT with PAC and TGT without PAC sizes from nxc nopac output.

    Looks for lines of the form:
        TGT with PAC size 1482
        TGT without PAC size 1282

    Returns (with_pac_size, without_pac_size) as ints, or (None, None) if
    either value is not found in the output.
    """
    with_pac    = re.search(r"TGT with PAC size\s+(\d+)",    output, re.IGNORECASE)
    without_pac = re.search(r"TGT without PAC size\s+(\d+)", output, re.IGNORECASE)
    if with_pac and without_pac:
        return int(with_pac.group(1)), int(without_pac.group(1))
    return None, None


def _scan_dc(nxc_exe, auth_args, dc_ip, log):
    """Run nxc smb -M nopac against a single DC.

    Compares the TGT with PAC size to the TGT without PAC size:
      - Equal sizes   → DC is patched (not vulnerable)
      - Unequal sizes → DC is vulnerable (PAC-less TGT is smaller)

    Returns True if vulnerable, False if clean, None on error/inconclusive.
    """
    cmd = [nxc_exe, "smb", dc_ip] + auth_args + ["-M", "nopac"]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=60
        )  # nosec B603 — validated list, no shell interpolation
        output = result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        log.warning("  [WARN] nxc nopac module timed out for DC: %s", dc_ip)
        return None
    except Exception as exc:
        log.warning("  [WARN] nxc nopac module error for DC %s: %s", dc_ip, exc)
        return None

    with_pac, without_pac = _parse_tgt_sizes(output)
    if with_pac is None:
        log.debug("  nxc nopac output for %s did not contain TGT size values.", dc_ip)
        return None

    log.debug(
        "  %s — TGT with PAC: %d bytes, TGT without PAC: %d bytes",
        dc_ip, with_pac, without_pac,
    )
    return with_pac != without_pac


def run_check(connector, verbose=False):
    findings = []
    log      = connector.log

    nxc_exe = ensure_tool("nxc")
    if nxc_exe is None:
        findings.append({
            "title": "NoPac Vulnerability — NetExec Not Found",
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
        log.warning("  [WARN] No domain controllers found — skipping NoPac check.")
        return findings

    auth_args  = _build_auth_args(connector)
    vulnerable = []
    errors     = []

    for dc in dc_hosts:
        log.debug("  Scanning DC for NoPac: %s", dc)
        result = _scan_dc(nxc_exe, auth_args, dc, log)
        if result is True:
            vulnerable.append(dc)
        elif result is False:
            pass  # clean — no finding needed
        else:
            errors.append(dc)

    log.debug("  NoPac vulnerable DCs : %d / %d", len(vulnerable), len(dc_hosts))

    if vulnerable:
        findings.append({
            "title": "Domain Controllers Vulnerable to NoPac (CVE-2021-42278/CVE-2021-42287)",
            "severity": "critical",
            "deduction": 20,
            "description": (
                "One or more Domain Controllers issued a TGT without a PAC, indicating "
                "they are vulnerable to the NoPac attack (CVE-2021-42278 / CVE-2021-42287). "
                "NoPac allows any authenticated domain user to impersonate a Domain "
                "Controller via sAMAccountName spoofing and Kerberos S4U2self abuse, "
                "resulting in a full domain compromise (Domain Admin equivalent) without "
                "any prior privilege. Exploitation requires only valid domain credentials."
            ),
            "recommendation": (
                "Apply the November 2021 cumulative update (KB5008380 for 2019/2022, "
                "KB5008602 for 2016) to all Domain Controllers immediately. "
                "Verify remediation by re-running this check after patching. "
                "As a defence-in-depth measure, set ms-DS-MachineAccountQuota to 0 "
                "to prevent unprivileged users from adding machine accounts to the domain."
            ),
            "details": vulnerable,
        })

    if errors and not vulnerable:
        findings.append({
            "title": "NoPac Scan — Inconclusive Results for Some Domain Controllers",
            "severity": "info",
            "deduction": 0,
            "description": (
                "The nxc nopac module did not return a clear result for one or more "
                "Domain Controllers. This may indicate a network timeout, authentication "
                "failure, or that the module output format was not recognised."
            ),
            "recommendation": (
                "Re-run the check manually against the affected DCs: "
                "nxc smb <DC_IP> -d <domain> -u <user> -p <pass> -M nopac"
            ),
            "details": errors,
        })

    return findings
