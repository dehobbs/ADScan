"""
checks/check_pre2k.py - Pre-Windows 2000 Computer Accounts Check

When a computer account is pre-created in Active Directory with the
"Assign this computer account as a pre-Windows 2000 computer" checkbox
enabled, the password is set to the lowercase version of the sAMAccountName
(minus the trailing '$'). These predictable credentials can be used directly
for authentication and lateral movement without any prior exploitation.

Uses NetExec's pre2k LDAP module to enumerate computer objects and test
whether their password matches the pre-Windows 2000 default (account name
in lowercase).

    nxc ldap <dc-ip> -u <user> -p <pass> -M pre2k

Risk Criteria:
  - Any computer account with a predictable pre-2k password -> high (-15 pts)
"""

CHECK_NAME     = "Pre-Windows 2000 Computer Accounts"
CHECK_ORDER    = 24
CHECK_CATEGORY = ["Account Hygiene"]
CHECK_WEIGHT   = 15

import re
import subprocess

from lib.tools import ensure_tool


def _build_auth_args(connector):
    """Build nxc auth args. Returns None when no usable creds are available."""
    domain   = getattr(connector, "domain", "") or ""
    username = getattr(connector, "username", "") or ""
    password = getattr(connector, "password", None)
    nt_hash  = getattr(connector, "nt_hash", None)
    lm_hash  = getattr(connector, "lm_hash", "") or ""
    use_kerb = getattr(connector, "use_kerberos", False)

    args = ["-d", domain, "-u", username]
    if use_kerb:
        # nxc reads KRB5CCNAME via -k for Kerberos authentication
        args += ["-k"]
    elif nt_hash:
        args += ["-H", f"{lm_hash}:{nt_hash}" if lm_hash else nt_hash]
    elif password is not None:
        args += ["-p", password]
    else:
        return None
    return args


_PRE2K_LINE_RE = re.compile(
    r"""\bVALID\b      |   # explicit VALID marker
        \bvulnerable\b |   # 'is vulnerable' / 'pre2k vulnerable'
        \bSUCCESS\b    |   # 'Login Success'
        Login\s+Successful""",
    re.IGNORECASE | re.VERBOSE,
)
_ACCOUNT_RE = re.compile(r"([A-Za-z0-9._\-]+\$)")


def _parse_nxc_output(combined):
    """Extract computer account names that nxc reported as vulnerable.

    nxc's pre2k module typically emits a line per matching account, e.g.:

        PRE2K  10.0.0.1  389  DC01    [+] DOMAIN\\COMPUTER1$ is vulnerable!
        LDAP   10.0.0.1  389  DC01    [+] COMPUTER1$:computer1 - VALID

    Different NetExec versions phrase it differently, so we look for any
    line containing a 'success' marker AND a SAM-style computer name.
    """
    vulnerable = []
    for line in combined.splitlines():
        if not _PRE2K_LINE_RE.search(line):
            continue
        for match in _ACCOUNT_RE.finditer(line):
            name = match.group(1)
            if name not in vulnerable:
                vulnerable.append(name)
    return vulnerable


def run_check(connector, verbose=False):
    findings = []
    log      = connector.log

    nxc_exe = ensure_tool("nxc")
    if nxc_exe is None:
        findings.append({
            "title": "Pre-Windows 2000 Computer Accounts — NetExec Not Found",
            "severity": "info",
            "deduction": 0,
            "description": (
                "NetExec (nxc) is required for this check but was not found on PATH. "
                "nxc's pre2k module enumerates computer accounts and tests whether "
                "they have predictable pre-Windows 2000 passwords."
            ),
            "recommendation": (
                "Install NetExec: uv tool install netexec  "
                "(or run: python adscan.py --setup-tools)"
            ),
            "details": [],
        })
        return findings

    dc_host = getattr(connector, "dc_host", None)
    domain  = getattr(connector, "domain", None)
    if not dc_host or not domain:
        log.warning("  [WARN] No DC host or domain configured — skipping pre2k check.")
        return findings

    auth_args = _build_auth_args(connector)
    if auth_args is None:
        findings.append({
            "title": "Pre-Windows 2000 Computer Accounts — Skipped (No Credentials)",
            "severity": "info",
            "deduction": 0,
            "description": (
                "nxc requires a password, NTLM hash, or Kerberos ccache to bind "
                "to the DC. None were provided to ADScan, so this check was skipped."
            ),
            "recommendation": (
                "Re-scan with -p <password>, --hash <NT>, or --kerberos (with "
                "KRB5CCNAME or --ccache pointing at a valid ccache)."
            ),
            "details": [],
        })
        return findings

    cmd = [nxc_exe, "ldap", dc_host, *auth_args, "-M", "pre2k"]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=180,
        )  # nosec B603 — validated list, no shell interpolation
    except subprocess.TimeoutExpired:
        findings.append({
            "title": "Pre-Windows 2000 Computer Accounts — Query Timed Out",
            "severity": "info",
            "deduction": 0,
            "description": "nxc ldap -M pre2k did not complete within 180 seconds.",
            "recommendation": "Check network connectivity to the domain controller and retry.",
            "details": [f"DC: {dc_host}"],
        })
        return findings
    except Exception as exc:
        findings.append({
            "title": "Pre-Windows 2000 Computer Accounts — Query Failed",
            "severity": "info",
            "deduction": 0,
            "description": f"nxc raised an exception: {exc}",
            "recommendation": "Check that nxc is installed and credentials are valid.",
            "details": [],
        })
        return findings

    # Log the subprocess invocation (with credential redaction) to the debug log
    dbg = getattr(connector, "debug_log", None)
    if dbg:
        dbg.log_subprocess(
            cmd=cmd,
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
        )

    combined = (result.stdout or "") + (result.stderr or "")
    vulnerable = _parse_nxc_output(combined)
    log.debug("  Pre-2k vulnerable accounts : %d", len(vulnerable))

    if vulnerable:
        findings.append({
            "title": "Pre-Windows 2000 Computer Accounts With Predictable Passwords",
            "severity": "high",
            "deduction": 15,
            "description": (
                "One or more computer accounts were created with the 'Assign this "
                "computer account as a pre-Windows 2000 computer' option enabled. "
                "This sets the machine account password to the lowercase version "
                "of the computer name, which is trivially guessable. An attacker "
                "can authenticate as these accounts directly to enumerate domain "
                "resources, perform LDAP queries, or chain into further attacks "
                "without any prior exploitation."
            ),
            "recommendation": (
                "Reset the password on each affected computer account using "
                "Set-ADAccountPassword or by re-joining the machine to the domain. "
                "If the account belongs to a decommissioned machine, disable or "
                "delete it. Audit computer account pre-creation procedures to "
                "ensure the pre-Windows 2000 checkbox is never used going forward."
            ),
            "details": vulnerable[:100],
            "discovery_command": (
                f"nxc ldap {dc_host} -d {domain} -u <user> -p <pass> -M pre2k"
            ),
        })

    return findings
