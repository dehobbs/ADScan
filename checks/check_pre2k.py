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
    """Build nxc auth args matching: -u <user> -p <pass> | -H <hash> | -k.

    Returns None when no usable creds are available.
    """
    username = getattr(connector, "username", "") or ""
    password = getattr(connector, "password", None)
    nt_hash  = getattr(connector, "nt_hash", None)
    lm_hash  = getattr(connector, "lm_hash", "") or ""
    use_kerb = getattr(connector, "use_kerberos", False)

    args = ["-u", username]
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


# Patterns for the two outcomes we care about, both on PRE2K module lines:
#
#   PRE2K  ...  Pre-created computer account: TEST-PC$
#       -> account has the pre-Windows 2000 flag (PASSWD_NOTREQD) set,
#          potentially still using the default predictable password.
#
#   PRE2K  ...  [+] TEST-PC$ - SUCCESS!  (or 'Login Successful', 'VALID', etc.)
#       -> NetExec confirmed the account authenticates with its lowercase
#          name as the password.
_ACCOUNT_RE       = re.compile(r"\b([A-Za-z0-9._\-]+\$)")
_PRE_CREATED_RE   = re.compile(r"Pre-created computer account[: ]\s*([A-Za-z0-9._\-]+\$)", re.IGNORECASE)
_CONFIRMED_TOKENS = ("VALID", "vulnerable", "SUCCESS", "Login Successful", "Pwn3d", "Login Success")


def _parse_nxc_output(combined):
    """Return (pre_created_accounts, confirmed_vulnerable_accounts).

    pre_created: accounts NetExec flagged as having the pre-Windows 2000
                 PASSWD_NOTREQD bit set (potentially vulnerable).
    confirmed:   accounts NetExec verified by successfully authenticating
                 with the predictable lowercase password.
    """
    pre_created = []
    confirmed = []
    pc_seen, cf_seen = set(), set()

    for raw in combined.splitlines():
        line = raw.rstrip()
        if "PRE2K" not in line.upper():
            continue

        m = _PRE_CREATED_RE.search(line)
        if m:
            name = m.group(1)
            if name not in pc_seen:
                pc_seen.add(name)
                pre_created.append(name)
            continue

        # Confirmed-vulnerable lines: [+] success marker plus a positive token
        # AND a SAM-style account name. We require BOTH the [+] marker and a
        # positive keyword so the LDAP bind success line ("[+] domain\\user:pwd")
        # cannot leak in (it has no PRE2K prefix, but belt-and-braces).
        if "[+]" in line and any(tok.lower() in line.lower() for tok in _CONFIRMED_TOKENS):
            for am in _ACCOUNT_RE.finditer(line):
                name = am.group(1)
                if name not in cf_seen:
                    cf_seen.add(name)
                    confirmed.append(name)

    return pre_created, confirmed


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

    # --kdcHost forces NetExec's pre2k TGT verification to use the supplied
    # DC instead of resolving the realm name via the system DNS resolver,
    # which on lab/internal networks can return a stray public IP.
    cmd = [nxc_exe, "ldap", dc_host, *auth_args, "--kdcHost", dc_host, "-M", "pre2k"]
    _dns_server = getattr(connector, "dns_server", None)
    if _dns_server:
        cmd += ["--dns-server", _dns_server]
    if getattr(connector, "dns_tcp", False):
        cmd += ["--dns-tcp"]

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
    pre_created, confirmed = _parse_nxc_output(combined)
    log.debug(
        "  Pre-2k pre-created: %d  confirmed-vulnerable: %d",
        len(pre_created), len(confirmed),
    )

    if confirmed:
        details = [f"{n}  (CONFIRMED — predictable password works)" for n in confirmed]
        details += [
            f"{n}  (pre-created; password not verified)"
            for n in pre_created if n not in confirmed
        ]
        findings.append({
            "title": "Pre-Windows 2000 Computer Accounts With Predictable Passwords",
            "severity": "high",
            "deduction": 15,
            "description": (
                "One or more computer accounts were created with the 'Assign this "
                "computer account as a pre-Windows 2000 computer' option enabled, "
                "and at least one was confirmed to authenticate using the lowercase "
                "version of its account name as the password. An attacker can "
                "authenticate as these accounts directly to enumerate domain "
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
            "details": details[:100],
            "discovery_command": (
                f"nxc ldap {dc_host} -u <user> -p <pass> -M pre2k"
            ),
        })
    elif pre_created:
        findings.append({
            "title": "Pre-Created Computer Accounts (Pre-Windows 2000 flag set)",
            "severity": "medium",
            "deduction": 8,
            "description": (
                f"NetExec found {len(pre_created)} computer account(s) with the "
                "PASSWD_NOTREQD flag set, indicating they were pre-created with "
                "the 'Assign this computer account as a pre-Windows 2000 computer' "
                "option. The default password for these accounts is the lowercase "
                "version of the account name. NetExec could not confirm whether "
                "the predictable default is still in place (TGT verification "
                "failed or was skipped) — manual verification recommended."
            ),
            "recommendation": (
                "Verify whether each account still uses its predictable default "
                "password. If it does, reset the password (Set-ADAccountPassword) "
                "or re-join the machine to the domain. Disable or delete accounts "
                "for decommissioned machines. Stop using the pre-Windows 2000 "
                "compatibility checkbox going forward."
            ),
            "details": pre_created[:100],
            "discovery_command": (
                f"nxc ldap {dc_host} -u <user> -p <pass> -M pre2k"
            ),
        })

    return findings
