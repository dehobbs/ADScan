"""
checks/check_pre2k.py - Pre-Windows 2000 Computer Accounts Check

When a computer account is pre-created in Active Directory with the
"Assign this computer account as a pre-Windows 2000 computer" checkbox
enabled, the password is set to the lowercase version of the sAMAccountName
(minus the trailing '$'). These predictable credentials can be used directly
for authentication and lateral movement without any prior exploitation.

Uses the pre2k tool (https://github.com/garrettfoster13/pre2k-TS) to
enumerate computer objects and test whether their password matches the
pre-Windows 2000 default (account name in lowercase).

Risk Criteria:
  - Any computer account with a predictable pre-2k password -> high (-15 pts)
"""

CHECK_NAME     = "Pre-Windows 2000 Computer Accounts"
CHECK_ORDER    = 24
CHECK_CATEGORY = ["Account Hygiene"]
CHECK_WEIGHT   = 15

import os
import subprocess

from lib.tools import ensure_tool

_PRE2K_INSTALL = (
    "Install pre2k with: "
    "uv tool install git+https://github.com/garrettfoster13/pre2k-TS.git  "
    "or run: python adscan.py --setup-tools"
)


def _build_auth_args(connector):
    username = getattr(connector, "username", None) or ""
    password = getattr(connector, "password", None)
    nt_hash  = getattr(connector, "nt_hash", None)
    lm_hash  = getattr(connector, "lm_hash", "") or ""

    args = ["-u", username]
    if nt_hash:
        args += ["-H", f"{lm_hash}:{nt_hash}" if lm_hash else nt_hash]
    elif password:
        args += ["-p", password]
    else:
        args += ["-p", ""]
    return args


def _parse_pre2k_output(log_path):
    """Parse pre2k output file for successful logins.

    pre2k marks successful authentications with a '[+]' prefix:
        [+] COMPUTER$ - Login Successful!
    Returns a list of account names (sAMAccountName with '$') that
    authenticated with their predictable pre-2k password.
    """
    vulnerable = []
    try:
        with open(log_path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                stripped = line.strip()
                if not stripped.startswith("[+]"):
                    continue
                # Extract account name — first token after '[+]'
                parts = stripped.split()
                if len(parts) >= 2:
                    account = parts[1].rstrip(":")
                    vulnerable.append(account)
    except OSError:
        pass
    return vulnerable


def run_check(connector, verbose=False):
    findings = []
    log      = connector.log

    pre2k_exe = ensure_tool("pre2k")
    if pre2k_exe is None:
        findings.append({
            "title": "Pre-Windows 2000 Computer Accounts — pre2k Not Found",
            "severity": "info",
            "deduction": 0,
            "description": (
                "The pre2k tool is required for this check but was not found on PATH. "
                "pre2k tests whether computer accounts were created with the "
                "'Assign this computer account as a pre-Windows 2000 computer' option, "
                "which sets a predictable password equal to the account name in lowercase."
            ),
            "recommendation": _PRE2K_INSTALL,
            "details": [],
        })
        return findings

    dc_host = getattr(connector, "dc_host", None)
    domain  = getattr(connector, "domain", None)
    if not dc_host or not domain:
        log.warning("  [WARN] No DC host or domain configured — skipping pre2k check.")
        return findings

    artifacts_dir = getattr(connector, "artifacts_dir", None) or "."
    log_path = os.path.join(artifacts_dir, "pre2k.log")

    cmd = [
        pre2k_exe, "auth",
        *_build_auth_args(connector),
        "-dc-ip", dc_host,
        "-d", domain,
        "-outputfile", log_path,
    ]

    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        # nosec B603 — command is a validated list, no shell interpolation
    except subprocess.TimeoutExpired:
        findings.append({
            "title": "Pre-Windows 2000 Computer Accounts — Query Timed Out",
            "severity": "info",
            "deduction": 0,
            "description": "The pre2k command timed out after 180 seconds.",
            "recommendation": "Check network connectivity to the domain controller.",
            "details": [],
        })
        return findings
    except Exception as exc:
        findings.append({
            "title": "Pre-Windows 2000 Computer Accounts — Query Failed",
            "severity": "info",
            "deduction": 0,
            "description": f"pre2k raised an exception: {exc}",
            "recommendation": "Check that pre2k is installed correctly and credentials are valid.",
            "details": [],
        })
        return findings

    vulnerable = _parse_pre2k_output(log_path)
    log.debug("  Pre-2k vulnerable accounts : %d", len(vulnerable))

    if vulnerable:
        findings.append({
            "title": "Pre-Windows 2000 Computer Accounts With Predictable Passwords",
            "severity": "high",
            "deduction": 15,
            "description": (
                "One or more computer accounts were created with the 'Assign this computer "
                "account as a pre-Windows 2000 computer' option enabled. This sets the "
                "machine account password to the lowercase version of the computer name, "
                "which is trivially guessable. An attacker can authenticate as these "
                "accounts directly to enumerate domain resources, perform LDAP queries, "
                "or chain into further attacks without any prior exploitation."
            ),
            "recommendation": (
                "Reset the password on each affected computer account using "
                "'Set-ADAccountPassword' or by re-joining the machine to the domain. "
                "If the account belongs to a decommissioned machine, disable or delete it. "
                "Audit computer account pre-creation procedures to ensure the pre-Windows "
                "2000 checkbox is never checked going forward."
            ),
            "details": vulnerable[:100],
            "raw_output": f"Artifact saved to: {log_path}",
        })

    return findings
