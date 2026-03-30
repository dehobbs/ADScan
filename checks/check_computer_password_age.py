"""
checks/check_computer_password_age.py - Computer Account Password Age Check

Windows computers automatically rotate their machine account passwords every
30 days via the Netlogon secure channel. This check flags computer accounts
whose pwdLastSet is older than 30 days — indicating the machine is offline,
has a broken secure channel, or has disabled automatic password rotation.

Uses NetExec (nxc) via LDAP --query to enumerate computer pwdLastSet values.
pwdLastSet is returned as a raw Windows FILETIME integer (100-nanosecond
intervals since 1601-01-01 UTC) and converted to a UTC datetime for comparison.

Risk Criteria:
  - Computer pwdLastSet > 30 days (or never set) -> medium (-8 pts)
"""

CHECK_NAME     = "Computer Account Password Age"
CHECK_ORDER    = 23
CHECK_CATEGORY = ["Account Hygiene"]
CHECK_WEIGHT   = 15

import re
import subprocess
from datetime import datetime, timezone, timedelta

from lib.tools import ensure_tool

_PWD_AGE_DAYS   = 30
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _filetime_to_dt(raw):
    """Convert a Windows FILETIME integer to a UTC datetime.

    FILETIME is a count of 100-nanosecond intervals since 1601-01-01 UTC.
    Dividing by 10 converts to microseconds for use with timedelta.
    """
    try:
        val = int(raw)
        if val <= 0:
            return None
        return _FILETIME_EPOCH + timedelta(microseconds=val // 10)
    except (TypeError, ValueError):
        return None


def _build_auth_args(connector):
    username = getattr(connector, "username", None) or ""
    password = getattr(connector, "password", None)
    nt_hash  = getattr(connector, "nt_hash", None)
    lm_hash  = getattr(connector, "lm_hash", "") or ""
    domain   = getattr(connector, "domain", "") or ""

    args = ["-u", username]
    if nt_hash:
        args += ["-H", f"{lm_hash}:{nt_hash}" if lm_hash else nt_hash]
    elif password:
        args += ["-p", password]
    else:
        args += ["-p", ""]
    if domain:
        args += ["-d", domain]
    return args


def _parse_nxc_output(output):
    """Parse nxc ldap --query output into (sAMAccountName, pwdLastSet_raw) pairs.

    nxc emits one attribute per line, prefixed by LDAP metadata columns:
        LDAP   10.0.0.1   389   DC01   sAMAccountName: COMPUTER1$
        LDAP   10.0.0.1   389   DC01   pwdLastSet: 133812345678900000
    Records are separated by a dn: line or a blank attribute field.
    """
    records = []
    current = {}

    for line in output.splitlines():
        stripped = line.strip()
        if not re.match(r"^LDAP\b", stripped, re.IGNORECASE):
            continue

        # Split off the 4 leading metadata columns (protocol, ip, port, hostname)
        parts = stripped.split(None, 4)
        if len(parts) < 5:
            # Blank attribute field — record boundary
            if "sam" in current and "pwd" in current:
                records.append((current["sam"], current["pwd"]))
            current = {}
            continue

        attr_val = parts[4].strip()
        lower    = attr_val.lower()

        if lower.startswith("dn:"):
            # New LDAP entry — save previous record if complete
            if "sam" in current and "pwd" in current:
                records.append((current["sam"], current["pwd"]))
            current = {}
        elif lower.startswith("samaccountname:"):
            current["sam"] = attr_val.split(":", 1)[1].strip()
        elif lower.startswith("pwdlastset:"):
            current["pwd"] = attr_val.split(":", 1)[1].strip()

    # Flush any trailing record
    if "sam" in current and "pwd" in current:
        records.append((current["sam"], current["pwd"]))

    return records


def run_check(connector, verbose=False):
    findings = []
    log      = connector.log

    nxc_exe = ensure_tool("nxc")
    if nxc_exe is None:
        findings.append({
            "title": "Computer Account Password Age — NetExec Not Found",
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

    dc_host = getattr(connector, "dc_host", None)
    if not dc_host:
        log.warning("  [WARN] No DC host configured — skipping computer password age check.")
        return findings

    cmd = [
        nxc_exe, "ldap", dc_host,
        *_build_auth_args(connector),
        "--query", "(objectClass=computer)",
        "sAMAccountName pwdLastSet",
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        output = result.stdout
    except subprocess.TimeoutExpired:
        findings.append({
            "title": "Computer Account Password Age — Query Timed Out",
            "severity": "info",
            "deduction": 0,
            "description": "The nxc ldap --query command timed out after 120 seconds.",
            "recommendation": "Check network connectivity to the domain controller.",
            "details": [],
        })
        return findings
    except Exception as exc:
        findings.append({
            "title": "Computer Account Password Age — Query Failed",
            "severity": "info",
            "deduction": 0,
            "description": f"nxc ldap --query raised an exception: {exc}",
            "recommendation": "Check that nxc is installed and credentials are valid.",
            "details": [],
        })
        return findings

    now    = datetime.now(tz=timezone.utc)
    cutoff = now - timedelta(days=_PWD_AGE_DAYS)
    stale  = []

    records = _parse_nxc_output(output)
    log.debug("  Computer records returned : %d", len(records))

    for sam, pwd_raw in records:
        dt = _filetime_to_dt(pwd_raw)
        if dt is None:
            stale.append(f"{sam} (password never set)")
        elif dt < cutoff:
            days = (now - dt).days
            stale.append(f"{sam} (pwd set {days}d ago)")

    log.debug("  Stale machine passwords  : %d", len(stale))

    if stale:
        findings.append({
            "title": f"Computer Accounts With Stale Machine Passwords (> {_PWD_AGE_DAYS} Days)",
            "severity": "medium",
            "deduction": 8,
            "description": (
                "Windows computers automatically rotate their machine account passwords "
                "every 30 days via the Netlogon secure channel. A pwdLastSet older than "
                "30 days on an enabled, non-DC computer account indicates the machine is "
                "either offline, has a broken secure channel, or has disabled automatic "
                "password rotation (DisablePasswordChange registry key). Such accounts "
                "represent a lateral-movement risk — an attacker with the old NTLM hash "
                "can still authenticate until the password rotates."
            ),
            "recommendation": (
                "Re-join or repair affected machines. Force a password refresh with "
                "'netdom resetpwd' or 'Reset-ComputerMachinePassword'. Check for the "
                "DisablePasswordChange registry key under "
                "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters. "
                "Disable or delete accounts for decommissioned machines."
            ),
            "details": stale[:100],
        })

    return findings
