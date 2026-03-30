"""
checks/check_computer_password_age.py - Computer Account Password Age Check

Windows computers automatically rotate their machine account passwords every
30 days via the Netlogon secure channel. This check flags enabled, non-DC
computer accounts whose pwdLastSet is older than 30 days — indicating the
machine is offline, has a broken secure channel, or has disabled automatic
password rotation.

Risk Criteria:
  - Computer pwdLastSet > 30 days (or never set) -> medium (-8 pts)
"""

CHECK_NAME     = "Computer Account Password Age"
CHECK_ORDER    = 23
CHECK_CATEGORY = ["Account Hygiene"]
CHECK_WEIGHT   = 15

from datetime import datetime, timezone, timedelta

_FILETIME_EPOCH_OFFSET   = 11644473600
_UAC_ACCOUNTDISABLE      = 0x2
_UAC_SERVER_TRUST_ACCOUNT = 0x2000   # Domain Controller
_PWD_AGE_DAYS            = 30

_ATTRS = [
    "sAMAccountName",
    "distinguishedName",
    "dNSHostName",
    "pwdLastSet",
    "userAccountControl",
    "operatingSystem",
]


def _filetime_to_dt(val):
    try:
        v = int(val)
        if v <= 0:
            return None
        return datetime.fromtimestamp((v / 10_000_000) - _FILETIME_EPOCH_OFFSET, tz=timezone.utc)
    except Exception:
        return None


def _uac(entry, flag):
    try:
        return bool(int(entry.get("userAccountControl") or 0) & flag)
    except Exception:
        return False


def _sam(entry):
    try:
        return str(entry.get("sAMAccountName") or "?")
    except Exception:
        return "?"


def run_check(connector, verbose=False):
    findings = []
    log = connector.log

    now        = datetime.now(tz=timezone.utc)
    cutoff     = now - timedelta(days=_PWD_AGE_DAYS)

    entries = connector.ldap_search(
        search_filter=(
            "(&(objectClass=computer)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))"
        ),
        attributes=_ATTRS,
    ) or []

    stale = []

    for entry in entries:
        sam = _sam(entry)
        ps  = _filetime_to_dt(entry.get("pwdLastSet"))

        if ps is None:
            stale.append(f"{sam} (password never set)")
        elif ps < cutoff:
            days = (now - ps).days
            stale.append(f"{sam} (pwd set {days}d ago)")

    log.debug("  Enabled non-DC computers : %d", len(entries))
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
