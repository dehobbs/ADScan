"""
checks/check_account_hygiene.py - Account Hygiene Check

Checks:
  1. Stale user accounts (enabled, lastLogonTimestamp > 90 days or never)
  2. Stale computer accounts (enabled, lastLogonTimestamp > 90 days or never)
  3. Never-logged-in accounts (enabled accounts that have NEVER authenticated)
  4. PASSWD_NOTREQD flag (accounts where a password is not required)
  5. Reversible encryption per-account (per-account ENCRYPTED_TEXT_PASSWORD_ALLOWED)
  6. Old passwords (password last set > 365 days, not in non-expiry policy)
  7. Duplicate SPNs (two or more accounts share the same SPN)

Risk Deductions:
  Critical (-20): Per-account reversible encryption enabled
  High    (-15): PASSWD_NOTREQD on enabled accounts
  High    (-15): Duplicate SPNs (causes Kerberos auth failures and security issues)
  Medium   (-8): Stale enabled user accounts (> 90 days)
  Medium   (-8): Stale enabled computer accounts (> 90 days)
  Medium   (-8): Never-logged-in enabled user accounts
  Medium   (-8): Old passwords on enabled user accounts (> 365 days)
  Low      (-5): Never-logged-in computer accounts
"""

CHECK_NAME = "Account Hygiene"
CHECK_ORDER = 8
CHECK_CATEGORY = ["Account Hygiene"]

from datetime import datetime, timezone, timedelta
from collections import defaultdict

_UAC_ACCOUNTDISABLE              = 0x2
_UAC_PASSWD_NOTREQD              = 0x20
_UAC_ENCRYPTED_TEXT_PWD_ALLOWED  = 0x80    # Reversible encryption per-account
_UAC_DONT_EXPIRE_PASSWD          = 0x10000
_UAC_SERVER_TRUST_ACCOUNT        = 0x2000  # DC computer account

_FILETIME_EPOCH_OFFSET = 11644473600
_STALE_DAYS   = 90
_OLD_PWD_DAYS = 365

_USER_ATTRS = [
    "sAMAccountName",
    "distinguishedName",
    "userAccountControl",
    "lastLogonTimestamp",
    "pwdLastSet",
    "servicePrincipalName",
    "objectClass",
    "whenCreated",
]

_COMP_ATTRS = [
    "sAMAccountName",
    "distinguishedName",
    "userAccountControl",
    "lastLogonTimestamp",
    "pwdLastSet",
    "operatingSystem",
    "servicePrincipalName",
    "whenCreated",
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
        return bool(int(entry["userAccountControl"].value) & flag)
    except Exception:
        return False


def _sam(entry):
    try:
        return str(entry["sAMAccountName"].value)
    except Exception:
        return "?"


def _spns(entry):
    try:
        v = entry["servicePrincipalName"].values
        return list(v) if v else []
    except Exception:
        return []


def run_check(connector, verbose=False):
    findings = []

    now            = datetime.now(tz=timezone.utc)
    stale_cutoff   = now - timedelta(days=_STALE_DAYS)
    old_pwd_cutoff = now - timedelta(days=_OLD_PWD_DAYS)

    # -----------------------------------------------------------------------
    # USER accounts
    # -----------------------------------------------------------------------
    user_entries = connector.ldap_search(
        search_filter="(&(objectClass=user)(!(objectClass=computer)))",
        attributes=_USER_ATTRS,
    ) or []

    stale_users      = []
    never_logon_users = []
    passwd_notreqd   = []
    reversible_enc   = []
    old_pwd_users    = []
    spn_map          = defaultdict(list)  # SPN -> [SAM accounts]

    for entry in user_entries:
        if _uac(entry, _UAC_ACCOUNTDISABLE):
            continue
        sam = _sam(entry)

        # Reversible encryption per-account
        if _uac(entry, _UAC_ENCRYPTED_TEXT_PWD_ALLOWED):
            reversible_enc.append(sam)

        # PASSWD_NOTREQD
        if _uac(entry, _UAC_PASSWD_NOTREQD):
            passwd_notreqd.append(sam)

        # Stale / never logged in
        ll = _filetime_to_dt(entry["lastLogonTimestamp"].value if "lastLogonTimestamp" in entry else None)
        if ll is None:
            never_logon_users.append(sam)
        elif ll < stale_cutoff:
            days = (now - ll).days
            stale_users.append(f"{sam} ({days}d ago)")

        # Old password
        no_expire = _uac(entry, _UAC_DONT_EXPIRE_PASSWD)
        if not no_expire:
            ps = _filetime_to_dt(entry["pwdLastSet"].value if "pwdLastSet" in entry else None)
            if ps is not None and ps < old_pwd_cutoff:
                days = (now - ps).days
                old_pwd_users.append(f"{sam} (pwd set {days}d ago)")

        # Collect SPNs
        for spn in _spns(entry):
            spn_lower = spn.lower()
            spn_map[spn_lower].append(sam)

    # -----------------------------------------------------------------------
    # COMPUTER accounts
    # -----------------------------------------------------------------------
    comp_entries = connector.ldap_search(
        search_filter="(objectClass=computer)",
        attributes=_COMP_ATTRS,
    ) or []

    stale_comps       = []
    never_logon_comps = []

    for entry in comp_entries:
        if _uac(entry, _UAC_ACCOUNTDISABLE):
            continue
        if _uac(entry, _UAC_SERVER_TRUST_ACCOUNT):
            continue  # Skip DCs
        sam = _sam(entry)

        ll = _filetime_to_dt(entry["lastLogonTimestamp"].value if "lastLogonTimestamp" in entry else None)
        if ll is None:
            never_logon_comps.append(sam)
        elif ll < stale_cutoff:
            days = (now - ll).days
            stale_comps.append(f"{sam} ({days}d ago)")

        # Collect computer SPNs too
        for spn in _spns(entry):
            spn_lower = spn.lower()
            spn_map[spn_lower].append(sam)

    # -----------------------------------------------------------------------
    # Duplicate SPNs
    # -----------------------------------------------------------------------
    dup_spns = {
        spn: accounts
        for spn, accounts in spn_map.items()
        if len(accounts) > 1
    }

    if verbose:
        print(f"  Enabled users       : {len(user_entries)}")
        print(f"  Stale users         : {len(stale_users)}")
        print(f"  Never-logon users   : {len(never_logon_users)}")
        print(f"  PASSWD_NOTREQD      : {len(passwd_notreqd)}")
        print(f"  Reversible enc      : {len(reversible_enc)}")
        print(f"  Old password users  : {len(old_pwd_users)}")
        print(f"  Stale computers     : {len(stale_comps)}")
        print(f"  Duplicate SPNs      : {len(dup_spns)}")

    # -----------------------------------------------------------------------
    # Build findings
    # -----------------------------------------------------------------------
    if reversible_enc:
        findings.append({
            "title": "Per-Account Reversible Encryption Enabled",
            "severity": "critical",
            "deduction": 20,
            "description": (
                f"{len(reversible_enc)} enabled account(s) have the "
                "ENCRYPTED_TEXT_PASSWORD_ALLOWED (reversible encryption) flag set. "
                "This stores the password in a recoverable form in the AD database -- "
                "essentially plaintext. Any attacker with access to the NTDS.dit file "
                "can recover the plaintext credentials."
            ),
            "recommendation": (
                "Clear the ENCRYPTED_TEXT_PASSWORD_ALLOWED UAC flag on all accounts. "
                "Require all affected users to change their passwords after the change. "
                "Audit using: (userAccountControl:1.2.840.113556.1.4.803:=128)"
            ),
            "details": reversible_enc,
        })

    if passwd_notreqd:
        findings.append({
            "title": "Accounts With PASSWD_NOTREQD Flag Set",
            "severity": "high",
            "deduction": 15,
            "description": (
                f"{len(passwd_notreqd)} enabled account(s) have the PASSWD_NOTREQD flag "
                "(UAC bit 0x20) set, meaning these accounts are not required to have a "
                "password at all. This bypasses the domain password policy completely. "
                "These accounts may have empty or trivially simple passwords."
            ),
            "recommendation": (
                "Clear the PASSWD_NOTREQD flag on all accounts and force a password reset. "
                "Use: Get-ADUser -Filter {PasswordNotRequired -eq $true} to enumerate. "
                "Investigate why these accounts were created with this flag."
            ),
            "details": passwd_notreqd,
        })

    if dup_spns:
        dup_details = [
            f"SPN '{spn}' -> {', '.join(accounts)}"
            for spn, accounts in list(dup_spns.items())[:50]
        ]
        findings.append({
            "title": f"Duplicate Service Principal Names Detected ({len(dup_spns)} conflicts)",
            "severity": "high",
            "deduction": 15,
            "description": (
                f"{len(dup_spns)} SPN(s) are registered on more than one account. "
                "Duplicate SPNs cause Kerberos authentication failures and can be abused: "
                "if an attacker controls one of the conflicting accounts, they may be able "
                "to intercept Kerberos service tickets intended for the legitimate service."
            ),
            "recommendation": (
                "Remove duplicate SPNs -- each SPN must be unique within the forest. "
                "Use: setspn -X -F (forest-wide duplicate check) to enumerate. "
                "Identify which account should own the SPN and remove it from the others."
            ),
            "details": dup_details,
        })

    if stale_users:
        findings.append({
            "title": f"Stale Enabled User Accounts (Inactive > {_STALE_DAYS} Days)",
            "severity": "medium",
            "deduction": 8,
            "description": (
                f"{len(stale_users)} enabled user account(s) have not authenticated in "
                f"over {_STALE_DAYS} days. Stale accounts increase the attack surface -- "
                "they may belong to former employees, vendors, or abandoned service accounts "
                "and are often overlooked in access reviews."
            ),
            "recommendation": (
                "Implement a lifecycle management process. Disable accounts after 90 days "
                "of inactivity and delete after 180 days (or per your retention policy). "
                "Use scheduled tasks or Identity Governance tooling for automation."
            ),
            "details": stale_users[:100],
        })

    if stale_comps:
        findings.append({
            "title": f"Stale Enabled Computer Accounts (Inactive > {_STALE_DAYS} Days)",
            "severity": "medium",
            "deduction": 8,
            "description": (
                f"{len(stale_comps)} enabled computer account(s) have not authenticated "
                f"in over {_STALE_DAYS} days. Stale computer accounts may represent "
                "decommissioned workstations/servers still present in AD, increasing "
                "the domain attack surface."
            ),
            "recommendation": (
                "Disable or delete stale computer accounts. "
                "Verify the physical/virtual machine is decommissioned before removal. "
                "Automate with: Search-ADAccount -ComputerObject -AccountInactive -TimeSpan 90."
            ),
            "details": stale_comps[:100],
        })

    if never_logon_users:
        findings.append({
            "title": "Enabled User Accounts That Have Never Logged On",
            "severity": "medium",
            "deduction": 8,
            "description": (
                f"{len(never_logon_users)} enabled user account(s) have no recorded "
                "logon history (lastLogonTimestamp is unset). These may be provisioned "
                "accounts waiting for onboarding, orphaned accounts, or test accounts "
                "that were never cleaned up."
            ),
            "recommendation": (
                "Review all enabled accounts with no logon history. "
                "Disable accounts that have been active for more than 30 days without "
                "any authentication. Investigate if any are shared/service accounts."
            ),
            "details": never_logon_users[:100],
        })

    if old_pwd_users:
        findings.append({
            "title": f"Enabled User Accounts With Passwords Older Than {_OLD_PWD_DAYS} Days",
            "severity": "medium",
            "deduction": 8,
            "description": (
                f"{len(old_pwd_users)} enabled user account(s) (without DONT_EXPIRE_PASSWD) "
                f"have passwords that have not been changed in over {_OLD_PWD_DAYS} days. "
                "Old passwords increase the risk of credential compromise, especially "
                "if the domain has had past breaches or NTLM hash exposure."
            ),
            "recommendation": (
                "Force password resets for accounts with passwords older than 365 days. "
                "Review domain password expiry policy and ensure it is being enforced. "
                "Consider breach-detection integration (HIBP) for password validation."
            ),
            "details": old_pwd_users[:100],
        })

    if never_logon_comps:
        findings.append({
            "title": "Enabled Computer Accounts That Have Never Authenticated",
            "severity": "low",
            "deduction": 5,
            "description": (
                f"{len(never_logon_comps)} enabled computer account(s) have no recorded "
                "authentication history. These may be pre-staged accounts or systems "
                "that were joined to the domain but never brought online."
            ),
            "recommendation": (
                "Audit pre-staged computer accounts. Disable or delete those that "
                "do not correspond to active systems."
            ),
            "details": never_logon_comps[:100],
        })

    return findings
