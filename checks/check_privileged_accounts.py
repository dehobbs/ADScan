"""
checks/check_privileged_accounts.py - Privileged Account Security Check

Enumerates members of high-privilege groups and evaluates their security posture.

Checks performed:
  - Membership of: Domain Admins, Enterprise Admins, Schema Admins,
    Administrators, Account Operators, Backup Operators, Print Operators,
    Server Operators, Group Policy Creator Owners, DNSAdmins
  - Stale privileged accounts (lastLogonTimestamp > 90 days)
  - Non-expiring passwords on privileged accounts
  - Passwords stored in the Description field (keyword scan)
  - Built-in Administrator account (RID 500) in active use / enabled
  - krbtgt account password age (> 180 days)

Risk Deductions:
  Critical (-20): krbtgt password > 180 days
  Critical (-20): Password in description field of privileged account
  High    (-15): Non-expiring passwords on privileged accounts
  High    (-15): Stale privileged accounts (>90 days inactive)
  High    (-15): Built-in Administrator account actively used / not renamed
  Medium  (-8) : Excessive members in Tier-0 groups
  Low     (-5) : Account Operators / Backup Operators / Print Operators populated
"""

CHECK_NAME = "Privileged Accounts"
CHECK_ORDER = 4
CHECK_CATEGORY = "Privileged Identity Governance"

from datetime import datetime, timezone, timedelta

# UAC flags
_UAC_ACCOUNTDISABLE       = 0x2
_UAC_PASSWD_NOTREQD       = 0x20
_UAC_DONT_EXPIRE_PASSWD   = 0x10000
_UAC_SMARTCARD_REQUIRED   = 0x40000

# Windows FILETIME epoch offset (100-ns intervals between 1601-01-01 and 1970-01-01)
_FILETIME_EPOCH_OFFSET = 11644473600

# Sensitive keywords that suggest a password is stored in description
_PASSWORD_KEYWORDS = [
    "pass", "pwd", "password", "cred", "secret", "token",
    "key", "login", "logon", "auth", "p@ss", "p@$$",
]

# Group common names to check (sAMAccountName)
_TIER0_GROUPS = [
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Group Policy Creator Owners",
]
_TIER1_GROUPS = [
    "Account Operators",
    "Backup Operators",
    "Print Operators",
    "Server Operators",
    "DnsAdmins",
    "Remote Management Users",
    "Exchange Windows Permissions",
    "Exchange Trusted Subsystem",
]

_ATTRS_GROUP = ["member", "distinguishedName", "sAMAccountName"]
_ATTRS_USER  = [
    "sAMAccountName", "distinguishedName", "userAccountControl",
    "pwdLastSet", "lastLogonTimestamp", "description",
    "objectSid", "adminCount", "memberOf",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _uac(entry, flag):
    try:
        return bool(int(entry["userAccountControl"].value) & flag)
    except Exception:
        return False


def _is_disabled(entry):
    return _uac(entry, _UAC_ACCOUNTDISABLE)


def _pwd_never_expires(entry):
    return _uac(entry, _UAC_DONT_EXPIRE_PASSWD)


def _filetime_to_dt(filetime_val):
    """Convert Windows FILETIME (int or ldap3 value) to UTC datetime, or None."""
    try:
        val = int(filetime_val)
        if val <= 0:
            return None
        ts = (val / 10_000_000) - _FILETIME_EPOCH_OFFSET
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    except Exception:
        return None


def _last_logon_dt(entry):
    try:
        return _filetime_to_dt(entry["lastLogonTimestamp"].value)
    except Exception:
        return None


def _pwd_last_set_dt(entry):
    try:
        return _filetime_to_dt(entry["pwdLastSet"].value)
    except Exception:
        return None


def _description_has_password(entry):
    """Return True if the description field looks like it contains a password."""
    try:
        desc = str(entry["description"].value).lower()
        return any(kw in desc for kw in _PASSWORD_KEYWORDS)
    except Exception:
        return False


def _get_sam(entry):
    try:
        return str(entry["sAMAccountName"].value)
    except Exception:
        return "?"


def _get_rid(entry):
    """Extract the RID from an objectSid."""
    try:
        sid = entry["objectSid"].value  # bytes
        return int.from_bytes(sid[-4:], byteorder="little")
    except Exception:
        return None


def _resolve_members(connector, group_dn, verbose=False):
    """Return a flat list of user SAMAccountNames who are members of the group DN."""
    entries = connector.ldap_search(
        search_filter=f"(memberOf={group_dn})",
        attributes=_ATTRS_USER,
    )
    return entries or []


def _search_group(connector, group_name):
    """Find a group by sAMAccountName, return its DN or None."""
    entries = connector.ldap_search(
        search_filter=f"(&(objectClass=group)(sAMAccountName={group_name}))",
        attributes=["distinguishedName", "sAMAccountName"],
    )
    if entries:
        return entries[0]
    return None


# ---------------------------------------------------------------------------
# Main check
# ---------------------------------------------------------------------------

def run_check(connector, verbose=False):
    findings = []
    now = datetime.now(tz=timezone.utc)
    stale_threshold = now - timedelta(days=90)
    krbtgt_threshold = now - timedelta(days=180)

    # -----------------------------------------------------------------------
    # 1. Tier-0 group membership analysis
    # -----------------------------------------------------------------------
    tier0_members_all = {}   # group_name -> list of SAM names

    for group_name in _TIER0_GROUPS:
        group_entry = _search_group(connector, group_name)
        if not group_entry:
            continue
        group_dn = str(group_entry["distinguishedName"].value)
        members = _resolve_members(connector, group_dn, verbose)
        active_members = [e for e in members if not _is_disabled(e)]
        if verbose:
            print(f"     {group_name}: {len(active_members)} active member(s)")
        tier0_members_all[group_name] = active_members

    # Collect all unique privileged user entries (deduplicated by SAM)
    seen_sams = set()
    all_priv_entries = []
    for members in tier0_members_all.values():
        for entry in members:
            sam = _get_sam(entry)
            if sam not in seen_sams:
                seen_sams.add(sam)
                all_priv_entries.append(entry)

    # -----------------------------------------------------------------------
    # 2. Excessive Tier-0 membership
    # -----------------------------------------------------------------------
    da_group = tier0_members_all.get("Domain Admins", [])
    # Filter out default accounts (krbtgt, Administrator) for count
    da_real = [e for e in da_group
               if _get_sam(e).lower() not in ("krbtgt", "administrator")]
    if len(da_real) > 5:
        findings.append({
            "title": "Excessive Domain Admins Membership",
            "severity": "medium",
            "deduction": 8,
            "description": (
                f"Domain Admins contains {len(da_real)} active non-default member(s). "
                "A large Domain Admins group significantly increases the attack surface. "
                "Each member is a potential path to full domain compromise."
            ),
            "recommendation": (
                "Apply the principle of least privilege. Limit Domain Admins to "
                "break-glass accounts only. Use delegated permissions or JIT/PAM "
                "solutions for day-to-day administrative tasks."
            ),
            "details": [_get_sam(e) for e in da_real],
        })

    # -----------------------------------------------------------------------
    # 3. Non-expiring passwords on privileged accounts
    # -----------------------------------------------------------------------
    non_expiring = [
        _get_sam(e) for e in all_priv_entries
        if _pwd_never_expires(e) and _get_sam(e).lower() != "krbtgt"
    ]
    if non_expiring:
        findings.append({
            "title": "Privileged Accounts with Non-Expiring Passwords",
            "severity": "high",
            "deduction": 15,
            "description": (
                f"{len(non_expiring)} privileged account(s) have the "
                "'Password Never Expires' flag set. If these credentials are "
                "compromised, the attacker retains access indefinitely."
            ),
            "recommendation": (
                "Remove the DONT_EXPIRE_PASSWD flag from all privileged accounts. "
                "Consider pairing long passphrase policies with breach-detection "
                "monitoring instead of mandatory rotation."
            ),
            "details": non_expiring,
        })

    # -----------------------------------------------------------------------
    # 4. Stale privileged accounts
    # -----------------------------------------------------------------------
    stale = []
    for entry in all_priv_entries:
        sam = _get_sam(entry)
        if sam.lower() in ("krbtgt",):
            continue
        last_logon = _last_logon_dt(entry)
        if last_logon is None:
            stale.append(f"{sam} (never logged on)")
        elif last_logon < stale_threshold:
            days_ago = (now - last_logon).days
            stale.append(f"{sam} (last logon: {days_ago} days ago)")

    if stale:
        findings.append({
            "title": "Stale Privileged Accounts (Inactive > 90 Days)",
            "severity": "high",
            "deduction": 15,
            "description": (
                f"{len(stale)} privileged account(s) have not logged on in over 90 days. "
                "Stale accounts may belong to departed employees or unused service accounts "
                "and represent an unnecessary attack surface."
            ),
            "recommendation": (
                "Disable or remove privileged accounts that have been inactive for "
                "more than 90 days. Implement a quarterly access review process."
            ),
            "details": stale,
        })

    # -----------------------------------------------------------------------
    # 5. Passwords in Description field
    # -----------------------------------------------------------------------
    desc_passwords = [
        f"{_get_sam(e)}: {e['description'].value}"
        for e in all_priv_entries
        if _description_has_password(e)
    ]
    if desc_passwords:
        findings.append({
            "title": "Passwords Found in Privileged Account Description Fields",
            "severity": "critical",
            "deduction": 20,
            "description": (
                f"{len(desc_passwords)} privileged account(s) appear to have passwords "
                "or credentials stored in the Description attribute. This attribute is "
                "readable by all authenticated domain users and is a common misconfiguration "
                "left over from legacy account provisioning."
            ),
            "recommendation": (
                "Immediately clear the Description attribute for all affected accounts "
                "and rotate the credentials. Audit all accounts — not just privileged ones "
                "— for this pattern using: (description=*pass*)"
            ),
            "details": desc_passwords,
        })

    # -----------------------------------------------------------------------
    # 6. Built-in Administrator (RID 500)
    # -----------------------------------------------------------------------
    admin_entries = connector.ldap_search(
        search_filter="(&(objectClass=user)(objectSid=*)(sAMAccountName=Administrator))",
        attributes=_ATTRS_USER,
    )
    # Also search by RID 500 via objectSid filter pattern
    for entry in (admin_entries or []):
        rid = _get_rid(entry)
        if rid != 500:
            continue
        sam = _get_sam(entry)
        disabled = _is_disabled(entry)
        last_logon = _last_logon_dt(entry)
        recently_used = (
            last_logon is not None and
            (now - last_logon).days < 30
        )

        issues = []
        if not disabled:
            issues.append("account is enabled")
        if recently_used:
            issues.append(f"last used {(now - last_logon).days} days ago")
        if _pwd_never_expires(entry):
            issues.append("password never expires")
        if sam == "Administrator":
            issues.append("account has not been renamed (still 'Administrator')")

        if issues:
            findings.append({
                "title": "Built-in Administrator Account (RID 500) Security Issues",
                "severity": "high",
                "deduction": 15,
                "description": (
                    "The built-in Administrator account (RID 500) has one or more security issues. "
                    "This account cannot be locked out and is a high-value target. "
                    f"Issues found: {'; '.join(issues)}."
                ),
                "recommendation": (
                    "Rename the built-in Administrator account to a non-obvious name. "
                    "Disable it if not required for emergency break-glass access. "
                    "Enable the 'Password Never Expires' only if managed via a PAM solution. "
                    "Monitor all authentication events for this account (Event ID 4624)."
                ),
                "details": [f"RID-500 ({sam}): {', '.join(issues)}"],
            })
        break

    # -----------------------------------------------------------------------
    # 7. krbtgt password age
    # -----------------------------------------------------------------------
    krbtgt_entries = connector.ldap_search(
        search_filter="(&(objectClass=user)(sAMAccountName=krbtgt))",
        attributes=["sAMAccountName", "pwdLastSet", "distinguishedName"],
    )
    for entry in (krbtgt_entries or []):
        pwd_set = _pwd_last_set_dt(entry)
        if pwd_set is None:
            findings.append({
                "title": "krbtgt Password Has Never Been Reset",
                "severity": "critical",
                "deduction": 20,
                "description": (
                    "The krbtgt account password has never been changed (pwdLastSet = 0). "
                    "The krbtgt key is used to sign all Kerberos tickets in the domain. "
                    "A stale key may indicate the domain has never been hardened post-setup, "
                    "and any Golden Ticket forged with the current key remains valid."
                ),
                "recommendation": (
                    "Reset the krbtgt password twice (to invalidate any forged tickets). "
                    "Establish a procedure to rotate it every 180 days. "
                    "See Microsoft's krbtgt reset script on GitHub."
                ),
                "details": ["pwdLastSet = 0 (never changed)"],
            })
        elif pwd_set < krbtgt_threshold:
            days_old = (now - pwd_set).days
            findings.append({
                "title": f"krbtgt Password Not Rotated in {days_old} Days",
                "severity": "critical",
                "deduction": 20,
                "description": (
                    f"The krbtgt account password was last set {days_old} days ago "
                    f"(on {pwd_set.strftime('%Y-%m-%d')}). "
                    "Golden Tickets forged before a krbtgt reset remain valid. "
                    "Regular rotation limits the blast radius of any potential compromise."
                ),
                "recommendation": (
                    "Reset the krbtgt password twice to invalidate all existing Kerberos tickets. "
                    "Aim to rotate every 90-180 days. "
                    "Use the Microsoft ATA/Defender for Identity recommended reset procedure."
                ),
                "details": [
                    f"pwdLastSet: {pwd_set.strftime('%Y-%m-%d')} ({days_old} days ago)"
                ],
            })
        break

    # -----------------------------------------------------------------------
    # 8. Tier-1 sensitive groups populated
    # -----------------------------------------------------------------------
    tier1_populated = []
    for group_name in _TIER1_GROUPS:
        group_entry = _search_group(connector, group_name)
        if not group_entry:
            continue
        group_dn = str(group_entry["distinguishedName"].value)
        members = _resolve_members(connector, group_dn)
        active = [_get_sam(e) for e in members if not _is_disabled(e)]
        if active:
            tier1_populated.append(f"{group_name} ({len(active)} member(s)): {', '.join(active[:5])}")

    if tier1_populated:
        findings.append({
            "title": "Sensitive Delegated Groups Have Active Members",
            "severity": "low",
            "deduction": 5,
            "description": (
                "The following sensitive built-in groups have active members. "
                "Groups like Backup Operators and Account Operators have implicit "
                "domain-level privileges that can be abused for privilege escalation "
                "even without Domain Admin membership."
            ),
            "recommendation": (
                "Audit membership of all sensitive built-in groups regularly. "
                "Remove unnecessary members. Where possible, replace broad group "
                "membership with fine-grained delegated permissions."
            ),
            "details": tier1_populated,
        })

    return findings
