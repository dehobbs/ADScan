"""
checks/check_protected_users_group.py - Protected Users Group Membership Check

Identifies enabled privileged accounts that are NOT members of the Protected Users
security group (introduced in Windows Server 2012 R2 / domain functional level 2012 R2).

Membership of Protected Users enforces the following restrictions regardless of
individual account or GPO settings:
  - NTLM authentication is blocked (Kerberos only)
  - RC4 and DES Kerberos encryption is blocked (AES only)
  - Credentials are NOT cached (no LSASS credential material)
  - Kerberos TGT lifetime is capped at 4 hours (non-renewable)
  - Delegation (constrained, unconstrained, and S4U2Self) is blocked

Accounts checked: members of Domain Admins, Enterprise Admins, Schema Admins,
Administrators, Account Operators, Backup Operators, and Server Operators.

Risk Deductions:
  High   (-12): Tier-0 accounts (DA/EA/SA/Administrators) not in Protected Users
  Medium  (-6): Tier-1 accounts (AO/BO/SO) not in Protected Users
  Medium  (-8): Protected Users group does not exist (pre-2012 R2 domain)
"""

CHECK_NAME = "Protected Users Group Membership"
CHECK_ORDER = 61
CHECK_CATEGORY = ["Privileged Accounts"]

# UAC flag: account disabled
_UAC_DISABLED = 0x2

# High-privilege Tier-0 groups — absence from Protected Users is High severity
_TIER0_GROUPS = [
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
]

# Sensitive Tier-1 groups — absence from Protected Users is Medium severity
_TIER1_GROUPS = [
    "Account Operators",
    "Backup Operators",
    "Server Operators",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_disabled(entry):
    try:
        return bool(int(entry.get("userAccountControl", 0)) & _UAC_DISABLED)
    except Exception:
        return False


def _get_sam(entry):
    try:
        val = entry.get("sAMAccountName", "?")
        return str(val) if not hasattr(val, "value") else str(val.value)
    except Exception:
        return "?"


def _get_attr(entry, key):
    """Return a normalised string value for an attribute from an ldap3 result entry."""
    try:
        val = entry.get(key)
        if val is None:
            return None
        return str(val) if not hasattr(val, "value") else str(val.value)
    except Exception:
        return None


def _get_dn(entry):
    return _get_attr(entry, "distinguishedName") or ""


def _find_group_dn(connector, group_name):
    """Return the DN of a group by sAMAccountName, or None if not found."""
    results = connector.ldap_search(
        search_filter=f"(&(objectClass=group)(sAMAccountName={group_name}))",
        attributes=["distinguishedName"],
    )
    if results:
        return _get_dn(results[0])
    return None


def _get_group_members(connector, group_dn):
    """Return list of result entries for enabled users who are direct members of group_dn."""
    results = connector.ldap_search(
        search_filter=f"(&(objectClass=user)(objectCategory=person)(memberOf={group_dn}))",
        attributes=["sAMAccountName", "distinguishedName", "userAccountControl"],
    )
    if not results:
        return []
    enabled = []
    for entry in results:
        if not _is_disabled(entry):
            enabled.append(entry)
    return enabled


def _get_protected_users_members(connector, protected_users_dn):
    """Return a set of lowercase DNs for all members of Protected Users."""
    results = connector.ldap_search(
        search_filter=f"(&(objectClass=user)(objectCategory=person)(memberOf={protected_users_dn}))",
        attributes=["distinguishedName"],
    )
    if not results:
        return set()
    return {_get_dn(e).lower() for e in results}


# ---------------------------------------------------------------------------
# Main check
# ---------------------------------------------------------------------------

def run_check(connector, verbose=False):
    findings = []
    log = connector.log

    try:
        # -----------------------------------------------------------------------
        # 1. Locate the Protected Users group
        # -----------------------------------------------------------------------
        protected_users_dn = _find_group_dn(connector, "Protected Users")

        if not protected_users_dn:
            findings.append({
                "title": "Protected Users Group Does Not Exist",
                "severity": "medium",
                "deduction": 8,
                "description": (
                    "The 'Protected Users' security group was not found in this domain. "
                    "This group was introduced in Windows Server 2012 R2 and requires a "
                    "domain functional level of 2012 R2 or higher. Without it, privileged "
                    "accounts cannot benefit from its hardened authentication restrictions "
                    "(no NTLM, no RC4, no credential caching, 4-hour TGT cap)."
                ),
                "recommendation": (
                    "Raise the domain functional level to Windows Server 2012 R2 or higher "
                    "to enable the Protected Users group. Once available, add all Tier-0 "
                    "privileged accounts to it and test for NTLM/RC4 dependency issues "
                    "before enforcing broadly."
                ),
                "details": ["Protected Users group not found — domain may be pre-2012 R2 DFL"],
            })
            return findings

        # -----------------------------------------------------------------------
        # 2. Enumerate current Protected Users membership
        # -----------------------------------------------------------------------
        protected_dns = _get_protected_users_members(connector, protected_users_dn)

        log.debug(f"  Protected Users DN  : {protected_users_dn}")
        log.debug(f"  Protected Users members: {len(protected_dns)}")

        # -----------------------------------------------------------------------
        # 3. Check Tier-0 groups
        # -----------------------------------------------------------------------
        tier0_unprotected = []
        tier0_seen = set()

        for group_name in _TIER0_GROUPS:
            group_dn = _find_group_dn(connector, group_name)
            if not group_dn:
                continue
            members = _get_group_members(connector, group_dn)
            for entry in members:
                sam = _get_sam(entry)
                dn_lower = _get_dn(entry).lower()
                if dn_lower in tier0_seen:
                    continue
                tier0_seen.add(dn_lower)
                # Skip well-known service accounts that should never be in Protected Users
                if sam.lower() in ("krbtgt",):
                    continue
                if dn_lower not in protected_dns:
                    tier0_unprotected.append(f"{sam} (member of: {group_name})")
                    log.debug(f"  [!] {sam} is NOT in Protected Users (Tier-0: {group_name})")

        if tier0_unprotected:
            findings.append({
                "title": (
                    f"Tier-0 Privileged Accounts Not in Protected Users: "
                    f"{len(tier0_unprotected)} account(s)"
                ),
                "severity": "high",
                "deduction": 12,
                "description": (
                    f"{len(tier0_unprotected)} enabled Tier-0 privileged account(s) are not "
                    "members of the Protected Users group. These accounts remain vulnerable to "
                    "NTLM relay attacks, RC4/DES downgrade attacks, and credential theft via "
                    "LSASS dumping. Protected Users membership blocks all of these vectors "
                    "at the domain level, independent of local host configuration."
                ),
                "recommendation": (
                    "Add all Tier-0 accounts (Domain Admins, Enterprise Admins, Schema Admins, "
                    "Administrators) to the Protected Users group. Before doing so, audit each "
                    "account for NTLM or RC4 dependencies (e.g. legacy applications, NTLMv2 "
                    "logons). Test in a non-production environment first. Note: computer and "
                    "service accounts should generally NOT be added as this can break "
                    "authentication for services that require NTLM or Kerberos delegation."
                ),
                "details": tier0_unprotected,
            })
        else:
            log.debug("  [OK] All Tier-0 accounts are in Protected Users")

        # -----------------------------------------------------------------------
        # 4. Check Tier-1 groups
        # -----------------------------------------------------------------------
        tier1_unprotected = []
        tier1_seen = set()

        for group_name in _TIER1_GROUPS:
            group_dn = _find_group_dn(connector, group_name)
            if not group_dn:
                continue
            members = _get_group_members(connector, group_dn)
            for entry in members:
                sam = _get_sam(entry)
                dn_lower = _get_dn(entry).lower()
                if dn_lower in tier1_seen or dn_lower in tier0_seen:
                    continue
                tier1_seen.add(dn_lower)
                if dn_lower not in protected_dns:
                    tier1_unprotected.append(f"{sam} (member of: {group_name})")
                    log.debug(f"  [!] {sam} is NOT in Protected Users (Tier-1: {group_name})")

        if tier1_unprotected:
            findings.append({
                "title": (
                    f"Tier-1 Privileged Accounts Not in Protected Users: "
                    f"{len(tier1_unprotected)} account(s)"
                ),
                "severity": "medium",
                "deduction": 6,
                "description": (
                    f"{len(tier1_unprotected)} enabled Tier-1 privileged account(s) "
                    "(Account Operators, Backup Operators, Server Operators) are not "
                    "members of the Protected Users group. While less critical than Tier-0, "
                    "these accounts carry significant implicit privileges and benefit from "
                    "the same NTLM/RC4 restrictions that Protected Users enforces."
                ),
                "recommendation": (
                    "Evaluate adding Tier-1 accounts to Protected Users after resolving "
                    "any NTLM/RC4 compatibility issues. Prioritise Tier-0 accounts first. "
                    "As with Tier-0, do not add computer accounts or service accounts that "
                    "rely on NTLM authentication or Kerberos delegation."
                ),
                "details": tier1_unprotected,
            })
        else:
            log.debug("  [OK] All Tier-1 accounts are in Protected Users (or groups are empty)")

        # -----------------------------------------------------------------------
        # 5. Clean pass
        # -----------------------------------------------------------------------
        if not findings:
            total_checked = len(tier0_seen) + len(tier1_seen)
            findings.append({
                "title": "Protected Users Group Membership: No Issues Found",
                "severity": "info",
                "deduction": 0,
                "description": (
                    f"All {total_checked} enabled privileged account(s) checked are members "
                    "of the Protected Users group. NTLM, RC4, and credential-caching "
                    "restrictions are in effect for these accounts."
                ),
                "recommendation": (
                    "Continue to enforce Protected Users membership as part of your "
                    "privileged access management process. Review membership quarterly."
                ),
                "details": [],
            })

    except Exception as e:
        findings.append({
            "title": "Protected Users Group Membership: Check Encountered an Error",
            "severity": "info",
            "deduction": 0,
            "description": f"The check could not complete: {e}",
            "recommendation": "Verify LDAP connectivity and permissions.",
            "details": [str(e)],
        })

    return findings
