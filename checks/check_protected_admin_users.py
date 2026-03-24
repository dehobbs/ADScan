CHECK_NAME = "Protected Admin Users"
CHECK_ORDER = 60
CHECK_CATEGORY = ["Privileged Accounts"]

from datetime import datetime, timezone, timedelta

# Accounts with adminCount=1 that have NOT logged on in this many days are flagged as stale
STALE_DAYS = 90

# UAC flag: account is disabled
UAC_DISABLED = 0x2

# Well-known privileged group RIDs (relative to domain SID)
# We use these to determine if an adminCount=1 account is truly expected
EXPECTED_PRIV_GROUPS = {
    "512",  # Domain Admins
    "518",  # Schema Admins
    "519",  # Enterprise Admins
    "548",  # Account Operators
    "549",  # Server Operators
    "550",  # Print Operators
    "551",  # Backup Operators
    "552",  # Replicators
}


def _uac_disabled(uac):
    try:
        return bool(int(uac) & UAC_DISABLED)
    except Exception:
        return False


def _days_since(timestamp_str):
    """Return number of days since an AD timestamp (ISO format or None)."""
    if not timestamp_str:
        return None
    try:
        if isinstance(timestamp_str, str):
            dt = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        else:
            dt = timestamp_str
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        delta = datetime.now(timezone.utc) - dt
        return delta.days
    except Exception:
        return None


def run_check(connector, verbose=False):
    findings = []

    try:
        # Query all accounts with adminCount=1
        results = connector.ldap_search(
            search_filter="(&(objectCategory=person)(objectClass=user)(adminCount=1))",
            attributes=[
                "sAMAccountName",
                "distinguishedName",
                "userAccountControl",
                "lastLogonTimestamp",
                "pwdLastSet",
                "memberOf",
                "whenCreated",
                "description",
            ],
        )

        if not results:
            findings.append({
                "title": "Protected Admin Users: No adminCount=1 accounts found",
                "severity": "info",
                "deduction": 0,
                "description": "No accounts with adminCount=1 were found. This attribute marks accounts protected by SDProp.",
                "recommendation": "No action required.",
                "details": [],
            })
            return findings

        ghost_accounts = []    # disabled but adminCount=1
        stale_accounts = []    # enabled but never/long-since logged on
        orphaned_accounts = [] # adminCount=1 but no longer member of any privileged group

        for entry in results:
            sam = entry.get("sAMAccountName", "unknown")
            dn = entry.get("distinguishedName", "")
            uac = entry.get("userAccountControl", 0)
            last_logon = entry.get("lastLogonTimestamp")
            member_of = entry.get("memberOf") or []
            if isinstance(member_of, str):
                member_of = [member_of]

            # Skip well-known system accounts
            if sam.lower() in ("krbtgt",):
                continue

            # Ghost: disabled account still carrying adminCount=1
            if _uac_disabled(uac):
                ghost_accounts.append(f"{sam} (DN: {dn})")
                continue

            # Stale: enabled but last logon > STALE_DAYS ago or never logged in
            days = _days_since(last_logon)
            if days is None or days > STALE_DAYS:
                stale_label = "never logged in" if days is None else f"{days} days ago"
                stale_accounts.append(f"{sam} — last logon: {stale_label}")

            # Orphaned: adminCount=1 but not a member of any recognised priv group
            in_priv_group = False
            for grp_dn in member_of:
                # Check if group DN contains a known RID CN pattern
                for rid in EXPECTED_PRIV_GROUPS:
                    if f"-{rid}," in grp_dn or grp_dn.lower().startswith(f"cn=domain admins") or                        "domain admins" in grp_dn.lower() or "enterprise admins" in grp_dn.lower() or                        "schema admins" in grp_dn.lower() or "account operators" in grp_dn.lower() or                        "backup operators" in grp_dn.lower() or "server operators" in grp_dn.lower() or                        "print operators" in grp_dn.lower() or "administrators" in grp_dn.lower():
                        in_priv_group = True
                        break
                if in_priv_group:
                    break

            if not in_priv_group:
                orphaned_accounts.append(f"{sam} (DN: {dn})")

        # --- Ghost accounts finding ---
        if ghost_accounts:
            findings.append({
                "title": f"Ghost Admin Accounts: {len(ghost_accounts)} disabled account(s) with adminCount=1",
                "severity": "medium",
                "deduction": 8,
                "description": (
                    "These accounts are disabled but still carry adminCount=1 and therefore "
                    "fall under SDProp protection, meaning their ACLs are continuously overwritten "
                    "to match AdminSDHolder. An attacker who re-enables such an account immediately "
                    "gains protected admin privileges."
                ),
                "recommendation": (
                    "Remove adminCount=1 from disabled accounts or delete them entirely. "
                    "Use: Set-ADUser <account> -Clear adminCount"
                ),
                "details": ghost_accounts,
            })

        # --- Stale accounts finding ---
        if stale_accounts:
            findings.append({
                "title": f"Stale Protected Admin Accounts: {len(stale_accounts)} account(s) inactive > {STALE_DAYS} days",
                "severity": "high",
                "deduction": 10,
                "description": (
                    f"These enabled accounts have adminCount=1 but have not authenticated in over "
                    f"{STALE_DAYS} days (or have never logged on). Stale privileged accounts are "
                    "prime targets for password-spray and credential-stuffing attacks."
                ),
                "recommendation": (
                    "Disable or delete stale privileged accounts. Investigate whether each account "
                    "is still required. If service accounts, migrate to gMSAs."
                ),
                "details": stale_accounts,
            })

        # --- Orphaned accounts finding ---
        if orphaned_accounts:
            findings.append({
                "title": f"Orphaned adminCount=1 Accounts: {len(orphaned_accounts)} account(s) no longer in privileged groups",
                "severity": "medium",
                "deduction": 8,
                "description": (
                    "These accounts have adminCount=1 set (receiving SDProp DACL protection) but "
                    "are no longer members of any recognised privileged group. This is a residual "
                    "flag from a previous group membership that was never cleaned up. "
                    "Their non-standard ACLs can block legitimate auditing and access."
                ),
                "recommendation": (
                    "Clear adminCount on accounts no longer in privileged groups: "
                    "Get-ADUser <account> | Set-ADObject -Clear adminCount. "
                    "Then reset the DACL to the default via Active Directory Users and Computers > "
                    "Advanced > Reset permissions."
                ),
                "details": orphaned_accounts,
            })

        if not findings:
            findings.append({
                "title": "Protected Admin Users: No issues found",
                "severity": "info",
                "deduction": 0,
                "description": (
                    f"All {len(results)} adminCount=1 accounts are active members of privileged "
                    "groups, enabled, and have logged in within the last 90 days."
                ),
                "recommendation": "Continue to periodically review privileged account inventory.",
                "details": [],
            })

    except Exception as e:
        findings.append({
            "title": "Protected Admin Users: Check encountered an error",
            "severity": "info",
            "deduction": 0,
            "description": f"The check could not complete: {e}",
            "recommendation": "Verify LDAP connectivity and permissions.",
            "details": [str(e)],
        })

    return findings
