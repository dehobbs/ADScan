CHECK_NAME = "SID History"
CHECK_ORDER = 64
CHECK_CATEGORY = ["Account Hygiene"]

# Well-known privileged group RIDs that trigger CRITICAL escalation
PRIVILEGED_RIDS = {
    "500",  # Domain Administrator
    "502",  # krbtgt
    "512",  # Domain Admins
    "516",  # Domain Controllers
    "517",  # Cert Publishers
    "518",  # Schema Admins
    "519",  # Enterprise Admins
    "520",  # Group Policy Creator Owners
    "521",  # Read-only Domain Controllers
    "544",  # BUILTIN Administrators
    "548",  # Account Operators
    "549",  # Server Operators
    "550",  # Print Operators
    "551",  # Backup Operators
    "552",  # Replicators
    "553",  # RAS and IAS Servers
}

# Well-known SID prefixes for BUILTIN groups
BUILTIN_PRIVILEGED_SIDS = {
    "S-1-5-32-544",  # Administrators
    "S-1-5-32-548",  # Account Operators
    "S-1-5-32-549",  # Server Operators
    "S-1-5-32-550",  # Print Operators
    "S-1-5-32-551",  # Backup Operators
    "S-1-5-18",      # SYSTEM
}


def _sid_is_privileged(sid_str):
    """
    Return True if a SID maps to a privileged group / account.
    Checks:
      - BUILTIN well-known SIDs
      - Domain SIDs ending in a privileged RID
    """
    if not sid_str:
        return False
    sid_str = str(sid_str)

    # Check BUILTIN well-known
    if sid_str in BUILTIN_PRIVILEGED_SIDS:
        return True

    # Check domain SIDs: format S-1-5-21-<sub>-<sub>-<sub>-<RID>
    parts = sid_str.split("-")
    if len(parts) >= 2:
        rid = parts[-1]
        if rid in PRIVILEGED_RIDS:
            return True

    return False


def run_check(connector, verbose=False):
    findings = []

    try:
        # Query all objects (users and computers) that have sIDHistory populated
        results = connector.ldap_search(
            search_filter="(sIDHistory=*)",
            attributes=[
                "sAMAccountName",
                "distinguishedName",
                "objectClass",
                "sIDHistory",
                "userAccountControl",
                "adminCount",
            ],
        )

        if not results:
            findings.append({
                "title": "SID History: No accounts with sIDHistory found",
                "severity": "info",
                "deduction": 0,
                "description": (
                    "No accounts with populated sIDHistory attributes were found. "
                    "This is expected in a healthy domain with no recent migrations or "
                    "domain consolidations."
                ),
                "recommendation": (
                    "If domain migrations have occurred in the past, continue to review "
                    "sIDHistory periodically to ensure only legitimate migration SIDs remain."
                ),
                "details": [],
            })
            return findings

        critical_accounts = []   # sIDHistory contains a privileged group SID
        warning_accounts = []    # sIDHistory present but not obviously privileged

        for entry in results:
            sam = entry.get("sAMAccountName", "unknown")
            dn = entry.get("distinguishedName", "")
            sid_history = entry.get("sIDHistory", [])
            if isinstance(sid_history, (str, bytes)):
                sid_history = [sid_history]

            has_privileged = False
            priv_sids = []

            for sid in sid_history:
                sid_str = str(sid)
                if _sid_is_privileged(sid_str):
                    has_privileged = True
                    priv_sids.append(sid_str)

            all_sids_str = ", ".join(str(s) for s in sid_history[:10])
            if len(sid_history) > 10:
                all_sids_str += f" ... (+{len(sid_history) - 10} more)"

            if has_privileged:
                critical_accounts.append(
                    f"{sam} — PRIVILEGED SID(s): {', '.join(priv_sids)} | all history: {all_sids_str} | DN: {dn}"
                )
            else:
                warning_accounts.append(
                    f"{sam} — sIDHistory: {all_sids_str} | DN: {dn}"
                )

        # Critical finding: privileged SID injection
        if critical_accounts:
            findings.append({
                "title": f"SID History: {len(critical_accounts)} account(s) with PRIVILEGED injected SIDs",
                "severity": "critical",
                "deduction": 20,
                "description": (
                    "One or more accounts have sIDHistory values that map to privileged groups "
                    "(Domain Admins, Enterprise Admins, BUILTIN\\Administrators, etc.). "
                    "When these accounts authenticate, Windows includes the historical SID in the "
                    "Kerberos PAC, granting the account the same privileges as the privileged group. "
                    "This is a known domain persistence and privilege escalation technique used "
                    "by attackers who have previously compromised the domain."
                ),
                "recommendation": (
                    "1. Investigate whether these SIDs are legitimate migration remnants or malicious injections.\n"
                    "2. Remove sIDHistory from accounts where it is no longer required: "
                    "Set-ADUser <account> -Remove @{sIDHistory='<SID>'}\n"
                    "3. Enable SID filtering on all external trusts.\n"
                    "4. Audit: Get-ADUser -Filter * -Properties sIDHistory | "
                    "Where-Object {$_.sIDHistory} | Select Name, sIDHistory"
                ),
                "details": critical_accounts,
            })

        # High finding: non-privileged sIDHistory
        if warning_accounts:
            findings.append({
                "title": f"SID History: {len(warning_accounts)} account(s) with sIDHistory populated",
                "severity": "high",
                "deduction": 10,
                "description": (
                    "These accounts have sIDHistory attributes populated with non-privileged SIDs. "
                    "While not immediately dangerous, sIDHistory is commonly used for privilege "
                    "escalation and lateral movement. Any SID in history grants the account access "
                    "to resources that were ACL'd to the historical SID. "
                    "Attacker-controlled sIDHistory injection (via DCSync or ndcedit) can be used "
                    "for stealthy persistence."
                ),
                "recommendation": (
                    "Review each account's sIDHistory and remove entries that are no longer "
                    "required for resource access after migration. "
                    "Set-ADUser <account> -Remove @{sIDHistory='<SID>'}"
                ),
                "details": warning_accounts,
            })

        if not findings:
            findings.append({
                "title": "SID History: No issues found",
                "severity": "info",
                "deduction": 0,
                "description": "No accounts with sIDHistory were found.",
                "recommendation": "No action required.",
                "details": [],
            })

    except Exception as e:
        findings.append({
            "title": "SID History: Check encountered an error",
            "severity": "info",
            "deduction": 0,
            "description": f"The check could not complete: {e}",
            "recommendation": "Verify LDAP connectivity and permissions.",
            "details": [str(e)],
        })

    return findings
