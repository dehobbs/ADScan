"""
checks/check_service_accounts.py - Service Account hygiene checks

Checks:
  - gMSA adoption: accounts of objectClass msDS-GroupManagedServiceAccount        info
  - Regular user accounts used as service accounts (SPN on userAccount)          -10
  - Service accounts with adminCount=1                                           -15
"""

CHECK_NAME = "Service Accounts"
CHECK_ORDER = 18
CHECK_CATEGORY = ["Privileged Accounts"]

def run_check(connector, verbose=False):
    findings = []
    log = connector.log

    # gMSA adoption
    try:
        gmsas = connector.ldap_search(
            connector.base_dn,
            "(objectClass=msDS-GroupManagedServiceAccount)",
            ["cn", "sAMAccountName"],
        ) or []
        gmsa_count = len(gmsas)
        log.debug("[ServiceAccounts] gMSAs found: %d", gmsa_count)
    except Exception as exc:
        log.warning("[ServiceAccounts] gMSA query error: %s", exc)
        gmsa_count = 0

    # Regular user accounts used as service accounts (SPN set, objectClass=user, not computer)
    try:
        user_spn_accounts = connector.ldap_search(
            connector.base_dn,
            "(&(objectClass=user)(!(objectClass=computer))(servicePrincipalName=*))",
            ["cn", "sAMAccountName", "servicePrincipalName", "adminCount",
             "userAccountControl", "pwdLastSet"],
        ) or []
    except Exception as exc:
        log.warning("[ServiceAccounts] SPN user query error: %s", exc)
        user_spn_accounts = []

    # Filter out krbtgt and typical system accounts
    excluded = {"krbtgt"}
    service_users = [
        u for u in user_spn_accounts
        if u.get("sAMAccountName", "").lower() not in excluded
    ]

    if service_users and gmsa_count == 0:
        names = [u.get("sAMAccountName", u.get("cn", "Unknown")) for u in service_users]
        findings.append({
            "title": "User Accounts Used as Service Accounts (No gMSA Adoption)",
            "severity": "medium",
            "deduction": 10,
            "description": (
                f"{len(service_users)} regular user account(s) have Service Principal Names (SPNs) "
                "set, indicating they are used as service accounts. No Group Managed Service Accounts "
                "(gMSAs) were found. User-based service accounts have manually managed passwords, "
                "increasing the risk of weak or stale credentials and Kerberoasting exposure."
            ),
            "recommendation": (
                "Migrate service accounts to Group Managed Service Accounts (gMSAs) where possible. "
                "gMSAs have automatically rotated 240-bit passwords and are immune to Kerberoasting. "
                "New-ADServiceAccount -Name <name> -DNSHostName <fqdn> -PrincipalsAllowedToRetrieveManagedPassword <group>"
            ),
            "details": names,
        })
    elif service_users and gmsa_count > 0:
        names = [u.get("sAMAccountName", u.get("cn", "Unknown")) for u in service_users]
        findings.append({
            "title": "Mix of User-Based and gMSA Service Accounts",
            "severity": "low",
            "deduction": 5,
            "description": (
                f"{len(service_users)} user account(s) with SPNs exist alongside "
                f"{gmsa_count} gMSA(s). Legacy user-based service accounts should be migrated to gMSAs."
            ),
            "recommendation": (
                "Continue migrating remaining user-based service accounts to gMSAs. "
                "Prioritise accounts with high privileges or those exposed to Kerberoasting."
            ),
            "details": names,
        })

    if gmsa_count > 0:
        findings.append({
            "title": "Group Managed Service Accounts (gMSAs) In Use",
            "severity": "info",
            "deduction": 0,
            "description": (
                f"{gmsa_count} Group Managed Service Account(s) (gMSAs) were found. "
                "gMSAs provide automatic password management and reduce Kerberoasting risk."
            ),
            "recommendation": "Continue expanding gMSA adoption to all service workloads.",
            "details": [u.get("sAMAccountName", u.get("cn", "Unknown")) for u in gmsas],
        })

    # Service accounts with adminCount=1 (have been in a privileged group)
    try:
        admin_service_accounts = [
            u for u in service_users
            if str(u.get("adminCount", "0")) == "1"
        ]
    except Exception:
        admin_service_accounts = []

    if admin_service_accounts:
        names = [u.get("sAMAccountName", u.get("cn", "Unknown")) for u in admin_service_accounts]
        findings.append({
            "title": "Service Accounts With adminCount=1",
            "severity": "high",
            "deduction": 15,
            "description": (
                f"{len(admin_service_accounts)} service account(s) have adminCount=1, meaning "
                "they were previously (or currently are) members of a privileged group. "
                "These accounts have SDProp protection applied and are high-value Kerberoasting targets "
                "if they have SPNs with weak or old passwords."
            ),
            "recommendation": (
                "Review membership of privileged groups for these service accounts. "
                "Remove from privileged groups if not required. "
                "Ensure passwords are strong (25+ characters) or migrate to gMSAs. "
                "Monitor these accounts closely for unusual authentication patterns."
            ),
            "details": names,
        })

    return findings
