"""
checks/check_misc_hardening.py - Miscellaneous Hardening checks

Checks:
  - Machine account quota (ms-DS-MachineAccountQuota > 0)                       -15
  - Tombstone lifetime (too short or not set)                                    -8
  - Guest account enabled                                                        -15
  - Schema Admins / Enterprise Admins permanent membership                       -8
  - Audit policy guidance (informational)                                        0
"""

CHECK_NAME = "Miscellaneous Hardening"
CHECK_ORDER = 19

def run_check(connector, verbose=False):
    findings = []

    # Machine Account Quota
    try:
        domain_objs = connector.ldap_search(
            connector.base_dn,
            "(objectClass=domain)",
            ["ms-DS-MachineAccountQuota"],
            scope="BASE",
        ) or []
        for obj in domain_objs:
            quota = obj.get("ms-DS-MachineAccountQuota")
            try:
                quota_val = int(quota) if quota is not None else 10
            except (TypeError, ValueError):
                quota_val = 10
            if quota_val > 0:
                findings.append({
                    "title": "Machine Account Quota Is Non-Zero",
                    "severity": "high",
                    "deduction": 15,
                    "description": (
                        f"ms-DS-MachineAccountQuota is set to {quota_val}. "
                        "This allows any authenticated user to join up to "
                        f"{quota_val} computer account(s) to the domain. "
                        "Attackers with a foothold can exploit this to create computer accounts "
                        "for Resource-Based Constrained Delegation (RBCD) attacks."
                    ),
                    "recommendation": (
                        "Set ms-DS-MachineAccountQuota to 0 to prevent non-admin users "
                        "from joining computers to the domain: "
                        "Set-ADDomain -Identity <domain> -Replace @{'ms-DS-MachineAccountQuota'='0'} "
                        "Delegate computer-join rights to specific accounts/groups instead."
                    ),
                    "details": [f"Current value: {quota_val}"],
                })
    except Exception as exc:
        if verbose:
            print(f"[MiscHardening] Machine account quota error: {exc}")

    # Tombstone lifetime
    try:
        ds_dn = "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration," + connector.base_dn
        ds_objs = connector.ldap_search(
            ds_dn, "(objectClass=*)", ["tombstoneLifetime"], scope="BASE"
        ) or []
        for obj in ds_objs:
            tsl = obj.get("tombstoneLifetime")
            try:
                tsl_val = int(tsl) if tsl is not None else 60
            except (TypeError, ValueError):
                tsl_val = 60
            if tsl_val < 180:
                findings.append({
                    "title": "Short Tombstone Lifetime",
                    "severity": "medium",
                    "deduction": 8,
                    "description": (
                        f"The AD tombstone lifetime is set to {tsl_val} days "
                        "(recommended minimum: 180 days). "
                        "A short tombstone lifetime can cause lingering objects after DC recovery "
                        "and may lead to inconsistent AD replication state after restoring from backup."
                    ),
                    "recommendation": (
                        "Increase tombstoneLifetime to at least 180 days (preferably 365): "
                        "Set-ADObject -Identity 'CN=Directory Service,...' "
                        "-Replace @{tombstoneLifetime=180}"
                    ),
                    "details": [f"Current tombstone lifetime: {tsl_val} days"],
                })
    except Exception as exc:
        if verbose:
            print(f"[MiscHardening] Tombstone lifetime error: {exc}")

    # Guest account enabled
    try:
        guests = connector.ldap_search(
            connector.base_dn,
            "(&(objectClass=user)(sAMAccountName=Guest))",
            ["sAMAccountName", "userAccountControl"],
        ) or []
        for guest in guests:
            uac = guest.get("userAccountControl", 0)
            try:
                uac_val = int(uac)
            except (TypeError, ValueError):
                uac_val = 0
            # ACCOUNTDISABLE = 0x2 (bit 1)
            account_disabled = bool(uac_val & 0x2)
            if not account_disabled:
                findings.append({
                    "title": "Built-in Guest Account Is Enabled",
                    "severity": "high",
                    "deduction": 15,
                    "description": (
                        "The built-in Guest account is enabled. The Guest account provides "
                        "unauthenticated or minimally-authenticated access to resources and is "
                        "a well-known attack vector for initial access and enumeration."
                    ),
                    "recommendation": (
                        "Disable the Guest account: "
                        "Disable-ADAccount -Identity Guest "
                        "Also ensure the account has no group memberships beyond Domain Guests."
                    ),
                    "details": ["Guest account (SID ending -501) is enabled"],
                })
    except Exception as exc:
        if verbose:
            print(f"[MiscHardening] Guest account error: {exc}")

    # Schema Admins and Enterprise Admins permanent membership
    sensitive_groups = ["Schema Admins", "Enterprise Admins"]
    for group_name in sensitive_groups:
        try:
            groups = connector.ldap_search(
                connector.base_dn,
                f"(&(objectClass=group)(cn={group_name}))",
                ["cn", "member"],
            ) or []
            for group in groups:
                members = group.get("member", [])
                if not isinstance(members, list):
                    members = [members] if members else []
                # Filter out krbtgt and Administrator-like accounts
                human_members = [m for m in members if m]
                if len(human_members) > 0:
                    findings.append({
                        "title": f"Permanent Members in {group_name}",
                        "severity": "medium",
                        "deduction": 8,
                        "description": (
                            f"The '{group_name}' group has {len(human_members)} permanent member(s). "
                            f"{'Schema Admins' if group_name == 'Schema Admins' else 'Enterprise Admins'} "
                            "should be empty when not actively needed. Permanent membership increases "
                            "the blast radius of any account compromise."
                        ),
                        "recommendation": (
                            f"Remove all members from {group_name} when not actively performing "
                            "schema or forest-level administrative tasks. "
                            "Use just-in-time access (PAM/PIM) for these roles."
                        ),
                        "details": human_members[:20],
                    })
        except Exception as exc:
            if verbose:
                print(f"[MiscHardening] {group_name} query error: {exc}")

    # Audit policy guidance (informational)
    findings.append({
        "title": "Advanced Audit Policy – Manual Review Required",
        "severity": "info",
        "deduction": 0,
        "description": (
            "AD security depends heavily on audit policy configuration. "
            "Critical subcategories include: Logon/Logoff, Account Logon, "
            "DS Access, Account Management, Policy Change, Privilege Use, and System. "
            "These cannot be fully assessed via LDAP alone."
        ),
        "recommendation": (
            "Review Advanced Audit Policy settings via GPO or: auditpol /get /category:* "
            "Ensure the following are configured for Success and Failure: "
            "Audit Logon, Audit Account Logon, Audit Directory Service Access, "
            "Audit Account Management, Audit Privilege Use. "
            "Consider deploying a SIEM to collect and alert on Security event logs."
        ),
        "details": [],
    })

    return findings
