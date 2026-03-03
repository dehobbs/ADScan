CHECK_NAME = "Foreign Security Principals in Privileged Groups"
CHECK_ORDER = 67
CHECK_CATEGORY = "Cross-Domain Privilege Exposure"

# Sensitive local group names to check for FSP membership
SENSITIVE_GROUPS = [
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Account Operators",
    "Backup Operators",
    "Server Operators",
    "Print Operators",
    "Replicators",
    "Group Policy Creator Owners",
    "Remote Desktop Users",
    "Distributed COM Users",
    "Network Configuration Operators",
    "Cryptographic Operators",
    "Event Log Readers",
    "Certificate Service DCOM Access",
]


def run_check(connector, verbose=False):
    findings = []

    try:
        # Step 1: Enumerate all Foreign Security Principals
        fsp_dn = "CN=ForeignSecurityPrincipals," + connector.base_dn
        fsp_results = connector.ldap_search(
            search_filter="(objectClass=foreignSecurityPrincipal)",
            search_base=fsp_dn,
            attributes=[
                "cn",
                "distinguishedName",
                "memberOf",
                "objectSid",
            ],
        )

        if not fsp_results:
            findings.append({
                "title": "Foreign Security Principals: None found",
                "severity": "info",
                "deduction": 0,
                "description": (
                    "No Foreign Security Principal objects were found in "
                    "CN=ForeignSecurityPrincipals. This is expected if the domain has no "
                    "external trusts or cross-forest group memberships."
                ),
                "recommendation": "No action required.",
                "details": [],
            })
            return findings

        privileged_fsps = []
        non_privileged_fsps = []

        for entry in fsp_results:
            attrs = entry.get("attributes", {}) if isinstance(entry, dict) else {}
            cn = attrs.get("cn", "unknown")
            dn = attrs.get("distinguishedName", "")
            member_of = attrs.get("memberOf") or []
            if isinstance(member_of, str):
                member_of = [member_of]

            if not member_of:
                # FSP not in any group — skip
                continue

            for group_dn in member_of:
                group_dn_lower = group_dn.lower()
                for sensitive in SENSITIVE_GROUPS:
                    if sensitive.lower() in group_dn_lower:
                        privileged_fsps.append(
                            f"FSP: {cn} -> Group: {group_dn}"
                        )
                        break
                else:
                    non_privileged_fsps.append(
                        f"FSP: {cn} -> Group: {group_dn}"
                    )

        if privileged_fsps:
            findings.append({
                "title": (
                    f"Foreign Security Principals in Privileged Groups: "
                    f"{len(privileged_fsps)} membership(s) found"
                ),
                "severity": "critical",
                "deduction": 20,
                "description": (
                    "Foreign Security Principals (FSPs) from trusted external domains are members "
                    "of sensitive local groups. FSPs represent accounts from trusted domains. "
                    "If the trusted domain is compromised, or if the trust relationship is "
                    "misconfigured, these memberships grant the foreign domain privileged access "
                    "to this domain. This is a common attack path in forest compromise scenarios."
                ),
                "recommendation": (
                    "1. Review all FSPs in privileged groups and verify they are required.\n"
                    "2. Remove unnecessary FSPs from sensitive groups.\n"
                    "3. Ensure SID filtering is enabled on all external trusts.\n"
                    "4. Audit: Get-ADGroup -Identity 'Domain Admins' -Properties Members | "
                    "Select -ExpandProperty Members | "
                    "Where-Object {$_ -like 'CN=S-1-5*'}"
                ),
                "details": privileged_fsps,
            })

        if non_privileged_fsps:
            findings.append({
                "title": f"Foreign Security Principals in Standard Groups: {len(non_privileged_fsps)} membership(s)",
                "severity": "medium",
                "deduction": 5,
                "description": (
                    "Foreign Security Principals are members of non-privileged groups. "
                    "While not immediately critical, this indicates cross-domain/forest group "
                    "memberships that should be reviewed to ensure they are authorised and "
                    "the source domains are still trusted and healthy."
                ),
                "recommendation": (
                    "Review all FSP group memberships and remove any that are no longer "
                    "required. Ensure corresponding trust relationships are still valid."
                ),
                "details": non_privileged_fsps[:50],
            })

        if not privileged_fsps and not non_privileged_fsps:
            findings.append({
                "title": "Foreign Security Principals: No group memberships found",
                "severity": "info",
                "deduction": 0,
                "description": (
                    f"{len(fsp_results)} FSP objects exist but none are members of any groups. "
                    "This is generally expected — FSPs are often created automatically for "
                    "trust relationships and may not hold direct group memberships."
                ),
                "recommendation": "No action required. Periodically review FSP inventory.",
                "details": [
                    f"FSP: {e.get('attributes', {}).get('cn', 'unknown')} | "
                    f"DN: {e.get('attributes', {}).get('distinguishedName', '')}"
                    for e in fsp_results[:20]
                ],
            })

    except Exception as e:
        findings.append({
            "title": "Foreign Security Principals: Check encountered an error",
            "severity": "info",
            "deduction": 0,
            "description": f"The check could not complete: {e}",
            "recommendation": "Verify LDAP connectivity and permissions.",
            "details": [str(e)],
        })

    return findings
