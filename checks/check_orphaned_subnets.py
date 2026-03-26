CHECK_NAME = "Orphaned AD Subnets"
CHECK_ORDER = 70
CHECK_CATEGORY = ["Network Hygiene"]
CHECK_WEIGHT   = 0   # info-only check, no deduction possible

def run_check(connector, verbose=False):
    findings = []

    try:
        config_dn = "CN=Configuration," + connector.base_dn
        subnets_dn = "CN=Subnets,CN=Sites," + config_dn

        # Query all subnet objects
        subnet_results = connector.ldap_search(
            search_filter="(objectClass=subnet)",
            search_base=subnets_dn,
            attributes=["cn", "distinguishedName", "siteObject", "description", "location"],
        )

        if not subnet_results:
            findings.append({
                "title": "Orphaned AD Subnets: No subnets defined",
                "severity": "info",
                "deduction": 0,
                "description": (
                    "No subnet objects were found in CN=Subnets,CN=Sites,CN=Configuration. "
                    "If AD Sites and Services has not been configured, clients will use "
                    "any available DC regardless of network proximity."
                ),
                "recommendation": (
                    "Define subnets in AD Sites and Services and assign them to appropriate "
                    "AD Sites to ensure clients authenticate to the nearest DC. "
                    "This reduces WAN authentication traffic and improves logon performance."
                ),
                "details": [],
            })
            return findings

        orphaned = []    # No siteObject link
        assigned = []    # Has siteObject link

        for entry in subnet_results:
            cn = entry.get("cn", "unknown")
            site_obj = entry.get("siteObject")
            desc = entry.get("description", "") or ""
            location = entry.get("location", "") or ""

            label = cn
            if desc:
                label += f" — description: {desc}"
            if location:
                label += f" — location: {location}"

            if not site_obj:
                orphaned.append(label)
            else:
                site_name = site_obj.split(",")[0].replace("CN=", "") if site_obj else "unknown"
                assigned.append(f"{cn} -> Site: {site_name}")

        total = len(subnet_results)
        orphaned_count = len(orphaned)
        orphaned_pct = (orphaned_count / total * 100) if total > 0 else 0.0

        if orphaned:
            severity = "high" if orphaned_pct >= 50 else "medium" if orphaned_pct >= 20 else "low"
            deduction = 10 if orphaned_pct >= 50 else 5 if orphaned_pct >= 20 else 3

            findings.append({
                "title": (
                    f"Orphaned AD Subnets: {orphaned_count} of {total} subnets "
                    f"({orphaned_pct:.0f}%) have no site assignment"
                ),
                "severity": severity,
                "deduction": deduction,
                "description": (
                    f"{orphaned_count} subnet object(s) in AD Sites and Services have no "
                    "siteObject assignment. Clients whose IP addresses fall within these subnets "
                    "will not be correctly mapped to an AD Site. As a result:\n"
                    "- Clients may authenticate to a geographically distant DC over a WAN link\n"
                    "- DFS namespace referrals may point to incorrect servers\n"
                    "- Group Policy may apply slowly or inconsistently\n"
                    "- Kerberos authentication latency increases"
                ),
                "recommendation": (
                    "In AD Sites and Services (dssite.msc), assign each orphaned subnet to the "
                    "appropriate site. PowerShell: "
                    "Set-ADReplicationSubnet -Identity '<subnet>' -Site '<site-name>'"
                ),
                "details": orphaned,
            })

            # Informational summary of assigned subnets
            if assigned and verbose:
                findings.append({
                    "title": f"AD Subnets: {len(assigned)} assigned subnet(s)",
                    "severity": "info",
                    "deduction": 0,
                    "description": "These subnets are correctly assigned to AD Sites.",
                    "recommendation": "No action required.",
                    "details": assigned[:50],
                })
        else:
            findings.append({
                "title": f"Orphaned AD Subnets: All {total} subnet(s) assigned to sites",
                "severity": "info",
                "deduction": 0,
                "description": (
                    f"All {total} subnet(s) in AD Sites and Services have a site assignment. "
                    "Clients will be correctly directed to their nearest DC."
                ),
                "recommendation": "No action required. Continue to maintain subnet assignments as the network evolves.",
                "details": [],
            })

    except Exception as e:
        findings.append({
            "title": "Orphaned AD Subnets: Check encountered an error",
            "severity": "info",
            "deduction": 0,
            "description": f"The check could not complete: {e}",
            "recommendation": "Verify LDAP connectivity and permissions to CN=Configuration.",
            "details": [str(e)],
        })

    return findings
