"""
checks/check_dns_infrastructure.py - DNS & Infrastructure Check

Checks:
  1. Wildcard DNS records in AD-integrated DNS zones
  2. LLMNR / NetBIOS-NS poisoning guidance
  3. AD Sites and Services: subnet enumeration, missing subnets

Risk Deductions:
  High   (-15): Wildcard DNS records in AD-integrated zones
  Medium  (-8): LLMNR/NetBIOS-NS guidance
  Low     (-5): No subnets defined in AD Sites and Services
"""

CHECK_NAME = "DNS & Infrastructure"
CHECK_ORDER = 12
CHECK_CATEGORY = ["Network Hygiene"]


def _get_str(entry, attr, default=""):
    try:
        v = entry.get(attr)
        return str(v) if v else default
    except Exception:
        return default


def run_check(connector, verbose=False):
    findings = []
    log = connector.log

    config_dn = "CN=Configuration," + connector.base_dn

    # 1. Wildcard DNS records
    dns_base = f"DC=DomainDnsZones,{connector.base_dn}"
    wildcard_records = connector.ldap_search(
        search_filter="(&(objectClass=dnsNode)(dc=*))",
        attributes=["dc", "distinguishedName"],
        search_base=dns_base,
    ) or []

    wildcards_found = [
        _get_str(e, "dc") + " | " + _get_str(e, "distinguishedName")
        for e in wildcard_records
        if _get_str(e, "dc").strip() == "*"
    ]

    log.debug("  Wildcard DNS records: %d", len(wildcards_found))

    if wildcards_found:
        findings.append({
            "title": "Wildcard DNS Records Found in AD-Integrated DNS",
            "severity": "high",
            "deduction": 15,
            "description": (
                f"{len(wildcards_found)} wildcard DNS record(s) found. "
                "Wildcard records resolve any unmatched hostname in the zone to a single IP. "
                "Attackers exploit this for NTLM relay -- any typo or fabricated hostname "
                "resolves to the wildcard target. Also used as a persistence mechanism."
            ),
            "recommendation": (
                "Remove wildcard DNS records unless explicitly required. "
                "Review what service requires the wildcard and use specific records instead. "
                "Monitor AD-integrated DNS for unauthorized changes."
            ),
            "details": wildcards_found,
        })

    # 2. LLMNR / NetBIOS guidance
    findings.append({
        "title": "Verify LLMNR and NetBIOS-NS Are Disabled",
        "severity": "medium",
        "deduction": 8,
        "description": (
            "LLMNR and NetBIOS-NS broadcast name resolution requests on the local segment "
            "and are trivially abused by Responder to capture NTLMv2 hashes from any domain user. "
            "These settings cannot be verified passively via LDAP."
        ),
        "recommendation": (
            "Disable LLMNR via GPO: Computer Config > Admin Templates > Network > DNS Client > "
            "Turn off multicast name resolution = Enabled. "
            "Disable NetBIOS via DHCP option 001 or WMI (NetbiosOptions = 2 on each adapter). "
            "Deploy honeypot/canary for LLMNR/NBT-NS to detect Responder usage."
        ),
        "details": [
            "LLMNR GPO: Computer Config > Administrative Templates > Network > DNS Client",
            "NetBIOS: Set via DHCP option 001 (002=enable, 003=DHCP, 002=disable) "
            "or registry NetbiosOptions = 2 under "
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\"
            "Parameters\\Interfaces\\<adapter-GUID>",
        ],
    })

    # 3. AD Sites and Services subnets
    sites_dn   = f"CN=Sites,{config_dn}"
    subnets_dn = f"CN=Subnets,{sites_dn}"

    subnet_entries = connector.ldap_search(
        search_filter="(objectClass=subnet)",
        attributes=["cn", "siteObject"],
        search_base=subnets_dn,
    ) or []

    site_entries = connector.ldap_search(
        search_filter="(objectClass=site)",
        attributes=["cn"],
        search_base=sites_dn,
    ) or []

    log.debug("  AD Sites  : %d", len(site_entries))
    log.debug("  AD Subnets: %d", len(subnet_entries))

    unassigned = [_get_str(e, "cn") for e in subnet_entries if not _get_str(e, "siteObject")]

    if not subnet_entries and site_entries:
        findings.append({
            "title": "No Subnets Defined in AD Sites and Services",
            "severity": "low",
            "deduction": 5,
            "description": (
                f"{len(site_entries)} site(s) configured but no subnets defined. "
                "Clients cannot locate their nearest DC efficiently."
            ),
            "recommendation": (
                "Define subnets: "
                "New-ADReplicationSubnet -Name '192.168.1.0/24' -Site 'Default-First-Site-Name'"
            ),
            "details": [f"Sites: {len(site_entries)}", "Subnets: 0"],
        })

    if unassigned:
        findings.append({
            "title": f"Subnets Not Assigned to a Site ({len(unassigned)})",
            "severity": "low",
            "deduction": 5,
            "description": (
                f"{len(unassigned)} subnet(s) not assigned to any AD site. "
                "Clients may authenticate to distant DCs."
            ),
            "recommendation": "Assign all subnets to appropriate AD sites.",
            "details": [f"Unassigned: {s}" for s in unassigned[:30]],
        })

    if subnet_entries:
        findings.append({
            "title": "AD Sites and Services Inventory",
            "severity": "info",
            "deduction": 0,
            "description": (
                f"{len(site_entries)} site(s) and {len(subnet_entries)} subnet(s) defined."
            ),
            "recommendation": "Review periodically for accuracy.",
            "details": (
                [f"Sites: {len(site_entries)}", f"Subnets: {len(subnet_entries)}",
                 f"Unassigned: {len(unassigned)}"] +
                [_get_str(e, "cn") for e in subnet_entries[:30]]
            ),
        })

    return findings
