"""
checks/check_replication.py - Replication Health checks

Checks:
  - Site count and site link replication intervals                               -5
  - nTDSDSA objects (DC count per site)                                          -5
  - Excessive replication interval (>60 min) on any site link                   -10
  - Sites with no DCs (empty sites)                                              -5
"""

CHECK_NAME = "Replication Health"
CHECK_ORDER = 17
CHECK_CATEGORY = ["Domain Hygiene"]
CHECK_WEIGHT   = 10   # max deduction at stake for this check module

def run_check(connector, verbose=False):
    findings = []
    log = connector.log

    config_dn = "CN=Configuration," + connector.base_dn
    sites_dn = "CN=Sites," + config_dn

    # Gather sites
    try:
        sites = connector.ldap_search(
            sites_dn,
            "(objectClass=site)",
            ["cn", "distinguishedName"],
            scope="ONELEVEL",
        ) or []
    except Exception as exc:
        log.warning("[Replication] Sites LDAP error: %s", exc)
        sites = []

    site_count = len(sites)

    # Gather site links
    site_links_dn = "CN=IP,CN=Inter-Site Transports," + sites_dn
    try:
        site_links = connector.ldap_search(
            site_links_dn,
            "(objectClass=siteLink)",
            ["cn", "replInterval", "siteList"],
        ) or []
    except Exception as exc:
        log.warning("[Replication] Site links LDAP error: %s", exc)
        site_links = []

    # Check for excessive replication intervals
    high_interval_links = []
    for link in site_links:
        try:
            interval = int(link.get("replInterval", 180))
        except (TypeError, ValueError):
            interval = 180
        if interval > 60:
            high_interval_links.append(f"{link.get('cn', 'Unknown')} ({interval} min)")

    if high_interval_links:
        findings.append({
            "title": "Excessive Site Link Replication Intervals",
            "severity": "medium",
            "deduction": 10,
            "description": (
                f"{len(high_interval_links)} site link(s) have replication intervals greater "
                "than 60 minutes. This delays propagation of security-sensitive changes such as "
                "password resets, account lockouts, and group membership changes."
            ),
            "recommendation": (
                "Review and reduce replication intervals for critical site links. "
                "The default is 180 minutes; consider setting 15-30 minutes for well-connected sites. "
                "Use AD Sites and Services or: Set-ADReplicationSiteLink -Identity <link> -ReplicationFrequencyInMinutes 30"
            ),
            "details": high_interval_links,
        })

    # Count nTDSDSA objects (one per DC)
    try:
        ntdsdsa_objects = connector.ldap_search(
            config_dn,
            "(objectClass=nTDSDSA)",
            ["cn", "distinguishedName"],
        ) or []
        dc_count = len(ntdsdsa_objects)
    except Exception as exc:
        log.warning("[Replication] nTDSDSA LDAP error: %s", exc)
        dc_count = 0
        ntdsdsa_objects = []

    log.debug("[Replication] Sites: %d, DCs: %d, Site links: %d", site_count, dc_count, len(site_links))

    # Report site topology summary as informational
    if site_count > 1:
        findings.append({
            "title": "Multi-Site AD Topology Detected",
            "severity": "info",
            "deduction": 0,
            "description": (
                f"The environment has {site_count} AD site(s), {dc_count} domain controller(s) "
                f"(nTDSDSA objects), and {len(site_links)} site link(s). "
                "A healthy multi-site AD requires well-configured replication topology."
            ),
            "recommendation": (
                "Regularly run: repadmin /showrepl and repadmin /replsummary "
                "to validate replication health. Address any replication failures promptly."
            ),
            "details": [f"Sites: {site_count}", f"DCs: {dc_count}", f"Site links: {len(site_links)}"],
        })

    # Check for sites with no DCs (empty sites can indicate stale configuration)
    if site_count > 1 and dc_count > 0:
        dcs_per_site = {}
        for ntds in ntdsdsa_objects:
            dn = ntds.get("distinguishedName", "")
            # DN format: CN=NTDS Settings,CN=<dcname>,CN=Servers,CN=<site>,CN=Sites,...
            parts = dn.split(",")
            site_part = ""
            for i, p in enumerate(parts):
                if p.upper().startswith("CN=SITES") or (i > 0 and parts[i-1].upper() == "CN=SERVERS"):
                    pass
                if "CN=Sites" in dn:
                    idx = dn.find("CN=Sites")
                    after = dn[idx:]
                    site_cn = after.split(",")[1] if "," in after else ""
                    site_part = site_cn
                    break
            dcs_per_site[site_part] = dcs_per_site.get(site_part, 0) + 1

        if site_count > len(dcs_per_site):
            empty_count = site_count - len(dcs_per_site)
            findings.append({
                "title": "AD Sites With No Domain Controllers",
                "severity": "low",
                "deduction": 5,
                "description": (
                    f"Approximately {empty_count} AD site(s) appear to have no domain controllers. "
                    "Empty sites may indicate stale site configuration or improper DC placement."
                ),
                "recommendation": (
                    "Review AD Sites and Services for sites without DCs. "
                    "Remove stale sites or assign DCs appropriately to ensure "
                    "clients authenticate to the nearest DC."
                ),
                "details": [],
            })

    return findings
