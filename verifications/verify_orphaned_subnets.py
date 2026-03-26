"""
verifications/verify_orphaned_subnets.py
Manual Verification and Remediation data for ADScan findings matching: Orphaned AD Subnets
"""

MATCH_KEYS = ["orphaned ad subnets:"]

TOOLS = [
    {
        "tool": "PowerShell",
        "icon": "ps",
        "desc": "List all subnets defined in AD Sites and Services and their associated site.",
        "code": "Get-ADReplicationSubnet -Filter * -Properties Site \\`\n    | Select-Object Name,Site,Location,Description \\`\n    | Sort-Object Site",
        "confirm": "Subnets where the <strong>Site</strong> field is empty or null are orphaned — they are not associated with any AD site.",
    },
    {
        "tool": "ADSI Edit",
        "icon": "cmd",
        "desc": "View subnets manually via ADSI Edit.",
        "code": "# Open adsiedit.msc\n# Connect to: CN=Configuration,DC=<domain>,DC=<tld>\n# Navigate to: CN=Subnets,CN=Sites,CN=Configuration,...\n# Review each subnet for a linked site object",
        "confirm": "Subnets without a <strong>siteObject</strong> attribute value are orphaned.",
    },
]

REMEDIATION = {
    "title": "Assign orphaned subnets to sites or remove them",
    "steps": [
        {
            "text": "Open <strong>Active Directory Sites and Services</strong> (dssite.msc), expand <em>Sites &rarr; Subnets</em>, and review each listed subnet.",
        },
        {
            "text": "For each orphaned subnet, right-click it and select <strong>Properties</strong>. Set the <strong>Site</strong> field to the appropriate AD site.",
        },
        {
            "text": "If the subnet no longer corresponds to an active network range, right-click and delete it.",
        },
        {
            "text": "Maintaining accurate subnet-to-site mappings ensures clients authenticate against the nearest DC, reducing authentication latency and cross-site replication traffic.",
        },
    ],
}


REFERENCES = [
    {"title": "AD Sites and Subnets - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/understanding-active-directory-site-topology", "tag": "vendor"},
    {"title": "Managing AD Subnets - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/assigning-domain-names", "tag": "vendor"},
    {"title": "MITRE ATT&CK: Network Topology Discovery (T1016)", "url": "https://attack.mitre.org/techniques/T1016/", "tag": "attack"},
    {"title": "AD Recon - Network Topology Enumeration", "url": "https://github.com/sense-of-security/ADRecon", "tag": "tool"},
    {"title": "BloodHound - AD Sites and Subnet Mapping", "url": "https://github.com/BloodHoundAD/BloodHound", "tag": "tool"},
    {"title": "AD Sites Design Best Practices - Microsoft", "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/site-topology-owner-role", "tag": "defense"},
    {"title": "Subnet Audit and Cleanup - AD Tiering Model", "url": "https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model", "tag": "defense"},
    {"title": "Orphaned Subnets and DC Locator Failures - TechNet", "url": "https://social.technet.microsoft.com/wiki/contents/articles/24960.active-directory-sites-and-services.aspx", "tag": "research"},
]
