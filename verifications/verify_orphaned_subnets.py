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
        "code": "Get-ADReplicationSubnet -Filter * -Properties Site \`\n    | Select-Object Name,Site,Location,Description \`\n    | Sort-Object Site",
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
