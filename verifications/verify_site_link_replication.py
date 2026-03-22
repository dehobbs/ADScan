"""
verifications/verify_site_link_replication.py
Manual Verification and Remediation data for ADScan findings matching: Site Link Replication
"""

MATCH_KEYS = ["site link replication"]

TOOLS = [
    {
        "tool": "PowerShell",
        "icon": "ps",
        "desc": "List all site links and their replication intervals.",
        "code": "Get-ADReplicationSiteLink -Filter * -Properties ReplInterval,Cost,SitesIncluded \`\n    | Select-Object Name,ReplInterval,Cost,SitesIncluded \`\n    | Sort-Object ReplInterval -Descending",
        "confirm": "Site links with <strong>ReplInterval</strong> above <strong>180 minutes</strong> (3 hours) are flagged. The default is 180 minutes; best practice is 15–60 minutes for most environments.",
    },
    {
        "tool": "ADSI Edit",
        "icon": "cmd",
        "desc": "View site link replication settings via Active Directory Sites and Services.",
        "code": "# Open dssite.msc\n# Expand Sites -> Inter-Site Transports -> IP\n# Right-click each site link -> Properties\n# Review Replicate every: (minutes)",
        "confirm": "Values above 180 minutes confirm the finding.",
    },
]

REMEDIATION = {
    "title": "Reduce site link replication intervals",
    "steps": [
        {
            "text": "Reduce the replication interval on affected site links to an appropriate value for your network bandwidth. 15 minutes is recommended for high-bandwidth links; 60 minutes for lower-bandwidth WAN links:",
            "code": "Set-ADReplicationSiteLink -Identity \"<SiteLinkName>\" -ReplicationFrequencyInMinutes 15",
        },
        {
            "text": "Also verify the site link <strong>Schedule</strong> is not restricting replication to certain hours, which compounds delay. In <strong>dssite.msc</strong>, right-click the site link &rarr; Properties &rarr; Change Schedule.",
        },
        {
            "text": "Ensure <strong>ISTG (Inter-Site Topology Generator)</strong> is functioning on each site by checking the NTDS Settings object and replication health:",
            "code": "repadmin /showrepl\nrepadmin /replsummary",
        },
    ],
}
