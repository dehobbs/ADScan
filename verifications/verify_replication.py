"""
verifications/verify_replication.py
Manual verification, remediation, and references for AD replication health findings.
"""

MATCH_KEYS = [
    "replication",
    "replsum",
    "replication failure",
    "replication lag",
]

TOOLS = [
    {
        "tool": "cmd (repadmin)",
        "icon": "cmd",
        "desc": "Check replication summary and identify failures across all DCs.",
        "code": (            "# Summary of all DC replication health:\n"            "repadmin /replsummary\n"            "\n"            "# Show replication failures:\n"            "repadmin /showrepl\n"            "\n"            "# Show per-DC replication queue:\n"            "repadmin /queue"
        ),
        "confirm": "Any Fails > 0 or Last Success older than expected replication interval indicates a replication problem.",
    },
    {
        "tool": "PowerShell (AD Module)",
        "icon": "ps",
        "desc": "Get replication status for all domain controllers.",
        "code": (            "Get-ADReplicationPartnerMetadata -Target * -Scope Domain |\n"            "  Select-Object Server, Partner, LastReplicationSuccess,\n"            "    LastReplicationResult, ConsecutiveReplicationFailures |\n"            "  Sort-Object ConsecutiveReplicationFailures -Descending |\n"            "  Format-Table -AutoSize"
        ),
        "confirm": "ConsecutiveReplicationFailures > 0 confirms an active replication problem. LastReplicationResult 0 = success.",
    },
]

REMEDIATION = {
    "title": "Resolve AD replication failures and restore healthy replication topology",
    "steps": [
        {
            "text": "Run repadmin /replsummary and identify which DCs are failing replication.",
        },
        {
            "text": "For transient errors, force replication on a specific DC:",
            "code": "repadmin /syncall /Ade <DC_hostname>",
        },
        {
            "text": "For persistent failures, check Event Viewer on the failing DC (Directory Service log, Event ID 1311, 1566, 2089).",
        },
        {
            "text": "Run the AD Replication diagnostic tool and act on identified issues:",
            "code": "dcdiag /test:replications /v",
        },
        {
            "text": "If a DC has been down longer than the tombstone lifetime (default 180 days), it must be forcibly demoted and rejoined.",
        },
    ],
}

REFERENCES = [
    {
        "title": "Microsoft — Troubleshooting Active Directory Replication Problems",
        "url": "https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/troubleshoot-active-directory-replication-problems",
        "tag": "vendor",
    },
    {
        "title": "Microsoft — repadmin command reference",
        "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc770963(v=ws.11)",
        "tag": "vendor",
    },
    {
        "title": "Microsoft — Get-ADReplicationPartnerMetadata",
        "url": "https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adreplicationpartnermetadata",
        "tag": "vendor",
    },
]
