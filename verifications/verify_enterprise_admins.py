"""
verifications/verify_enterprise_admins.py
Manual Verification and Remediation data for ADScan findings matching: Enterprise Admins
"""

MATCH_KEYS = ["enterprise admins"]

TOOLS = [
    {
        "tool": "PowerShell",
        "icon": "ps",
        "desc": "List current members of the Enterprise Admins group.",
        "code": "Get-ADGroupMember -Identity \"Enterprise Admins\" -Recursive \`\n    | Select-Object Name,SamAccountName,objectClass",
        "confirm": "Enterprise Admins should only contain the built-in Administrator account (or be empty). Any additional enabled user accounts confirm the finding.",
    },
]

REMEDIATION = {
    "title": "Remove permanent members from Enterprise Admins",
    "steps": [
        {
            "text": "Enterprise Admins should be <strong>empty</strong> under normal operations. Membership is only required for forest-level operations (e.g. adding/removing domains, raising forest functional level).",
        },
        {
            "text": "Remove all current non-Administrator members:",
            "code": "Get-ADGroupMember -Identity \"Enterprise Admins\" \`\n    | Where-Object { $_.SamAccountName -ne \"Administrator\" } \`\n    | ForEach-Object {\n        Remove-ADGroupMember -Identity \"Enterprise Admins\" -Members $_ -Confirm:$false\n    }",
        },
        {
            "text": "Grant Enterprise Admins membership only for the duration of a specific forest-level change, then immediately remove and verify.",
        },
        {
            "text": "Enable alerting on membership changes via <strong>Event ID 4728</strong> in the Security event log on the forest root DC.",
        },
    ],
}
