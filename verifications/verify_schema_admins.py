"""
verifications/verify_schema_admins.py
Manual Verification and Remediation data for ADScan findings matching: Schema Admins
"""

MATCH_KEYS = ["schema admins"]

TOOLS = [
    {
        "tool": "PowerShell",
        "icon": "ps",
        "desc": "List current members of the Schema Admins group.",
        "code": "Get-ADGroupMember -Identity \"Schema Admins\" -Recursive \`\n    | Select-Object Name,SamAccountName,objectClass",
        "confirm": "Any member other than the built-in Administrator (for legacy domains) or no members at all is the expected state. Any enabled, named user account listed confirms the finding.",
    },
]

REMEDIATION = {
    "title": "Remove permanent members from Schema Admins",
    "steps": [
        {
            "text": "Schema Admins should be <strong>empty</strong> at all times. Membership should only be granted temporarily when a schema extension is required, then immediately revoked.",
        },
        {
            "text": "Remove all current members:",
            "code": "Get-ADGroupMember -Identity \"Schema Admins\" | ForEach-Object {\n    Remove-ADGroupMember -Identity \"Schema Admins\" -Members $_ -Confirm:$false\n}",
        },
        {
            "text": "When a schema change is needed in future: add the required account temporarily, perform the change, then immediately remove the account and verify the group is empty again.",
        },
        {
            "text": "Enable alerting on changes to the Schema Admins group via <strong>Event ID 4728</strong> (member added) in the Security event log.",
        },
    ],
}
