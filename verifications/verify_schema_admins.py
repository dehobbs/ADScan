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


REFERENCES = [
    {"title": "Schema Admins Group - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory", "tag": "vendor"},
    {"title": "Active Directory Schema - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/windows/win32/ad/active-directory-schema", "tag": "vendor"},
    {"title": "MITRE ATT&CK: Domain Policy Modification (T1484)", "url": "https://attack.mitre.org/techniques/T1484/", "tag": "attack"},
    {"title": "Schema Modification for Persistence - Active Directory Security", "url": "https://adsecurity.org/?p=2782", "tag": "attack"},
    {"title": "BloodHound - Schema Admins Group Analysis", "url": "https://github.com/BloodHoundAD/BloodHound", "tag": "tool"},
    {"title": "Securing Schema Admins - Microsoft Best Practices", "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/reducing-the-active-directory-attack-surface", "tag": "defense"},
    {"title": "CIS Benchmark: Restrict Schema Admins membership", "url": "https://www.cisecurity.org/benchmark/microsoft_windows_server", "tag": "defense"},
    {"title": "Tiered Administration Model - Microsoft PAW", "url": "https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model", "tag": "defense"},
]
