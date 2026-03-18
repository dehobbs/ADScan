"""
verifications/verify_protected_users.py
Manual Verification and Remediation data for ADScan findings matching: protected users
"""

MATCH_KEYS = ["protected users"]

TOOLS = [
    {
        "tool": "PowerShell",
        "icon": "ps",
        "desc": "Check membership of the Protected Users security group.",
        "code": "Get-ADGroupMember -Identity \"Protected Users\" | Select-Object Name,SamAccountName,objectClass",
        "confirm": "If the group is empty or missing privileged accounts, those accounts lack enhanced protections.",
    },
    {
        "tool": "NetExec",
        "icon": "netexec",
        "desc": "Enumerate group membership via LDAP.",
        "code": "netexec ldap <DC_IP> -u <username> -p <password> -M groupmembership -o GROUP=\"Protected Users\"",
        "confirm": "An empty group means no accounts benefit from Protected Users mitigations.",
    },
    {
        "tool": "ADUC (dsa.msc)",
        "icon": "aduc",
        "desc": "View Protected Users group membership in the GUI.",
        "steps": [
            "Open <code>dsa.msc</code>",
            "Navigate to <em>Users</em> container",
            "Find <strong>Protected Users</strong> group → Properties → Members tab",
            "Verify all privileged accounts (Domain Admins, Enterprise Admins, etc.) are listed.",
        ],
    },
    {
        "tool": "net group",
        "icon": "cmd",
        "desc": "Check Protected Users group membership from command line.",
        "code": "net group \"Protected Users\" /domain",
        "confirm": "Empty output means no accounts are protected.",
    },
]

REMEDIATION = {
    "title": "Add privileged accounts to the Protected Users group",
    "steps": [
        {
            "text": "Add a privileged account to Protected Users:",
            "code": "Add-ADGroupMember -Identity \"Protected Users\" -Members <username>",
        },
        {
            "text": "Bulk-add all Domain Admins:",
            "code": "Get-ADGroupMember -Identity \"Domain Admins\" `\n    | ForEach-Object { Add-ADGroupMember -Identity \"Protected Users\" -Members $_ }",
        },
        {
            "text": "<strong>Test before production deployment</strong> — Protected Users disables NTLM authentication, DES/RC4 Kerberos, and credential caching. Service accounts that rely on these will break.",
        },
    ],
}
