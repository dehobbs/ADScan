"""
verifications/verify_pre_windows_2000.py
Manual verification, remediation, and references for the Pre-Windows 2000
Compatible Access group membership finding.
"""

MATCH_KEYS = [
    "pre-windows 2000",
    "pre windows 2000",
    "pre-win2k",
]

TOOLS = [
    {
        "tool": "PowerShell (AD Module)",
        "icon": "ps",
        "desc": "Check membership of the 'Pre-Windows 2000 Compatible Access' group.",
        "code": (            "Get-ADGroupMember -Identity 'Pre-Windows 2000 Compatible Access' |\n"            "  Select-Object Name, SamAccountName, objectClass"
        ),
        "confirm": "If 'Everyone' or 'ANONYMOUS LOGON' is a member, unauthenticated enumeration of AD is possible.",
    },
    {
        "tool": "NetExec",
        "icon": "netexec",
        "desc": "Attempt unauthenticated LDAP enumeration to confirm anonymous access.",
        "code": (            "netexec ldap <DC_IP> \\\n"            "  -u '' -p '' \\\n"            "  --users"
        ),
        "confirm": "If user accounts are returned without valid credentials, the Pre-Windows 2000 group is allowing unauthenticated LDAP reads.",
    },
]

REMEDIATION = {
    "title": "Remove Everyone and ANONYMOUS LOGON from Pre-Windows 2000 Compatible Access",
    "steps": [
        {
            "text": "Remove 'Everyone' and 'ANONYMOUS LOGON' from the group:",
            "code": (                "Remove-ADGroupMember \\\n"                "  -Identity 'Pre-Windows 2000 Compatible Access' \\\n"                "  -Members 'Everyone', 'NT AUTHORITY\\ANONYMOUS LOGON' \\\n"                "  -Confirm:$false"
            ),
        },
        {
            "text": "Restrict anonymous LDAP access at the DC level by setting the restrictAnonymous and restrictAnonymousSAM registry values:",
            "code": (                "# On each DC:\n"                "Set-ItemProperty \\\n"                "  -Path HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa \\\n"                "  -Name 'restrictAnonymous' -Value 1\n"                "Set-ItemProperty \\\n"                "  -Path HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa \\\n"                "  -Name 'restrictAnonymousSAM' -Value 1"
            ),
        },
        {
            "text": "Test that removing these members does not break any legacy authentication before enforcing in production.",
        },
    ],
}

REFERENCES = [
    {
        "title": "Microsoft — Pre-Windows 2000 Compatible Access Group",
        "url": "https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#pre-windows-2000-compatible-access",
        "tag": "vendor",
    },
    {
        "title": "MITRE ATT&CK — Account Discovery: Domain Account (T1087.002)",
        "url": "https://attack.mitre.org/techniques/T1087/002/",
        "tag": "attack",
    },
    {
        "title": "NetExec — LDAP anonymous enumeration",
        "url": "https://www.netexec.wiki/ldap-protocol/ldap-anonymous-bind",
        "tag": "tool",
    },
]
