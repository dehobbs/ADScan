"""
verifications/verify_adminsdholder.py
Manual Verification and Remediation data for ADScan findings matching: adminsdholder
"""

MATCH_KEYS = ["adminsdholder"]

TOOLS = [
    {
        "tool": "Impacket",
        "icon": "impacket",
        "desc": "Enumerate ACLs on the AdminSDHolder container using dacledit.",
        "code": "dacledit.py <domain>/<username>:<password> -dc-ip <DC_IP> `\n    -target-dn \"CN=AdminSDHolder,CN=System,DC=<domain>,DC=<tld>\"`\n    -action read",
        "confirm": "Unexpected accounts with GenericAll, WriteDACL, or GenericWrite permissions are a critical finding.",
    },
    {
        "tool": "PowerShell",
        "icon": "ps",
        "desc": "Read ACL on the AdminSDHolder object.",
        "code": "Get-ACL \"AD:\\CN=AdminSDHolder,CN=System,$(([adsi]\'\')).distinguishedName\" `\n    | Select-Object -Expand Access `\n    | Where-Object {$_.ActiveDirectoryRights -match \"GenericAll|WriteDACL|WriteOwner\"}",
        "confirm": "Non-admin accounts in the ACL output represent a persistence/escalation path.",
    },
    {
        "tool": "BloodHound / SharpHound",
        "icon": "netexec",
        "desc": "Collect ACL data and visualise AdminSDHolder attack paths.",
        "code": "SharpHound.exe -c All\n# Import to BloodHound and search:\n# MATCH p=()-[:GenericAll]->(n:Group {name:\"ADMINSDHOLDER@DOMAIN\"}) RETURN p",
        "confirm": "Any inbound edge to AdminSDHolder in BloodHound is exploitable.",
    },
    {
        "tool": "ADUC (dsa.msc)",
        "icon": "aduc",
        "desc": "View AdminSDHolder ACL via the Security tab in ADUC.",
        "steps": [
            "Open <code>dsa.msc</code> → View → Advanced Features",
            "Navigate to <em>System → AdminSDHolder</em>",
            "Properties → Security → Advanced",
            "Review all entries — only Domain Admins and SYSTEM should have full control.",
        ],
    },
]

REMEDIATION = {
    "title": "Remove unauthorized ACEs from AdminSDHolder",
    "steps": [
        {
            "text": "Remove a specific ACE using PowerShell (requires Domain Admin):",
            "code": "$acl = Get-ACL \"AD:\\CN=AdminSDHolder,CN=System,DC=<domain>,DC=<tld>\"\n$ace = $acl.Access | Where-Object {$_.IdentityReference -match \"<attacker_account>\"}\n$acl.RemoveAccessRule($ace)\nSet-ACL -Path \"AD:\\CN=AdminSDHolder...\" -AclObject $acl",
        },
        {
            "text": "Force SDProp to propagate corrected ACLs immediately:",
            "code": "Invoke-Expression -Command \"Repair-ADObject -Identity (Get-ADObject -SearchBase 'CN=AdminSDHolder,CN=System,DC=<domain>,DC=<tld>' -Filter *)\"",
        },
        {
            "text": "Audit SDProp propagation regularly using <strong>Active Directory Auditing</strong> — enable object modification auditing on AdminSDHolder.",
        },
    ],
}


REFERENCES = [
    {"title": "AdminSDHolder and SDProp - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory", "tag": "vendor"},
    {"title": "How SDProp Works - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/previous-versions/technet-magazine/ee361593(v=msdn.10)", "tag": "vendor"},
    {"title": "MITRE ATT&CK: Account Manipulation (T1098)", "url": "https://attack.mitre.org/techniques/T1098/", "tag": "attack"},
    {"title": "AdminSDHolder Backdoor Persistence - Active Directory Security", "url": "https://adsecurity.org/?p=1906", "tag": "attack"},
    {"title": "BloodHound - AdminSDHolder ACL Analysis", "url": "https://github.com/BloodHoundAD/BloodHound", "tag": "tool"},
    {"title": "Invoke-ACLpwn - ACL-based Privilege Escalation", "url": "https://github.com/fox-it/Invoke-ACLPwn", "tag": "tool"},
    {"title": "Monitoring AdminSDHolder Changes - Microsoft", "url": "https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5136", "tag": "defense"},
    {"title": "CIS Benchmark: Restrict AdminSDHolder ACLs", "url": "https://www.cisecurity.org/benchmark/microsoft_windows_server", "tag": "defense"},
]
