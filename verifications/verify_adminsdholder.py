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
