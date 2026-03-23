"""
verifications/verify_foreign_security_principals.py
Manual verification, remediation, and references for foreign security principal findings.
"""

MATCH_KEYS = [
    "foreign security principal",
    "foreignsecurityprincipal",
    "cross-domain group member",
]

TOOLS = [
    {
        "tool": "PowerShell (AD Module)",
        "icon": "ps",
        "desc": "Enumerate all Foreign Security Principals (FSPs) in the domain.",
        "code": (            "Get-ADObject \\\n"            "  -SearchBase \"CN=ForeignSecurityPrincipals,$($(Get-ADDomain).DistinguishedName)\" \\\n"            "  -Filter {objectClass -eq 'foreignSecurityPrincipal'} \\\n"            "  -Properties Name, memberOf |\n"            "  Select-Object Name, MemberOf |\n"            "  Format-Table -AutoSize\n"            "\n"            "# Resolve FSP SIDs to friendly names where possible:\n"            "Get-ADObject \\\n"            "  -SearchBase \"CN=ForeignSecurityPrincipals,$($(Get-ADDomain).DistinguishedName)\" \\\n"            "  -Filter {objectClass -eq 'foreignSecurityPrincipal'} |\n"            "  ForEach-Object { [System.Security.Principal.SecurityIdentifier]::new($_.Name).Translate([System.Security.Principal.NTAccount]) }"
        ),
        "confirm": "FSPs that are members of privileged groups (Domain Admins, Administrators) without documented justification are high risk.",
    },
]

REMEDIATION = {
    "title": "Review and remove unauthorised Foreign Security Principal group memberships",
    "steps": [
        {
            "text": "Identify each FSP and resolve its SID to a friendly name from the trusted domain.",
        },
        {
            "text": "Remove FSPs from privileged groups where cross-domain membership is not operationally required:",
            "code": "Remove-ADGroupMember -Identity 'Domain Admins' -Members '<FSP_DN>' -Confirm:$false",
        },
        {
            "text": "If the originating trust is no longer needed, remove the FSPs after decommissioning the trust.",
        },
        {
            "text": "Regularly audit FSP membership in privileged groups as part of access reviews.",
        },
    ],
}

REFERENCES = [
    {
        "title": "Microsoft — Foreign Security Principals",
        "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/securing-domain-controllers-against-attack",
        "tag": "vendor",
    },
    {
        "title": "MITRE ATT&CK — Domain Trust Discovery (T1482)",
        "url": "https://attack.mitre.org/techniques/T1482/",
        "tag": "attack",
    },
    {
        "title": "harmj0y — Foreign Group Memberships and Domain Trust Abuse",
        "url": "https://harmj0y.medium.com/a-guide-to-attacking-domain-trusts-ef5f8992bb4e",
        "tag": "research",
    },
]
