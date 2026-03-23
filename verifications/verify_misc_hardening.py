"""
verifications/verify_misc_hardening.py
Manual verification, remediation, and references for miscellaneous hardening findings.
Covers: machine account quota (ms-DS-MachineAccountQuota), LDAP channel binding,
krbtgt password age, domain functional level, and similar domain-wide settings.
"""

MATCH_KEYS = [
    "misc hardening",
    "miscellaneous",
    "machine account quota",
    "machineaccountquota",
    "ms-ds-machineaccountquota",
    "krbtgt password",
    "domain functional level",
]

TOOLS = [
    {
        "tool": "PowerShell (AD Module)",
        "icon": "ps",
        "desc": "Check key domain hardening settings in one pass.",
        "code": (            "# Machine account quota\n"            "(Get-ADDomain).ms-DS-MachineAccountQuota\n"            "# or:\n"            "Get-ADObject -Identity (Get-ADDomain).DistinguishedName \\\n"            "  -Properties ms-DS-MachineAccountQuota |\n"            "  Select-Object 'ms-DS-MachineAccountQuota'\n"            "\n"            "# krbtgt password last set\n"            "(Get-ADUser krbtgt -Properties PasswordLastSet).PasswordLastSet\n"            "\n"            "# Domain functional level\n"            "(Get-ADDomain).DomainMode"
        ),
        "confirm": "Machine account quota should be 0. krbtgt password should be changed within the last 180 days. DomainMode should be Windows2016Domain or higher.",
    },
]

REMEDIATION = {
    "title": "Apply domain-wide hardening: quota, krbtgt rotation, and functional level",
    "steps": [
        {
            "text": "Set ms-DS-MachineAccountQuota to 0 to prevent non-admin domain joins:",
            "code": "Set-ADDomain -Identity (Get-ADDomain).DistinguishedName -Replace @{'ms-DS-MachineAccountQuota'=0}",
        },
        {
            "text": "Rotate the krbtgt password twice (with a replication delay between rotations to avoid lockout):",
            "code": (                "# Rotation 1:\n"                "Set-ADAccountPassword -Identity krbtgt \\\n"                "  -Reset -NewPassword (ConvertTo-SecureString \\\n"                "    -AsPlainText (New-Guid).Guid -Force)\n"                "# Wait for replication (recommend 10+ hours for large environments)\n"                "# Then perform Rotation 2 identically"
            ),
        },
        {
            "text": "Raise the domain functional level to Windows Server 2016 or higher if all DCs support it: Set-ADDomainMode -Identity <domain> -DomainMode Windows2016Domain",
        },
    ],
}

REFERENCES = [
    {
        "title": "Microsoft — ms-DS-MachineAccountQuota Attribute",
        "url": "https://learn.microsoft.com/en-us/windows/win32/adschema/a-ms-ds-machineaccountquota",
        "tag": "vendor",
    },
    {
        "title": "Microsoft — Resetting the krbtgt Account Password",
        "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ad-forest-recovery-resetting-the-krbtgt-password",
        "tag": "vendor",
    },
    {
        "title": "MITRE ATT&CK — Create Account: Domain Account (T1136.002)",
        "url": "https://attack.mitre.org/techniques/T1136/002/",
        "tag": "attack",
    },
]
