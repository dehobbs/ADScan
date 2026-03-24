"""
verifications/verify_rodc_password_replication.py
Manual Verification and Remediation data for ADScan findings matching:
rodc permissive password replication policy
"""

MATCH_KEYS = [
    "permissive password replication",
    "rodc password replication",
]

TOOLS = [
    {
        "tool": "PowerShell",
        "icon": "ps",
        "desc": "Enumerate the Password Replication Policy (PRP) for all RODCs.",
        "code": "Get-ADDomainController -Filter {IsReadOnly -eq $true} | ForEach-Object {\n    $rodc = $_\n    Write-Host \"RODC: $($rodc.Name)\"\n    # Allowed list (accounts whose passwords CAN be cached)\n    Get-ADObject $rodc.ComputerObjectDN -Properties 'msDS-RevealOnDemandGroup' |\n        Select-Object -ExpandProperty 'msDS-RevealOnDemandGroup'\n    # Denied list\n    Get-ADObject $rodc.ComputerObjectDN -Properties 'msDS-NeverRevealGroup' |\n        Select-Object -ExpandProperty 'msDS-NeverRevealGroup'\n}",
        "confirm": "The Allowed list should be minimal (branch users only). The Denied list must include Domain Admins, Enterprise Admins, and krbtgt.",
    },
    {
        "tool": "ADUC (dsa.msc)",
        "icon": "aduc",
        "desc": "Review the Password Replication Policy in ADUC.",
        "steps": [
            "Open <code>dsa.msc</code> → Domain Controllers OU",
            "Right-click the RODC → Properties → Password Replication Policy tab",
            "Review the <strong>Allowed</strong> and <strong>Denied</strong> lists",
            "Ensure privileged accounts (Domain Admins, Enterprise Admins, Schema Admins) are in the <strong>Denied</strong> list",
            "The <strong>Allowed</strong> list should contain only the minimum required user/computer accounts for the branch site",
        ],
    },
    {
        "tool": "NetExec",
        "icon": "netexec",
        "desc": "Enumerate RODC cached credentials.",
        "code": "netexec ldap <DC_IP> -u <username> -p <password> --dc-list",
        "confirm": "Verify which accounts have cached passwords on the RODC by reviewing <strong>msDS-RevealedList</strong> attribute.",
    },
]

REMEDIATION = {
    "title": "Tighten the RODC Password Replication Policy",
    "steps": [
        {
            "text": "Remove all privileged accounts and groups from the <strong>Allowed</strong> PRP list. At minimum, these groups must be in the <strong>Denied</strong> list:",
            "code": "# Add privileged groups to Denied list:\nSet-ADObject -Identity <RODC_DN> \\\n    -Add @{'msDS-NeverRevealGroup' = @(\n        (Get-ADGroup 'Domain Admins').DistinguishedName,\n        (Get-ADGroup 'Enterprise Admins').DistinguishedName,\n        (Get-ADGroup 'Schema Admins').DistinguishedName\n    )}",
        },
        {
            "text": "Scope the <strong>Allowed</strong> list to only the accounts that legitimately need offline authentication at the branch site (specific users and computer accounts only).",
        },
        {
            "text": "Invalidate any cached credentials on the RODC that should not be there — use <strong>Reset and Notify</strong> in ADUC to force re-authentication:",
            "steps": [
                "ADUC → Domain Controllers → right-click RODC → Properties → Password Replication Policy tab",
                "Click <strong>Advanced</strong> → Accounts whose passwords are stored on this RODC",
                "Select any privileged accounts shown → <strong>Reset passwords for these accounts on the next logon</strong>",
            ],
        },
    ],
}

REFERENCES = [
    {"title": "RODC Password Replication Policy - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/rodc-planning", "tag": "vendor"},
    {"title": "Administering the Password Replication Policy - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ad-ds-simplified-administration", "tag": "vendor"},
    {"title": "MITRE ATT&CK: DCSync (T1003.006)", "url": "https://attack.mitre.org/techniques/T1003/006/", "tag": "attack"},
    {"title": "RODC Golden Ticket Attack - Active Directory Security", "url": "https://adsecurity.org/?p=3592", "tag": "research"},
    {"title": "Attacking Read-Only Domain Controllers - CQure Academy", "url": "https://cqureacademy.com/blog/rodc-attacks", "tag": "research"},
    {"title": "CIS Benchmark: Restrict RODC Password Replication Policy", "url": "https://www.cisecurity.org/benchmark/microsoft_windows_server", "tag": "defense"},
]
