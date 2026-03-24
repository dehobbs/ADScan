""" verifications/verify_unconstrained_delegation.py
Manual Verification and Remediation data for ADScan findings matching:
  Computer Accounts with Unconstrained Delegation
"""

MATCH_KEYS = ["computer accounts with unconstrained"]

TOOLS = [
    {
        "tool": "NetExec",
        "icon": "netexec",
        "desc": "Enumerate computer accounts configured with unconstrained delegation.",
        "code": "netexec ldap <DC_IP> -u <username> -p <password> --trusted-for-delegation",
        "confirm": "Any non-DC computer listed has unconstrained delegation — a critical risk.",
    },
    {
        "tool": "Impacket",
        "icon": "impacket",
        "desc": "Use findDelegation to enumerate all delegation types in the domain.",
        "code": "findDelegation.py <domain>/<username>:<password> -dc-ip <DC_IP>",
        "confirm": "Look for <strong>Unconstrained</strong> in the Delegation Type column for non-DC computer accounts.",
    },
    {
        "tool": "PowerShell",
        "icon": "ps",
        "desc": "Query AD for computer accounts with TrustedForDelegation set, excluding DCs.",
        "code": "Get-ADComputer -Filter {TrustedForDelegation -eq $true} `\n    -Properties TrustedForDelegation `\n    | Where-Object {$_.Name -notlike '*DC*'} `\n    | Select-Object Name,DNSHostName",
        "confirm": "Any computer listed (excluding DCs) has unconstrained delegation enabled.",
    },
    {
        "tool": "ADUC (dsa.msc)",
        "icon": "aduc",
        "desc": "Check delegation settings on individual computer objects.",
        "steps": [
            "Open <code>dsa.msc</code> → View → Advanced Features",
            "Locate the computer object → Properties → Delegation tab",
            "<strong>Trust this computer for delegation to any service (Kerberos only)</strong> = Unconstrained",
        ],
    },
]

REMEDIATION = {
    "title": "Migrate to constrained or resource-based constrained delegation",
    "steps": [
        {
            "text": "Remove unconstrained delegation flag from the computer account:",
            "code": "Set-ADComputer -Identity <computername> -TrustedForDelegation $false",
        },
        {
            "text": "Replace with constrained delegation (specific SPNs only):",
            "code": "Set-ADComputer -Identity <computername> `\n    -TrustedToAuthForDelegation $true `\n    -ServicePrincipalNames @{Add='cifs/<target>'}",
        },
        {
            "text": "Add the affected computer account to the <strong>Protected Users</strong> security group — members cannot be configured for unconstrained delegation.",
        },
    ],
}

REFERENCES = [
    {"title": "Unconstrained Delegation - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview", "tag": "vendor"},
    {"title": "Configuring Kerberos Delegation - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/jj553400(v=ws.11)", "tag": "vendor"},
    {"title": "MITRE ATT&CK: Steal or Forge Kerberos Tickets (T1558)", "url": "https://attack.mitre.org/techniques/T1558/", "tag": "attack"},
    {"title": "Unconstrained Delegation Abuse - SpecterOps", "url": "https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-dc6176b58138", "tag": "attack"},
    {"title": "SpoolSample - Printer Bug for Unconstrained Delegation", "url": "https://github.com/leechristensen/SpoolSample", "tag": "tool"},
    {"title": "Rubeus - Unconstrained Delegation Monitoring", "url": "https://github.com/GhostPack/Rubeus", "tag": "tool"},
    {"title": "BloodHound - Unconstrained Delegation Discovery", "url": "https://github.com/BloodHoundAD/BloodHound", "tag": "tool"},
    {"title": "CIS Benchmark: Disable Unconstrained Delegation", "url": "https://www.cisecurity.org/benchmark/microsoft_windows_server", "tag": "defense"},
    {"title": "Defender for Identity: Unconstrained Delegation Alert", "url": "https://learn.microsoft.com/en-us/defender-for-identity/unconstrained-delegation-alerts", "tag": "defense"},
]
