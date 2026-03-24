""" verifications/verify_user_unconstrained_delegation.py
Manual Verification and Remediation data for ADScan findings matching:
  User Accounts with Unconstrained Delegation
"""

MATCH_KEYS = ["user accounts with unconstrained"]

TOOLS = [
    {
        "tool": "NetExec",
        "icon": "netexec",
        "desc": "Enumerate user accounts configured with unconstrained delegation.",
        "code": "netexec ldap <DC_IP> -u <username> -p <password> --trusted-for-delegation",
        "confirm": "Any user account listed (not a computer) has unconstrained delegation — a critical risk.",
    },
    {
        "tool": "Impacket",
        "icon": "impacket",
        "desc": "Use findDelegation to enumerate all delegation types in the domain.",
        "code": "findDelegation.py <domain>/<username>:<password> -dc-ip <DC_IP>",
        "confirm": "Look for <strong>Unconstrained</strong> in the Delegation Type column for user accounts.",
    },
    {
        "tool": "PowerShell",
        "icon": "ps",
        "desc": "Query AD specifically for user accounts with TrustedForDelegation set.",
        "code": "Get-ADUser -Filter {TrustedForDelegation -eq $true} `\n    | Select-Object Name,SamAccountName,DistinguishedName",
        "confirm": "Any user account listed has unconstrained delegation enabled.",
    },
]

REMEDIATION = {
    "title": "Remove unconstrained delegation from user accounts",
    "steps": [
        {
            "text": "Remove the unconstrained delegation flag from the user account:",
            "code": "Set-ADUser -Identity <username> -TrustedForDelegation $false",
        },
        {
            "text": "If the account genuinely requires delegation, replace with constrained delegation scoped to specific SPNs only:",
            "code": "Set-ADUser -Identity <username> `\n    -TrustedToAuthForDelegation $true",
        },
        {
            "text": "Add the affected user account to the <strong>Protected Users</strong> security group — members cannot be configured for any form of Kerberos delegation.",
        },
        {
            "text": "Enable <strong>Account is sensitive and cannot be delegated</strong> on all privileged accounts:",
            "code": "Set-ADUser -Identity <username> -AccountNotDelegated $true",
        },
    ],
}

REFERENCES = [
    {"title": "Unconstrained Delegation - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview", "tag": "vendor"},
    {"title": "MITRE ATT&CK: Steal or Forge Kerberos Tickets (T1558)", "url": "https://attack.mitre.org/techniques/T1558/", "tag": "attack"},
    {"title": "Unconstrained Delegation Abuse - SpecterOps", "url": "https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-dc6176b58138", "tag": "attack"},
    {"title": "Rubeus - Unconstrained Delegation Monitoring", "url": "https://github.com/GhostPack/Rubeus", "tag": "tool"},
    {"title": "BloodHound - Unconstrained Delegation Discovery", "url": "https://github.com/BloodHoundAD/BloodHound", "tag": "tool"},
    {"title": "Protected Users Security Group - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group", "tag": "defense"},
    {"title": "CIS Benchmark: Disable Unconstrained Delegation", "url": "https://www.cisecurity.org/benchmark/microsoft_windows_server", "tag": "defense"},
    {"title": "Defender for Identity: Unconstrained Delegation Alert", "url": "https://learn.microsoft.com/en-us/defender-for-identity/unconstrained-delegation-alerts", "tag": "defense"},
]
