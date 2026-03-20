"""
verifications/verify_unconstrained_delegation.py
Manual Verification and Remediation data for ADScan findings matching: unconstrained delegation
"""

MATCH_KEYS = ["unconstrained delegation"]

TOOLS = [
    {
        "tool": "NetExec",
        "icon": "netexec",
        "desc": "Enumerate computers and users configured with unconstrained delegation.",
        "code": "netexec ldap <DC_IP> -u <username> -p <password> --trusted-for-delegation",
        "confirm": "Any non-DC host listed has unconstrained delegation — a critical risk.",
    },
    {
        "tool": "Impacket",
        "icon": "impacket",
        "desc": "Use findDelegation to enumerate all delegation types in the domain.",
        "code": "findDelegation.py <domain>/<username>:<password> -dc-ip <DC_IP>",
        "confirm": "Look for <strong>Unconstrained</strong> in the Delegation Type column for non-DC hosts.",
    },
    {
        "tool": "PowerShell",
        "icon": "ps",
        "desc": "Query AD for computers and users with TrustedForDelegation set.",
        "code": "Get-ADComputer -Filter {TrustedForDelegation -eq $true} `\n    -Properties TrustedForDelegation `\n    | Where-Object {$_.Name -notlike '*DC*'} `\n    | Select-Object Name,DNSHostName\n\nGet-ADUser -Filter {TrustedForDelegation -eq $true} `\n    | Select-Object Name,SamAccountName",
        "confirm": "Any computer (excluding DCs) or user listed has unconstrained delegation.",
    },
]

REMEDIATION = {
    "title": "Migrate to constrained or resource-based constrained delegation",
    "steps": [
        {
            "text": "Remove unconstrained delegation flag from a computer:",
            "code": "Set-ADComputer -Identity <computername> -TrustedForDelegation $false",
        },
        {
            "text": "Replace with constrained delegation (specific SPNs only):",
            "code": "Set-ADComputer -Identity <computername> `\n    -TrustedToAuthForDelegation $true `\n    -ServicePrincipalNames @{Add='cifs/<target>'}",
        },
        {
            "text": "Add affected computer and user accounts to the <strong>Protected Users</strong> security group — members cannot be configured for unconstrained delegation.",
        },
        {
            "text": "Enable <strong>Account is sensitive and cannot be delegated</strong> on all privileged accounts via ADUC or PowerShell: <code>Set-ADUser -Identity &lt;admin&gt; -AccountNotDelegated $true</code>",
        },
    ],
}
