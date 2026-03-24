"""
verifications/verify_constrained_delegation.py
Manual Verification and Remediation data for ADScan findings matching: constrained delegation
"""

MATCH_KEYS = ["accounts with constrained delegation", "constrained delegation targeting", "constrained delegation configured"]

TOOLS = [
    {
        "tool": "Impacket",
        "icon": "impacket",
        "desc": "Enumerate all delegation configurations in the domain.",
        "code": "findDelegation.py <domain>/<username>:<password> -dc-ip <DC_IP>",
        "confirm": "Accounts with <strong>Constrained w/ Protocol Transition</strong> allow S4U2Self — a privilege escalation risk.",
    },
    {
        "tool": "PowerShell",
        "icon": "ps",
        "desc": "Find accounts trusted for constrained delegation.",
        "code": "Get-ADObject -Filter {msDS-AllowedToDelegateTo -like \"*\"} `\n    -Properties msDS-AllowedToDelegateTo `\n    | Select-Object Name,msDS-AllowedToDelegateTo",
        "confirm": "Each listed account can impersonate any user to the specified service.",
    },
    {
        "tool": "NetExec",
        "icon": "netexec",
        "desc": "Enumerate delegation via LDAP enumeration.",
        "code": "netexec ldap <DC_IP> -u <username> -p <password> --trusted-for-delegation",
        "confirm": "Any non-DC account with delegation configured warrants review.",
    },
    {
        "tool": "ADUC (dsa.msc)",
        "icon": "aduc",
        "desc": "Check delegation tab on computer and user objects.",
        "steps": [
            "Open <code>dsa.msc</code> → View → Advanced Features",
            "Locate the object → Properties → Delegation tab",
            "<strong>Trust this computer for delegation to specified services only</strong> = Constrained",
            "Review the service list for any unexpected or overly-broad services.",
        ],
    },
]

REMEDIATION = {
    "title": "Audit and tighten constrained delegation scope",
    "steps": [
        {
            "text": "Remove protocol transition (S4U2Self) where not required:",
            "code": "Set-ADComputer -Identity <computername> -TrustedToAuthForDelegation $false",
        },
        {
            "text": "Switch to <strong>Resource-Based Constrained Delegation (RBCD)</strong> where possible — it\'s more granular and auditable.",
        },
        {
            "text": "Set <strong>AccountNotDelegated = $true</strong> on all privileged accounts to prevent delegation abuse.",
            "code": "Set-ADUser -Identity <admin_user> -AccountNotDelegated $true",
        },
    ],
}


REFERENCES = [
    {"title": "Kerberos Constrained Delegation Overview - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview", "tag": "vendor"},
    {"title": "Configure Constrained Delegation - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/jj553400(v=ws.11)", "tag": "vendor"},
    {"title": "MITRE ATT&CK: Use Alternate Authentication Material (T1550)", "url": "https://attack.mitre.org/techniques/T1550/", "tag": "attack"},
    {"title": "Constrained Delegation Abuse - SpecterOps", "url": "https://posts.specterops.io/s4u2pwnage-heimdal-kerberos-delegation-attack-research-7f47a8e41524", "tag": "attack"},
    {"title": "Rubeus - S4U Constrained Delegation Exploitation", "url": "https://github.com/GhostPack/Rubeus", "tag": "tool"},
    {"title": "BloodHound - Constrained Delegation Paths", "url": "https://github.com/BloodHoundAD/BloodHound", "tag": "tool"},
    {"title": "CIS Benchmark: Review Constrained Delegation", "url": "https://www.cisecurity.org/benchmark/microsoft_windows_server", "tag": "defense"},
    {"title": "Defender for Identity: Constrained Delegation Alerts", "url": "https://learn.microsoft.com/en-us/defender-for-identity/lateral-movement-alerts", "tag": "defense"},
]
