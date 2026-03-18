"""
verifications/verify_inactive.py
Manual Verification and Remediation data for ADScan findings matching: inactive
"""

MATCH_KEYS = ["inactive"]

TOOLS = [
    {
        "tool": "PowerShell",
        "icon": "ps",
        "desc": "Find user accounts that have not logged in for 90+ days.",
        "code": "$cutoff = (Get-Date).AddDays(-90)\nGet-ADUser -Filter {LastLogonDate -lt $cutoff -and Enabled -eq $true} `\n    -Properties LastLogonDate `\n    | Select-Object Name,SamAccountName,LastLogonDate",
        "confirm": "Each listed account is stale and an attack surface for password spray or brute-force.",
    },
    {
        "tool": "NetExec",
        "icon": "netexec",
        "desc": "Enumerate all enabled user accounts to identify stale ones.",
        "code": "netexec ldap <DC_IP> -u <username> -p <password> --users",
        "confirm": "Cross-reference last logon dates against 90-day threshold.",
    },
    {
        "tool": "ADUC (dsa.msc)",
        "icon": "aduc",
        "desc": "Use the built-in stale account query in ADUC.",
        "steps": [
            "Open <code>dsa.msc</code>",
            "Action → Find → Custom Search → Advanced tab",
            "LDAP query: <code>(&(objectClass=user)(lastLogon<=&lt;cutoff_timestamp&gt;)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))</code>",
            "Review results for accounts not used in 90+ days.",
        ],
    },
    {
        "tool": "net user",
        "icon": "cmd",
        "desc": "Check last logon for a specific account.",
        "code": "net user <username> /domain",
        "confirm": "Check <strong>Last logon</strong> date in the output.",
    },
]

REMEDIATION = {
    "title": "Disable and quarantine stale accounts",
    "steps": [
        {
            "text": "Disable stale accounts (safer than immediate deletion):",
            "code": "$cutoff = (Get-Date).AddDays(-90)\nGet-ADUser -Filter {LastLogonDate -lt $cutoff -and Enabled -eq $true} `\n    -Properties LastLogonDate `\n    | Disable-ADAccount",
        },
        {
            "text": "Move disabled accounts to a dedicated <strong>Disabled Users OU</strong> for 30-day quarantine before deletion.",
            "code": "Get-ADUser -SearchBase \"OU=Disabled,DC=<domain>...\" -Filter * `\n    | Move-ADObject -TargetPath \"OU=Quarantine,DC=<domain>...\"",
        },
        {
            "text": "Implement a <strong>User Lifecycle Management process</strong> — automate disabling accounts when users leave (integrate with HR system).",
        },
    ],
}
