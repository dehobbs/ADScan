"""
verifications/verify_password_never_expires.py
Manual Verification and Remediation data for ADScan findings matching: password never expires
"""

MATCH_KEYS = ["password never expires"]

TOOLS = [
    {
        "tool": "PowerShell",
        "icon": "ps",
        "desc": "Find all accounts with the PasswordNeverExpires flag set.",
        "code": "Get-ADUser -Filter {PasswordNeverExpires -eq $true} `\n    -Properties PasswordNeverExpires `\n    | Select-Object Name,SamAccountName",
        "confirm": "Each account listed has a non-expiring password.",
    },
    {
        "tool": "NetExec",
        "icon": "netexec",
        "desc": "Enumerate users with password-never-expires flag via LDAP.",
        "code": "netexec ldap <DC_IP> -u <username> -p <password> --password-not-required",
        "confirm": "Accounts listed have the flag set.",
    },
    {
        "tool": "ADUC (dsa.msc)",
        "icon": "aduc",
        "desc": "Search for accounts with password never expires via the GUI.",
        "steps": [
            "Open <code>dsa.msc</code>",
            "Action → Find → select <em>Users</em>",
            "Advanced tab → Field: <em>Password Never Expires</em> = <em>True</em>",
        ],
    },
    {
        "tool": "net user",
        "icon": "cmd",
        "desc": "Check a specific user account for the password expiry setting.",
        "code": "net user <username> /domain",
        "confirm": "Look for <strong>Password expires: Never</strong> in the output.",
    },
]

REMEDIATION = {
    "title": "Enable password expiration for non-service accounts",
    "steps": [
        {
            "text": "Enable password expiry for a single user:",
            "code": "Set-ADUser -Identity <username> -PasswordNeverExpires $false",
        },
        {
            "text": "Bulk-fix all non-service accounts:",
            "code": "Get-ADUser -Filter {PasswordNeverExpires -eq $true} `\n    | Where-Object {$_.SamAccountName -notlike '*svc*'} `\n    | Set-ADUser -PasswordNeverExpires $false",
        },
        {
            "text": "For <strong>service accounts</strong>, use <strong>Group Managed Service Accounts (gMSAs)</strong> which rotate passwords automatically — eliminating the need for PasswordNeverExpires.",
        },
    ],
}
