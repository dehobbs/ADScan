"""
verifications/verify_password_never_expires.py
Manual Verification and Remediation data for ADScan findings matching: password never expires
"""

MATCH_KEYS = ["non-expiring", "passwords never expire"]

TOOLS = [
    {
        "tool": "PowerShell",
        "icon": "ps",
        "desc": "Find all accounts with the PasswordNeverExpires flag set.",
        "code": "Get-ADUser -Filter {PasswordNeverExpires -eq $true} `\n    -Properties PasswordNeverExpires `\n    | Select-Object Name,SamAccountName",
        "confirm": "Each account listed has a non-expiring password.",
    },
    {
        "tool": "PowerShell (Windows)",
        "icon": "ps",
        "desc": "List all users with non-expiring passwords using a simple one-liner.",
        "code": "Get-ADUser -Filter {PasswordNeverExpires -eq $true} -Properties PasswordNeverExpires",
        "confirm": "Each user object returned has PasswordNeverExpires set to True.",
    },
    {
        "tool": "ADUC (dsa.msc)",
        "icon": "aduc",
        "desc": "Search for accounts with password never expires via the GUI.",
        "steps": [
            "Open <code>dsa.msc</code>",
            "Action \u2192 Find \u2192 select <em>Users</em>",
            "Advanced tab \u2192 Field: <em>Password Never Expires</em> = <em>True</em>",
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
            "text": "For <strong>service accounts</strong>, use <strong>Group Managed Service Accounts (gMSAs)</strong> which rotate passwords automatically \u2014 eliminating the need for PasswordNeverExpires.",
        },
        {
            "text": "Apply via <strong>ADUC (dsa.msc)</strong>:",
            "steps": [
                "Open <code>dsa.msc</code>",
                "Locate the user account \u2192 right-click \u2192 <em>Properties</em>",
                "Go to the <em>Account</em> tab",
                "Under <em>Account options</em>, uncheck <strong>Password never expires</strong>",
                "Click <em>Apply</em> then <em>OK</em>",
            ],
        },
        {
            "text": "Apply in bulk via <strong>PowerShell</strong> for all non-service accounts:",
            "code": "Get-ADUser -Filter {PasswordNeverExpires -eq $true} `\n    -Properties PasswordNeverExpires `\n    | Where-Object {$_.SamAccountName -notlike '*svc*'} `\n    | ForEach-Object { Set-ADUser $_ -PasswordNeverExpires $false }",
        },
    ],
}


REFERENCES = [
    {"title": "Password Never Expires Flag - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/windows/win32/adschema/a-pwdlastset", "tag": "vendor"},
    {"title": "Account Password Policy Settings - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-policy", "tag": "vendor"},
    {"title": "MITRE ATT&CK: Valid Accounts (T1078)", "url": "https://attack.mitre.org/techniques/T1078/", "tag": "attack"},
    {"title": "MITRE ATT&CK: Brute Force (T1110)", "url": "https://attack.mitre.org/techniques/T1110/", "tag": "attack"},
    {"title": "Get-ADUser PasswordNeverExpires Enumeration", "url": "https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-aduser", "tag": "tool"},
    {"title": "CIS Benchmark: Do not allow passwords to never expire", "url": "https://www.cisecurity.org/benchmark/microsoft_windows_server", "tag": "defense"},
    {"title": "Fine-Grained Password Policies for Service Accounts", "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/introduction-to-active-directory-administrative-center-enhancements--level-100-#fine_grained_pswd_policy_mgmt", "tag": "defense"},
    {"title": "Managing Privileged Accounts - PAW Model", "url": "https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model", "tag": "defense"},
]
