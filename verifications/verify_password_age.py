"""
verifications/verify_password_age.py
Manual Verification and Remediation data for ADScan findings matching:
passwords older than
"""

MATCH_KEYS = [
    "passwords older than",
    "password not changed",
]

TOOLS = [
    {
        "tool": "PowerShell",
        "icon": "ps",
        "desc": "Find enabled user accounts whose passwords have not changed in over 365 days.",
        "code": "$cutoff = (Get-Date).AddDays(-365)\nGet-ADUser -Filter {Enabled -eq $true -and PasswordLastSet -lt $cutoff} \\\n    -Properties PasswordLastSet, PasswordNeverExpires \\\n    | Select-Object Name, SamAccountName, PasswordLastSet, PasswordNeverExpires \\\n    | Sort-Object PasswordLastSet",
        "confirm": "Each listed account has not rotated its password in over a year — a significant credential theft risk.",
    },
    {
        "tool": "NetExec",
        "icon": "netexec",
        "desc": "Enumerate user accounts including password last set dates.",
        "code": "netexec ldap <DC_IP> -u <username> -p <password> --users",
        "confirm": "Review the <strong>pwd_last_set</strong> column for accounts with very old dates.",
    },
    {
        "tool": "ADUC (dsa.msc)",
        "icon": "aduc",
        "desc": "View password age for individual accounts in ADUC.",
        "steps": [
            "Open <code>dsa.msc</code>",
            "Locate a user → Properties → Account tab",
            "Check <strong>Password last changed</strong> date",
            "For bulk review, use Active Directory Administrative Center → Global Search with filters",
        ],
    },
    {
        "tool": "net user",
        "icon": "cmd",
        "desc": "Check password age for a specific account.",
        "code": "net user <username> /domain",
        "confirm": "Check <strong>Password last set</strong> in the output — compare against policy threshold.",
    },
]

REMEDIATION = {
    "title": "Force password rotation and enforce maximum password age",
    "steps": [
        {
            "text": "Force immediate password reset on all accounts exceeding the threshold:",
            "code": "$cutoff = (Get-Date).AddDays(-365)\nGet-ADUser -Filter {Enabled -eq $true -and PasswordLastSet -lt $cutoff} \\\n    | Set-ADUser -ChangePasswordAtLogon $true",
        },
        {
            "text": "Enforce <strong>Maximum Password Age</strong> via Default Domain Policy (recommended: 90 days for standard users, finer policy via PSOs for privileged accounts).",
            "code": "# Set via Group Policy:\n# Computer Configuration → Windows Settings → Security Settings\n# → Account Policies → Password Policy → Maximum password age",
        },
        {
            "text": "Use <strong>Fine-Grained Password Policies (PSOs)</strong> to apply stricter rotation requirements to privileged accounts (Domain Admins, service accounts).",
            "code": "New-ADFineGrainedPasswordPolicy -Name 'PrivilegedAccounts' \\\n    -MaxPasswordAge '30.00:00:00' \\\n    -MinPasswordLength 16 \\\n    -Precedence 10",
        },
        {
            "text": "Investigate <strong>service accounts</strong> with stale passwords — migrate to <strong>Group Managed Service Accounts (gMSA)</strong> for automatic rotation.",
        },
    ],
}

REFERENCES = [
    {"title": "Maximum Password Age Policy - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/maximum-password-age", "tag": "vendor"},
    {"title": "Fine-Grained Password Policies - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/azure/active-directory-domain-services/password-policy", "tag": "vendor"},
    {"title": "MITRE ATT&CK: Valid Accounts (T1078)", "url": "https://attack.mitre.org/techniques/T1078/", "tag": "attack"},
    {"title": "MITRE ATT&CK: Brute Force - Password Spraying (T1110.003)", "url": "https://attack.mitre.org/techniques/T1110/003/", "tag": "attack"},
    {"title": "CIS Benchmark: Set Maximum Password Age to 365 days or fewer", "url": "https://www.cisecurity.org/benchmark/microsoft_windows_server", "tag": "defense"},
    {"title": "NIST SP 800-63B: Digital Identity Guidelines - Password Best Practices", "url": "https://pages.nist.gov/800-63-3/sp800-63b.html", "tag": "defense"},
    {"title": "Group Managed Service Accounts - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview", "tag": "defense"},
]
