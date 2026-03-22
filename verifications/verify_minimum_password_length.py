"""
verifications/verify_minimum_password_length.py
Manual Verification and Remediation data for ADScan findings matching: minimum password length
"""

MATCH_KEYS = ["minimum password length"]

TOOLS = [
    {
        "tool": "NetExec",
        "icon": "netexec",
        "desc": "Enumerate password policy remotely to see the minimum length setting.",
        "code": "netexec smb <DC_IP> -u <username> -p <password> --pass-pol",
        "confirm": "Check <strong>Minimum password length</strong> value in the output.",
    },
    {
        "tool": "PowerShell",
        "icon": "ps",
        "desc": "Query minimum password length from the default domain password policy.",
        "code": "Get-ADDefaultDomainPasswordPolicy | Select-Object MinPasswordLength",
        "confirm": "A value below <strong>14</strong> confirms the finding.",
    },
    {
        "tool": "net accounts",
        "icon": "cmd",
        "desc": "Run from any domain-joined Windows host.",
        "code": "net accounts /domain",
        "confirm": "Check the <strong>Minimum password length</strong> row.",
    },
    {
        "tool": "GPMC (gpmc.msc)",
        "icon": "aduc",
        "desc": "Inspect the Default Domain Policy GPO for password settings.",
        "steps": [
            "Open <code>gpmc.msc</code> → Default Domain Policy → Edit",
            "Computer Configuration → Policies → Windows Settings → Security Settings → Account Policies → Password Policy",
            "Check <strong>Minimum password length</strong>.",
        ],
    },
]

REMEDIATION = {
    "title": "Set minimum password length to 14+ characters",
    "steps": [
        {
            "text": "Update via PowerShell:",
            "code": "Set-ADDefaultDomainPasswordPolicy -Identity <domain.fqdn> -MinPasswordLength 14",
        },
        {
            "text": "Enforce via Group Policy under <em>Default Domain Policy → Password Policy</em>.",
        },
        {
            "text": "Use <strong>Fine-Grained Password Policies (PSOs)</strong> to enforce stricter lengths for privileged accounts.",
        },
    ],
}


REFERENCES = [
    {"title": "Password Policy Settings - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/minimum-password-length", "tag": "vendor"},
    {"title": "NIST SP 800-63B: Digital Identity Guidelines", "url": "https://pages.nist.gov/800-63-3/sp800-63b.html", "tag": "vendor"},
    {"title": "MITRE ATT&CK: Brute Force (T1110)", "url": "https://attack.mitre.org/techniques/T1110/", "tag": "attack"},
    {"title": "MITRE ATT&CK: Password Spraying (T1110.003)", "url": "https://attack.mitre.org/techniques/T1110/003/", "tag": "attack"},
    {"title": "Sprayhound - Password Spraying Tool", "url": "https://github.com/Hackndo/sprayhound", "tag": "tool"},
    {"title": "CIS Benchmark: Minimum Password Length >= 14", "url": "https://www.cisecurity.org/benchmark/microsoft_windows_server", "tag": "defense"},
    {"title": "ACSC Password Policy Guidance", "url": "https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/ism/cyber-security-guidelines/guidelines-authentication", "tag": "defense"},
    {"title": "Have I Been Pwned - Password Exposure Research", "url": "https://haveibeenpwned.com/Passwords", "tag": "research"},
]
