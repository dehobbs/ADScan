"""
verifications/verify_minimum_password_age.py
Manual Verification and Remediation data for ADScan findings matching: minimum password age
"""

MATCH_KEYS = ["minimum password age"]

TOOLS = [
    {
        "tool": "PowerShell",
        "icon": "ps",
        "desc": "Query the minimum password age from the default domain password policy.",
        "code": "Get-ADDefaultDomainPasswordPolicy | Select-Object MinPasswordAge",
        "confirm": "A value of <strong>00:00:00</strong> (zero days) confirms the finding.",
    },
    {
        "tool": "net accounts",
        "icon": "cmd",
        "desc": "Run from any domain-joined Windows host.",
        "code": "net accounts /domain",
        "confirm": "Check the <strong>Minimum password age (days)</strong> row — a value of <strong>0</strong> confirms the finding.",
    },
    {
        "tool": "NetExec",
        "icon": "netexec",
        "desc": "Enumerate the full password policy remotely, including minimum password age.",
        "code": "netexec smb <DC_IP> -u <username> -p <password> --pass-pol",
        "confirm": "Look for <strong>Minimum password age</strong> in the output — a value of <strong>0 days</strong> confirms the finding.",
    },
    {
        "tool": "GPMC (gpmc.msc)",
        "icon": "aduc",
        "desc": "Inspect the Default Domain Policy GPO for password age settings.",
        "steps": [
            "Open <code>gpmc.msc</code> → Default Domain Policy → Edit",
            "Navigate to: Computer Configuration → Policies → Windows Settings → Security Settings → Account Policies → Password Policy",
            "Check <strong>Minimum password age</strong> — a value of <strong>0 days</strong> confirms the finding.",
        ],
    },
]

REMEDIATION = {
    "title": "Set minimum password age to at least 1 day",
    "steps": [
        {
            "text": "Apply via PowerShell on a domain controller or from a host with RSAT:",
            "code": "Set-ADDefaultDomainPasswordPolicy -Identity <domain.fqdn> -MinPasswordAge 1.00:00:00",
        },
        {
            "text": "Or configure via Group Policy Editor under <em>Default Domain Policy → Account Policies → Password Policy → Minimum password age</em> and set to <strong>1 day</strong>.",
        },
        {
            "text": "For privileged accounts, consider using <strong>Fine-Grained Password Policies (PSOs)</strong> to enforce stricter minimum ages independent of the default domain policy.",
        },
    ],
}

REFERENCES = [
    {"title": "Minimum Password Age - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/minimum-password-age", "tag": "vendor"},
    {"title": "Password Policy Best Practices - Microsoft", "url": "https://learn.microsoft.com/en-us/microsoft-365/admin/misc/password-policy-recommendations", "tag": "vendor"},
    {"title": "CIS Benchmark: Minimum Password Age >= 1", "url": "https://www.cisecurity.org/benchmark/microsoft_windows_server", "tag": "defense"},
    {"title": "MITRE ATT&CK: Account Manipulation (T1098)", "url": "https://attack.mitre.org/techniques/T1098/", "tag": "attack"},
    {"title": "Fine-Grained Password Policies - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/introduction-to-active-directory-administrative-center-enhancements--level-100-#fine_grained_pswd_policy_mgmt", "tag": "vendor"},
]
