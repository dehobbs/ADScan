"""
verifications/verify_account_lockout.py
Manual Verification and Remediation data for ADScan findings matching: account lockout
"""

MATCH_KEYS = ["account lockout"]

TOOLS = [
    {
        "tool": "NetExec",
        "icon": "netexec",
        "desc": "Query the password policy remotely from any machine with a valid domain account.",
        "code": "netexec smb <DC_IP> \\\n    -u <username> \\\n    -p <password> \\\n    --pass-pol",
        "confirm": "Look for <strong>Account Lockout Threshold: None</strong> or <strong>0</strong> in the output.",
    },
    {
        "tool": "net accounts",
        "icon": "cmd",
        "desc": "Run from any domain-joined Windows host. No special privileges needed beyond a standard domain account.",
        "code": "net accounts /domain",
        "confirm": "A value of <strong>Never</strong> or <strong>0</strong> next to <em>Lockout threshold</em> confirms the finding.",
    },
    {
        "tool": "GPMC (gpmc.msc)",
        "icon": "aduc",
        "desc": "GUI method via Group Policy Management Console on a domain-joined machine with RSAT installed.",
        "steps": [
            "Open <code>gpmc.msc</code>",
            "Expand <em>Forest → Domains → &lt;domain&gt; → Group Policy Objects</em>",
            "Right-click <em>Default Domain Policy</em> → <em>Edit</em>",
            "Navigate to: <code>Computer Configuration → Policies → Windows Settings → Security Settings → Account Policies → Account Lockout Policy</code>",
            "<em>Account lockout threshold</em> = <strong>0</strong> confirms the finding.",
        ],
    },
    {
        "tool": "PowerShell",
        "icon": "ps",
        "desc": "Run from a domain-joined host with the ActiveDirectory module available.",
        "code": "Get-ADDefaultDomainPasswordPolicy `\n    | Select-Object LockoutThreshold,\n        LockoutDuration,\n        LockoutObservationWindow",
        "confirm": "A <strong>LockoutThreshold</strong> of <strong>0</strong> confirms no lockout policy is in effect.",
    },
]

REMEDIATION = {
    "title": "Set lockout threshold to 5–10 attempts",
    "steps": [
        {
            "text": "Apply via PowerShell on the domain controller:",
            "code": "Set-ADDefaultDomainPasswordPolicy `\n    -Identity <domain.fqdn> `\n    -LockoutThreshold 5 `\n    -LockoutDuration 00:30:00 `\n    -LockoutObservationWindow 00:30:00",
        },
        {
            "text": "Or apply via Group Policy Editor (<code>gpedit.msc</code>) on the Domain Controller under <em>Default Domain Policy</em> at the path shown in the ADUC step above.",
        },
        {
            "text": "For privileged accounts requiring a stricter policy, use <strong>Fine-Grained Password Policies (PSOs)</strong> to apply a lower threshold (e.g. 3 attempts) to Domain Admins without affecting all users.",
        },
    ],
}


REFERENCES = [
    {"title": "Account Lockout Policy - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-policy", "tag": "vendor"},
    {"title": "Account Lockout Threshold - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-threshold", "tag": "vendor"},
    {"title": "MITRE ATT&CK: Brute Force - Password Spraying (T1110.003)", "url": "https://attack.mitre.org/techniques/T1110/003/", "tag": "attack"},
    {"title": "Sprayhound - AD Password Spray Tool", "url": "https://github.com/Hackndo/sprayhound", "tag": "tool"},
    {"title": "Kerbrute - Username and Password Spraying", "url": "https://github.com/ropnop/kerbrute", "tag": "tool"},
    {"title": "CIS Benchmark: Account Lockout Policy", "url": "https://www.cisecurity.org/benchmark/microsoft_windows_server", "tag": "defense"},
    {"title": "Fine-Grained Password Policies - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/introduction-to-active-directory-administrative-center-enhancements--level-100-#fine_grained_pswd_policy_mgmt", "tag": "vendor"},
    {"title": "Detecting Password Spraying - Defender for Identity", "url": "https://learn.microsoft.com/en-us/defender-for-identity/compromised-credentials-alerts#suspected-brute-force-attack-ldap-external-id-2004", "tag": "defense"},
]
