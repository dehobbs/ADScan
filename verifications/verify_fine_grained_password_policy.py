"""
verifications/verify_fine_grained_password_policy.py
Manual Verification and Remediation data for ADScan findings matching:
weak Fine-Grained Password Policy (PSO)
"""

MATCH_KEYS = ["fine-grained password policy"]

TOOLS = [
    {
        "tool": "PowerShell",
        "icon": "ps",
        "desc": "List every Fine-Grained Password Policy and its key settings. <strong>Run PowerShell as Administrator</strong> on a host with the RSAT ActiveDirectory module installed.",
        "code": "Get-ADFineGrainedPasswordPolicy -Filter * | Select-Object Name, Precedence, MinPasswordLength, ComplexityEnabled, LockoutThreshold, MaxPasswordAge, ReversibleEncryptionEnabled",
        "confirm": "Compare each PSO against the Default Domain Policy — any weaker value confirms the finding.",
    },
    {
        "tool": "PowerShell",
        "icon": "ps",
        "desc": "Show which users / groups a specific PSO is applied to. <strong>Run PowerShell as Administrator</strong> on a host with the RSAT ActiveDirectory module installed.",
        "code": "Get-ADFineGrainedPasswordPolicy -Identity '<PSO_NAME>' | Select-Object -ExpandProperty AppliesTo",
        "confirm": "A PSO linked to a privileged group (e.g. Domain Admins) is the highest risk.",
    },
    {
        "tool": "NetExec",
        "icon": "netexec",
        "desc": "PSOs are LDAP objects readable by any authenticated user — enumerate them remotely.",
        "code": "nxc ldap <DC_IP> -u <username> -p <password> --query \"(objectClass=msDS-PasswordSettings)\" \"msDS-MinimumPasswordLength msDS-LockoutThreshold msDS-PSOAppliesTo\"",
        "confirm": "Review returned PSO objects for weak length / lockout values.",
    },
    {
        "tool": "ADAC (dsac.exe)",
        "icon": "aduc",
        "desc": "Inspect PSOs in the Active Directory Administrative Center GUI.",
        "steps": [
            "Open <code>dsac.exe</code> (Active Directory Administrative Center).",
            "Navigate to <strong>System → Password Settings Container</strong>.",
            "Open each Password Settings object and review its values and 'Directly Applies To' list.",
        ],
    },
]

REMEDIATION = {
    "title": "Harden or remove the weak Fine-Grained Password Policy",
    "steps": [
        {
            "text": "Bring the PSO up to (or above) the Default Domain Policy baseline:",
            "code": "Set-ADFineGrainedPasswordPolicy -Identity '<PSO_NAME>' -MinPasswordLength 15 -ComplexityEnabled $true -LockoutThreshold 5 -LockoutObservationWindow 00:30:00 -ReversibleEncryptionEnabled $false",
        },
        {
            "text": "If the PSO exists only to exempt accounts from domain-wide requirements, remove it:",
            "code": "Remove-ADFineGrainedPasswordPolicy -Identity '<PSO_NAME>'",
        },
        {
            "text": "If privileged accounts need a <em>stricter</em> policy, create a dedicated PSO with a lower precedence (wins over others) and link it to Tier-0 groups.",
        },
        {
            "text": "Re-run the password-policy and PSO checks to confirm no PSO is weaker than the default domain policy.",
        },
    ],
}

REFERENCES = [
    {"title": "AD DS Fine-Grained Password Policies - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/introduction-to-active-directory-administrative-center-enhancements--level-100-#fine_grained_pswd_policy_mgmt", "tag": "vendor"},
    {"title": "msDS-PasswordSettings object class - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/windows/win32/adschema/c-msds-passwordsettings", "tag": "vendor"},
    {"title": "MITRE ATT&CK: Brute Force (T1110)", "url": "https://attack.mitre.org/techniques/T1110/", "tag": "attack"},
    {"title": "MITRE ATT&CK: Password Spraying (T1110.003)", "url": "https://attack.mitre.org/techniques/T1110/003/", "tag": "attack"},
    {"title": "CIS Microsoft Windows Server Benchmark", "url": "https://www.cisecurity.org/benchmark/microsoft_windows_server", "tag": "defense"},
]
