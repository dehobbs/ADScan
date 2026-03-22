"""
verifications/verify_esc10.py
Manual Verification and Remediation data for ADScan findings matching: ESC10
"""

MATCH_KEYS = ["esc10"]

TOOLS = [
    {
        "tool": "PowerShell",
        "icon": "ps",
        "desc": "Check the StrongCertificateBindingEnforcement registry value on Domain Controllers.",
        "code": "Invoke-Command -ComputerName <DC_FQDN> -ScriptBlock {\n    Get-ItemProperty -Path \"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Kdc\" `\n        -Name StrongCertificateBindingEnforcement -ErrorAction SilentlyContinue\n}",
        "confirm": "A value of <strong>0</strong> (disabled) or <strong>1</strong> (compatibility mode) confirms the finding. A value of <strong>2</strong> means full enforcement is in place.",
    },
    {
        "tool": "certutil",
        "icon": "cmd",
        "desc": "Verify certificate mapping configuration on the CA.",
        "code": "certutil -config <CA> -getreg CA\\CRLFlags",
        "confirm": "Review output for weak mapping flags. Run from an elevated command prompt on a domain-joined host.",
    },
]

REMEDIATION = {
    "title": "Enforce strong certificate-to-account mapping (KB5014754)",
    "steps": [
        {
            "text": "Set <strong>StrongCertificateBindingEnforcement = 2</strong> (Full Enforcement) on all Domain Controllers:",
            "code": "reg add \"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Kdc\" /v StrongCertificateBindingEnforcement /t REG_DWORD /d 2 /f",
        },
        {
            "text": "Apply Microsoft KB5014754 on all Domain Controllers to ensure the registry key is recognised and enforced.",
        },
        {
            "text": "If moving directly to Full Enforcement (2) causes authentication failures, temporarily set to <strong>1</strong> (Compatibility Mode) and review the event log (Event ID 39, 40, 41 in System log) before moving to 2.",
        },
    ],
}


REFERENCES = [
    {"title": "AD CS ESC10 - Weak Certificate Mappings - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-certificate-requirements-and-enumeration", "tag": "vendor"},
    {"title": "KB5014754 - Certificate-Based Authentication Changes", "url": "https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16", "tag": "vendor"},
    {"title": "MITRE ATT&CK: Steal or Forge Authentication Certificates (T1649)", "url": "https://attack.mitre.org/techniques/T1649/", "tag": "attack"},
    {"title": "ESC10 - Certipy Research (ly4k)", "url": "https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7", "tag": "research"},
    {"title": "Certipy - ESC10 Exploitation", "url": "https://github.com/ly4k/Certipy", "tag": "tool"},
    {"title": "Microsoft Security Advisory: KB5014754 Enforcement Mode", "url": "https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16", "tag": "defense"},
    {"title": "Hardening Certificate Mappings in AD CS", "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts", "tag": "defense"},
]
