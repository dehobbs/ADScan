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
