"""
verifications/verify_esc15.py
Manual Verification and Remediation data for ADScan findings matching: ESC15
"""

MATCH_KEYS = ["esc15"]

TOOLS = [
    {
        "tool": "PowerShell",
        "icon": "ps",
        "desc": "Identify Schema Version 1 certificate templates with client authentication EKUs.",
        "code": "Get-ADObject -SearchBase \"CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<tld>\" \`\n    -Filter * -Properties msPKI-Template-Schema-Version,pKIExtendedKeyUsage,msPKI-Certificate-Name-Flag \`\n    | Where-Object { $_.'msPKI-Template-Schema-Version' -eq 1 } \`\n    | Select-Object Name,'msPKI-Template-Schema-Version',pKIExtendedKeyUsage",
        "confirm": "Templates with schema version <strong>1</strong> and client authentication EKU (<code>1.3.6.1.5.5.7.3.2</code>) are potentially affected.",
    },
    {
        "tool": "certutil",
        "icon": "cmd",
        "desc": "List templates and their schema versions from the CA.",
        "code": "certutil -catemplates -v",
        "confirm": "Look for templates marked as Schema Version 1 with client auth capability. Run from a domain-joined host.",
    },
]

REMEDIATION = {
    "title": "Migrate Schema V1 templates and enforce strong certificate binding",
    "steps": [
        {
            "text": "Migrate affected templates from Schema Version 1 to <strong>Version 4</strong> using Certificate Template Manager (<code>certtmpl.msc</code>): duplicate the template and set the compatibility level to Windows Server 2012 or later.",
        },
        {
            "text": "Enforce <strong>StrongCertificateBindingEnforcement = 2</strong> on all Domain Controllers per KB5014754:",
            "code": "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Kdc\" /v StrongCertificateBindingEnforcement /t REG_DWORD /d 2 /f",
        },
        {
            "text": "If V1 templates cannot be migrated immediately, restrict enrollment rights to the minimum required set of accounts and enable CA Manager Approval.",
        },
    ],
}
