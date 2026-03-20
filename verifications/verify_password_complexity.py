"""
verifications/verify_password_complexity.py
Manual Verification and Remediation data for ADScan findings matching: password complexity
"""

MATCH_KEYS = ["password complexity"]

TOOLS = [
    {
        "tool": "NetExec",
        "icon": "netexec",
        "desc": "Retrieve full password policy including complexity flag from any authenticated host.",
        "code": "netexec smb <DC_IP> -u <username> -p <password> --pass-pol",
        "confirm": "Look for <strong>Password Complexity: Disabled</strong> in the output.",
    },
    {
        "tool": "net accounts",
        "icon": "cmd",
        "desc": "Quick check from any domain-joined Windows machine.",
        "code": "net accounts /domain",
        "confirm": "Run from a DC and check <strong>Password Complexity</strong> in Group Policy.",
    },
    {
        "tool": "PowerShell",
        "icon": "ps",
        "desc": "Query the default domain password policy object directly.",
        "code": "Get-ADDefaultDomainPasswordPolicy `\n    | Select-Object ComplexityEnabled,MinPasswordLength,MaxPasswordAge",
        "confirm": "<strong>ComplexityEnabled: False</strong> confirms the finding.",
    },
    {
        "tool": "ADUC (dsa.msc)",
        "icon": "aduc",
        "desc": "Navigate to the Default Domain Policy GPO and inspect Account Policies.",
        "steps": [
            "Open <code>gpmc.msc</code>",
            "Navigate to <em>Default Domain Policy</em> → Edit",
            "Computer Configuration → Policies → Windows Settings → Security Settings → Account Policies → Password Policy",
            "<strong>Password must meet complexity requirements: Disabled</strong> confirms the finding.",
        ],
    },
]

REMEDIATION = {
    "title": "Enable password complexity and set minimum length ≥ 14",
    "steps": [
        {
            "text": "Enable complexity and set minimum length via PowerShell:",
            "code": "Set-ADDefaultDomainPasswordPolicy `\n    -Identity <domain.fqdn> `\n    -ComplexityEnabled $true `\n    -MinPasswordLength 14",
        },
        {
            "text": "Alternatively configure via <code>gpedit.msc</code> under <em>Default Domain Policy → Password Policy</em>.",
        },
        {
            "text": "Consider deploying a <strong>passphrase policy</strong> (e.g. 3-word phrases, min 20 chars) for better usability and security.",
        },
    ],
}
