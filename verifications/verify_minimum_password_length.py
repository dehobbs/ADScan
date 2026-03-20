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
