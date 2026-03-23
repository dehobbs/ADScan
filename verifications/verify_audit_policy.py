"""
verifications/verify_audit_policy.py
Manual verification, remediation, and references for audit policy findings.
"""

MATCH_KEYS = [
    "audit policy",
    "audit logging",
    "advanced audit",
    "event logging",
    "auditpol",
]

TOOLS = [
    {
        "tool": "cmd (auditpol)",
        "icon": "cmd",
        "desc": "Review the effective audit policy on a Domain Controller.",
        "code": (            "# Run on the DC:\n"            "auditpol /get /category:*\n"            "\n"            "# Key categories to check:\n"            "auditpol /get /subcategory:\n"            "  \"Account Logon\",\"Account Management\",\n"            "  \"Directory Service Access\",\"Logon/Logoff\",\n"            "  \"Object Access\",\"Privilege Use\",\n"            "  \"Policy Change\",\"System\""
        ),
        "confirm": "Critical subcategories (Logon/Logoff, Directory Service Changes, Account Management) should show Success and Failure auditing.",
    },
    {
        "tool": "PowerShell (Group Policy module)",
        "icon": "ps",
        "desc": "Check the audit policy applied via GPO to Domain Controllers.",
        "code": (            "# List audit settings from the Default Domain Controllers Policy:\n"            "Get-GPO -Name 'Default Domain Controllers Policy' |\n"            "  Get-GPOReport -ReportType Xml |\n"            "  Select-String 'Audit'"
        ),
        "confirm": "The report should show Success and Failure for Account Logon, Account Management, Directory Service Access, Logon, Object Access, and Policy Change.",
    },
]

REMEDIATION = {
    "title": "Enable comprehensive Advanced Audit Policy on all Domain Controllers",
    "steps": [
        {
            "text": "Enable Advanced Audit Policy via GPO on the Default Domain Controllers Policy: Computer Configuration → Windows Settings → Security Settings → Advanced Audit Policy Configuration. Enable the following subcategories for both Success and Failure:",
            "steps": [
                "Account Logon: Credential Validation, Kerberos Authentication Service",
                "Account Management: User Account Management, Security Group Management",
                "Directory Service: Directory Service Access, Directory Service Changes",
                "Logon/Logoff: Logon, Logoff, Account Lockout",
                "Object Access: Certification Services (if ADCS is present)",
                "Policy Change: Authentication Policy Change, Audit Policy Change",
                "Privilege Use: Sensitive Privilege Use",
            ],
        },
        {
            "text": "Increase the Security event log maximum size on DCs to at least 1 GB to avoid overwriting critical events:",
            "code": "wevtutil sl Security /ms:1073741824",
        },
        {
            "text": "Forward DC Security logs to a SIEM or centralised log management solution for long-term retention and alerting.",
        },
    ],
}

REFERENCES = [
    {
        "title": "Microsoft — Advanced Security Audit Policy Settings",
        "url": "https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings",
        "tag": "vendor",
    },
    {
        "title": "CIS Benchmark — Windows Server 2022 Audit Policy",
        "url": "https://www.cisecurity.org/benchmark/microsoft_windows_server",
        "tag": "defense",
    },
    {
        "title": "MITRE ATT&CK — Impair Defenses: Disable Windows Event Logging (T1562.002)",
        "url": "https://attack.mitre.org/techniques/T1562/002/",
        "tag": "attack",
    },
    {
        "title": "NSA — Spotting the Adversary with Windows Event Log Monitoring",
        "url": "https://apps.nsa.gov/iaarchive/library/ia-guidance/security-configuration/operating-systems/spotting-the-adversary-with-windows-event-log-monitoring.cfm",
        "tag": "defense",
    },
]
