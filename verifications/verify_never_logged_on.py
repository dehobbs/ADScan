"""
verifications/verify_never_logged_on.py
Manual Verification and Remediation data for ADScan findings matching: Never Logged On
"""

MATCH_KEYS = ["never logged on"]

TOOLS = [
    {
        "tool": "PowerShell",
        "icon": "ps",
        "desc": "List all enabled user accounts that have never logged on (lastLogonTimestamp is null).",
        "code": "Get-ADUser -Filter {Enabled -eq $true} -Properties lastLogonTimestamp,whenCreated \`\n    | Where-Object { $_.lastLogonTimestamp -eq $null } \`\n    | Select-Object Name,SamAccountName,whenCreated \`\n    | Sort-Object whenCreated",
        "confirm": "Accounts returned have never authenticated to the domain. Cross-reference against HR records to determine if they are legitimate stale accounts.",
    },
]

REMEDIATION = {
    "title": "Disable or remove accounts that have never logged on",
    "steps": [
        {
            "text": "Validate with HR or the account owner whether each account is required. Accounts created but never used are prime targets for abuse.",
        },
        {
            "text": "Disable accounts that are confirmed unused:",
            "code": "Disable-ADAccount -Identity <SamAccountName>",
        },
        {
            "text": "After a quarantine period (e.g. 30 days), remove accounts that remain unused:",
            "code": "Remove-ADUser -Identity <SamAccountName>",
        },
        {
            "text": "Implement a joiners/movers/leavers process to ensure accounts are only created when needed and are disabled/removed when no longer required.",
        },
    ],
}


REFERENCES = [
    {"title": "lastLogon vs lastLogonTimestamp - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/windows/win32/adschema/a-lastlogontimestamp", "tag": "vendor"},
    {"title": "Managing Stale AD Objects - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/find-inactive-user-and-computer-accounts", "tag": "vendor"},
    {"title": "MITRE ATT&CK: Valid Accounts (T1078)", "url": "https://attack.mitre.org/techniques/T1078/", "tag": "attack"},
    {"title": "MITRE ATT&CK: Domain Accounts (T1078.002)", "url": "https://attack.mitre.org/techniques/T1078/002/", "tag": "attack"},
    {"title": "BloodHound - Stale Account Discovery", "url": "https://github.com/BloodHoundAD/BloodHound", "tag": "tool"},
    {"title": "CIS Benchmark: Disable or remove inactive accounts", "url": "https://www.cisecurity.org/benchmark/microsoft_windows_server", "tag": "defense"},
    {"title": "ACSC Essential Eight - User Application Hardening", "url": "https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight", "tag": "defense"},
    {"title": "Stale AD Accounts as Attack Surface - Active Directory Security", "url": "https://adsecurity.org/?p=1186", "tag": "research"},
]
