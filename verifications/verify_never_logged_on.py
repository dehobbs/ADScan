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
