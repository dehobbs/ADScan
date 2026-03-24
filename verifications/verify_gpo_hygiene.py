"""
verifications/verify_gpo_hygiene.py
Manual Verification and Remediation data for ADScan findings matching:
disabled group policy objects / empty group policy objects / excessive gpo count
"""

MATCH_KEYS = [
    "disabled group policy",
    "empty group policy",
    "excessive gpo",
    "unlinked group policy objects",
]

TOOLS = [
    {
        "tool": "PowerShell (disabled GPOs)",
        "icon": "ps",
        "desc": "List all GPOs that are fully disabled (both user and computer settings disabled).",
        "code": "Import-Module GroupPolicy\nGet-GPO -All | Where-Object {\n    $_.GpoStatus -eq 'AllSettingsDisabled'\n} | Select-Object DisplayName, GpoStatus, CreationTime, ModificationTime",
        "confirm": "Each GPO with <strong>AllSettingsDisabled</strong> applies no policy — it is waste and attack surface (adversaries can re-enable it or clone it with malicious settings).",
    },
    {
        "tool": "PowerShell (empty GPOs)",
        "icon": "ps",
        "desc": "Find GPOs that exist but contain no configured settings.",
        "code": "Import-Module GroupPolicy\nGet-GPO -All | ForEach-Object {\n    $report = Get-GPOReport -Guid $_.Id -ReportType Xml\n    $xml = [xml]$report\n    $userSettings = $xml.GPO.User.ExtensionData\n    $computerSettings = $xml.GPO.Computer.ExtensionData\n    if (-not $userSettings -and -not $computerSettings) {\n        $_ | Select-Object DisplayName, CreationTime, ModificationTime\n    }\n}",
        "confirm": "GPOs with no extension data contain no policy settings — they add processing overhead to every Group Policy refresh with no benefit.",
    },
    {
        "tool": "PowerShell (GPO count)",
        "icon": "ps",
        "desc": "Count total GPOs and identify potential bloat.",
        "code": "$all = Get-GPO -All\nWrite-Host \"Total GPOs: $($all.Count)\"\n$all | Group-Object GpoStatus | Select-Object Name, Count",
        "confirm": "Environments with more than ~50 GPOs should be reviewed for consolidation opportunities. Very high counts slow Group Policy processing and increase complexity.",
    },
    {
        "tool": "GPMC (gpmc.msc)",
        "icon": "aduc",
        "desc": "Review and manage GPOs in the Group Policy Management Console.",
        "steps": [
            "Open <code>gpmc.msc</code>",
            "Expand <strong>Group Policy Objects</strong> to see all GPOs",
            "Sort by <strong>Status</strong> to identify disabled GPOs",
            "Click each GPO → <strong>Settings</strong> tab → if the report shows no configured settings, the GPO is empty",
            "Check the <strong>Scope</strong> tab — GPOs with no links are unlinked and apply to nothing",
        ],
    },
]

REMEDIATION = {
    "title": "Remove disabled, empty, and redundant GPOs",
    "steps": [
        {
            "text": "<strong>Disabled GPOs</strong> — verify they serve no purpose, then delete. Use GPMC or PowerShell:",
            "code": "# Delete a single GPO by name:\nRemove-GPO -Name '<GPO Name>'\n\n# Bulk delete all fully-disabled GPOs (review output first!):\nGet-GPO -All | Where-Object { $_.GpoStatus -eq 'AllSettingsDisabled' } |\n    ForEach-Object { Remove-GPO -Name $_.DisplayName -WhatIf }",
        },
        {
            "text": "<strong>Empty GPOs</strong> — either delete or populate with intended settings. Do not leave empty GPOs linked to OUs as they still incur processing overhead.",
        },
        {
            "text": "<strong>Excessive GPO count</strong> — audit for redundant or overlapping policies. Consolidate related settings into fewer GPOs. Use the <strong>Group Policy Modeling</strong> wizard in GPMC to simulate resultant policy before and after changes.",
        },
        {
            "text": "Before deleting any GPO, back it up:",
            "code": "Backup-GPO -Name '<GPO Name>' -Path 'C:\\GPOBackups'\n# Or back up all GPOs:\nBackup-GPO -All -Path 'C:\\GPOBackups'",
        },
    ],
}

REFERENCES = [
    {"title": "Group Policy Overview - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-policy/group-policy-overview", "tag": "vendor"},
    {"title": "Back Up and Restore Group Policy Objects - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/jj717304(v=ws.11)", "tag": "vendor"},
    {"title": "MITRE ATT&CK: Group Policy Modification (T1484.001)", "url": "https://attack.mitre.org/techniques/T1484/001/", "tag": "attack"},
    {"title": "CIS Benchmark: Manage and audit Group Policy Objects", "url": "https://www.cisecurity.org/benchmark/microsoft_windows_server", "tag": "defense"},
    {"title": "Group Policy Best Practices - Microsoft TechNet", "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-policy/group-policy-overview", "tag": "defense"},
]
