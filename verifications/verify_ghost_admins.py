"""
verifications/verify_ghost_admins.py
Manual Verification and Remediation data for ADScan findings matching:
ghost admin accounts / stale protected admin accounts / orphaned admincount
"""

MATCH_KEYS = [
    "ghost admin",
    "stale protected admin",
    "orphaned admincount",
    "orphaned admin",
    "disabled account(s) with admincount",
]

TOOLS = [
    {
        "tool": "PowerShell",
        "icon": "ps",
        "desc": "Find disabled accounts that still have adminCount=1 (ghost admins).",
        "code": "Get-ADUser -Filter {adminCount -eq 1 -and Enabled -eq $false} \\\n    -Properties adminCount, MemberOf, LastLogonDate \\\n    | Select-Object Name, SamAccountName, Enabled, adminCount, LastLogonDate",
        "confirm": "Each disabled account with adminCount=1 retains ACL protections from AdminSDHolder and is an invisible attack surface — if re-enabled, it regains full privileges.",
    },
    {
        "tool": "PowerShell (stale active)",
        "icon": "ps",
        "desc": "Find enabled accounts with adminCount=1 that are no longer in any privileged group.",
        "code": "$privilegedGroups = @('Domain Admins','Enterprise Admins','Schema Admins','Account Operators','Backup Operators','Print Operators','Server Operators','Group Policy Creator Owners')\nGet-ADUser -Filter {adminCount -eq 1 -and Enabled -eq $true} -Properties adminCount, MemberOf |\n    Where-Object {\n        $memberOf = $_.MemberOf | ForEach-Object { (Get-ADGroup $_).Name }\n        -not ($memberOf | Where-Object { $privilegedGroups -contains $_ })\n    } | Select-Object Name, SamAccountName",
        "confirm": "These accounts have lingering adminCount=1 from a previous privileged group membership — they still have AdminSDHolder ACL protections applied but serve no legitimate purpose.",
    },
    {
        "tool": "BloodHound",
        "icon": "netexec",
        "desc": "Identify ghost/orphaned admin accounts with lingering privilege paths.",
        "code": "# After ingesting with SharpHound/BloodHound.py:\n# Search: MATCH (u:User {admincount:true, enabled:false}) RETURN u",
        "confirm": "Accounts flagged by BloodHound as <code>admincount:true</code> with <code>enabled:false</code> confirm the finding.",
    },
    {
        "tool": "ADUC (dsa.msc)",
        "icon": "aduc",
        "desc": "Manually inspect adminCount and group membership in ADUC.",
        "steps": [
            "Open <code>dsa.msc</code> → View → Advanced Features",
            "Locate the account → Properties → Attribute Editor",
            "Confirm <strong>adminCount</strong> = 1",
            "Check <strong>Member Of</strong> tab — verify the account is not in any privileged groups",
            "Check <strong>Account</strong> tab — confirm the account is disabled",
        ],
    },
]

REMEDIATION = {
    "title": "Clear adminCount and delete or quarantine ghost admin accounts",
    "steps": [
        {
            "text": "<strong>For disabled ghost admins</strong> — after confirming they are not needed, clear adminCount and delete or permanently disable with a descriptive name:",
            "code": "# Clear adminCount (removes AdminSDHolder ACL protection):\nSet-ADUser -Identity <username> -Replace @{adminCount=0}\n\n# Then remove from all groups and delete or move to quarantine OU:\nRemove-ADUser -Identity <username>",
        },
        {
            "text": "<strong>For enabled orphaned accounts</strong> (adminCount=1 but not in any privileged group) — clear adminCount and force an SDProp run to restore normal ACLs:",
            "code": "Set-ADUser -Identity <username> -Replace @{adminCount=0}\n\n# Force SDProp to run immediately (normally runs every 60 min):\n$domain = [ADSI]'LDAP://rootDSE'\n$domain.Put('runProtectAdminGroupsTask', 1)\n$domain.SetInfo()",
        },
        {
            "text": "Review the <strong>AdminSDHolder ACL</strong> itself for any unexpected principals — ghost admin accounts that were exploited may have written additional backdoor ACEs there.",
        },
    ],
}

REFERENCES = [
    {"title": "AdminSDHolder, Protected Groups and SDPROP - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory", "tag": "vendor"},
    {"title": "MITRE ATT&CK: Valid Accounts - Domain Accounts (T1078.002)", "url": "https://attack.mitre.org/techniques/T1078/002/", "tag": "attack"},
    {"title": "Sneaky Active Directory Persistence - AdminSDHolder Abuse", "url": "https://adsecurity.org/?p=1906", "tag": "research"},
    {"title": "Ghost Admin Accounts - Active Directory Security", "url": "https://adsecurity.org/?p=2142", "tag": "research"},
    {"title": "BloodHound - Visualizing AD Attack Paths", "url": "https://github.com/BloodHoundAD/BloodHound", "tag": "tool"},
    {"title": "CIS Benchmark: Remove inactive accounts from privileged groups", "url": "https://www.cisecurity.org/benchmark/microsoft_windows_server", "tag": "defense"},
]
