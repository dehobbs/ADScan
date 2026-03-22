"""
verifications/verify_orphaned_admincount.py
Manual Verification and Remediation data for ADScan findings matching: Orphaned adminCount
"""

MATCH_KEYS = ["orphaned admincount"]

TOOLS = [
    {
        "tool": "PowerShell",
        "icon": "ps",
        "desc": "Find user accounts with adminCount=1 that are no longer members of any privileged group.",
        "code": "# Get all privileged group members\n$privGroups = @(\"Domain Admins\",\"Enterprise Admins\",\"Schema Admins\",\"Administrators\",\"Account Operators\",\"Backup Operators\",\"Server Operators\",\"Print Operators\")\n$privMembers = $privGroups | ForEach-Object { Get-ADGroupMember -Identity $_ -Recursive } | Select-Object -ExpandProperty SamAccountName -Unique\n\n# Find accounts with adminCount=1 not in any privileged group\nGet-ADUser -Filter {adminCount -eq 1} -Properties adminCount,memberOf \`\n    | Where-Object { $_.SamAccountName -notin $privMembers } \`\n    | Select-Object Name,SamAccountName,Enabled",
        "confirm": "Accounts returned have <strong>adminCount=1</strong> set but are not members of any privileged group. This means SDProp is applying over-restrictive ACLs to accounts that no longer need them.",
    },
]

REMEDIATION = {
    "title": "Clear adminCount on accounts no longer in privileged groups",
    "steps": [
        {
            "text": "For each orphaned account identified above, clear the <strong>adminCount</strong> attribute:",
            "code": "Set-ADUser -Identity <SamAccountName> -Clear adminCount",
        },
        {
            "text": "Also restore the <strong>Protect object from accidental deletion</strong> and correct <strong>ACL inheritance</strong> on the account, as SDProp will have broken inheritance:",
            "code": "# Re-enable ACL inheritance via PowerShell (requires ActiveDirectory and ADSI):\n$user = [ADSI]\"LDAP://CN=<user>,OU=...,DC=...\"\n$acl = $user.psbase.ObjectSecurity\n$acl.SetAccessRuleProtection($false, $true)\n$user.psbase.CommitChanges()",
        },
        {
            "text": "Run SDProp manually to force propagation after clearing adminCount:",
            "code": "# Trigger SDProp immediately via ldp.exe or by modifying fixupinheritance on the AdminSDHolder container.\n# Or wait up to 60 minutes for the next automatic SDProp run.",
        },
        {
            "text": "Investigate how these accounts were granted privileged group membership in the past and ensure appropriate deprovisioning processes are in place.",
        },
    ],
}


REFERENCES = [
    {"title": "AdminSDHolder and SDProp - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory", "tag": "vendor"},
    {"title": "AdminCount Attribute - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/windows/win32/adschema/a-admincount", "tag": "vendor"},
    {"title": "MITRE ATT&CK: Valid Accounts - Domain Accounts (T1078.002)", "url": "https://attack.mitre.org/techniques/T1078/002/", "tag": "attack"},
    {"title": "AdminCount Persistence Abuse - Active Directory Security", "url": "https://adsecurity.org/?p=2011", "tag": "attack"},
    {"title": "BloodHound - Privileged Account Analysis", "url": "https://github.com/BloodHoundAD/BloodHound", "tag": "tool"},
    {"title": "Hardening Protected Accounts - Microsoft Best Practices", "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/attractive-accounts-for-credential-theft", "tag": "defense"},
    {"title": "CIS Benchmark: Review and clean up adminCount", "url": "https://www.cisecurity.org/benchmark/microsoft_windows_server", "tag": "defense"},
    {"title": "SDProp and AdminSDHolder Explained - Sean Metcalf", "url": "https://adsecurity.org/?p=1906", "tag": "research"},
]
