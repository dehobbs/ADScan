"""
verifications/verify_duplicate_spn.py
Manual Verification and Remediation data for ADScan findings matching:
duplicate service principal names
"""

MATCH_KEYS = [
    "duplicate service principal names",
    "duplicate spn",
]

TOOLS = [
    {
        "tool": "PowerShell",
        "icon": "ps",
        "desc": "Find all duplicate SPNs across the domain.",
        "code": "Import-Module ActiveDirectory\nGet-ADObject -Filter {ServicePrincipalName -ne '$null'} -Properties ServicePrincipalName |\n    ForEach-Object {\n        foreach ($spn in $_.ServicePrincipalName) { [PSCustomObject]@{Object=$_.Name;SPN=$spn} }\n    } |\n    Group-Object SPN |\n    Where-Object { $_.Count -gt 1 } |\n    Select-Object Name, @{n='Accounts';e={$_.Group.Object -join ', '}}",
        "confirm": "Each group with Count > 1 is a duplicate SPN conflict — Kerberos cannot resolve which account to ticket.",
    },
    {
        "tool": "setspn",
        "icon": "cmd",
        "desc": "Use the built-in setspn tool to detect duplicate SPNs forest-wide.",
        "code": "setspn -X -F",
        "confirm": "Any output listing the same SPN on multiple accounts confirms a duplicate.",
    },
    {
        "tool": "ADUC (dsa.msc)",
        "icon": "aduc",
        "desc": "Inspect SPNs on individual accounts via ADUC.",
        "steps": [
            "Open <code>dsa.msc</code> → View → Advanced Features",
            "Locate each account → Properties → Attribute Editor",
            "Check <strong>servicePrincipalName</strong> for conflicting values",
            "Cross-reference with <code>setspn -X</code> output to identify duplicates",
        ],
    },
    {
        "tool": "ldapsearch",
        "icon": "netexec",
        "desc": "Query all SPNs via LDAP.",
        "code": "ldapsearch -H ldap://<DC_IP> -x -D '<username>@<domain>' -w <password>\n  -b 'DC=<domain>,DC=<tld>'\n  '(servicePrincipalName=*)'\n  servicePrincipalName sAMAccountName",
        "confirm": "Sort and count: any SPN appearing on more than one account is a duplicate.",
    },
]

REMEDIATION = {
    "title": "Remove or deduplicate conflicting SPNs",
    "steps": [
        {
            "text": "Identify the canonical account for each SPN — the service account that should own it.",
        },
        {
            "text": "Remove the SPN from any account that should not own it:",
            "code": "setspn -D <SPN> <account_to_remove_from>",
        },
        {
            "text": "Verify the SPN now resolves to a single account:",
            "code": "setspn -Q <SPN>",
        },
        {
            "text": "For Kerberoastable SPNs on user accounts, consider migrating services to <strong>Group Managed Service Accounts (gMSA)</strong> — SPNs are managed automatically and passwords rotate.",
        },
    ],
}

REFERENCES = [
    {"title": "Duplicate SPNs and Kerberos Authentication Issues - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/service-principal-name-spn-authentication-failure", "tag": "vendor"},
    {"title": "setspn Tool Reference - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731241(v=ws.11)", "tag": "vendor"},
    {"title": "MITRE ATT&CK: Kerberoasting (T1558.003)", "url": "https://attack.mitre.org/techniques/T1558/003/", "tag": "attack"},
    {"title": "Kerberoasting - Duplicate SPNs Increase Attack Surface", "url": "https://adsecurity.org/?p=2293", "tag": "research"},
    {"title": "Group Managed Service Accounts Overview - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview", "tag": "defense"},
    {"title": "CIS Benchmark: Manage Service Account SPNs", "url": "https://www.cisecurity.org/benchmark/microsoft_windows_server", "tag": "defense"},
]
