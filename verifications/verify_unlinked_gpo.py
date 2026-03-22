"""
verifications/verify_unlinked_gpo.py
Manual Verification and Remediation data for ADScan findings matching: Unlinked Group Policy Objects
"""

MATCH_KEYS = ["unlinked group policy"]

TOOLS = [
    {
        "tool": "PowerShell",
        "icon": "ps",
        "desc": "List all GPOs and identify those not linked to any OU, domain root, or site.",
        "code": "Import-Module GroupPolicy\nGet-GPO -All | Where-Object {\n    ($_ | Get-GPOReport -ReportType Xml) -notmatch '<LinksTo>'\n} | Select-Object DisplayName,Id,CreationTime,ModificationTime",
        "confirm": "Any GPO returned is not linked anywhere in the directory and will never be applied.",
    },
    {
        "tool": "GPMC",
        "icon": "cmd",
        "desc": "Review unlinked GPOs via the Group Policy Management Console.",
        "code": "# Open gpmc.msc\n# Expand Forest -> Domains -> <domain> -> Group Policy Objects\n# GPOs with no link icon or not referenced by any OU are unlinked",
        "confirm": "GPOs not referenced under any OU in the left-hand tree are unlinked.",
    },
]

REMEDIATION = {
    "title": "Link or delete unlinked Group Policy Objects",
    "steps": [
        {
            "text": "Review each unlinked GPO in <strong>GPMC (gpmc.msc)</strong> under <em>Group Policy Objects</em>. Determine if the policy is still needed.",
        },
        {
            "text": "If the GPO should be applied, link it to the appropriate OU: right-click the target OU &rarr; <em>Link an Existing GPO</em> &rarr; select the GPO.",
        },
        {
            "text": "If the GPO is no longer required, delete it: right-click the GPO in <em>Group Policy Objects</em> &rarr; <em>Delete</em>. This removes it from both AD and SYSVOL.",
        },
        {
            "text": "Document the rationale for any GPO that must be retained but left unlinked (e.g. as a template). Consider adding a description to the GPO for clarity.",
        },
    ],
}


REFERENCES = [
    {"title": "Group Policy Overview - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh831791(v=ws.11)", "tag": "vendor"},
    {"title": "Managing Group Policy Objects - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/cc754421(v=ws.11)", "tag": "vendor"},
    {"title": "MITRE ATT&CK: Group Policy Modification (T1484.001)", "url": "https://attack.mitre.org/techniques/T1484/001/", "tag": "attack"},
    {"title": "GPO Abuse for Persistence and Lateral Movement", "url": "https://adsecurity.org/?p=2862", "tag": "attack"},
    {"title": "SharpGPOAbuse - Group Policy Exploitation Tool", "url": "https://github.com/FSecureLABS/SharpGPOAbuse", "tag": "tool"},
    {"title": "BloodHound - GPO Attack Path Analysis", "url": "https://github.com/BloodHoundAD/BloodHound", "tag": "tool"},
    {"title": "GPO Hygiene Best Practices - Microsoft", "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory", "tag": "defense"},
    {"title": "CIS Benchmark: Review and remove orphaned GPOs", "url": "https://www.cisecurity.org/benchmark/microsoft_windows_server", "tag": "defense"},
    {"title": "GPO Auditing with Get-GPOReport", "url": "https://learn.microsoft.com/en-us/powershell/module/grouppolicy/get-gporeport", "tag": "defense"},
]
