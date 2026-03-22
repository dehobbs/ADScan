"""
verifications/verify_fsmo.py
Manual Verification and Remediation data for ADScan findings matching: FSMO Role Distribution
"""

MATCH_KEYS = ["fsmo role distribution"]

TOOLS = [
    {
        "tool": "PowerShell",
        "icon": "ps",
        "desc": "Identify which DC holds each of the five FSMO roles.",
        "code": "Get-ADForest | Select-Object SchemaMaster,DomainNamingMaster\nGet-ADDomain | Select-Object PDCEmulator,RIDMaster,InfrastructureMaster",
        "confirm": "If all five roles resolve to the same DC hostname, the finding is confirmed.",
    },
    {
        "tool": "netdom",
        "icon": "cmd",
        "desc": "Query FSMO role holders from a domain-joined Windows host.",
        "code": "netdom query fsmo",
        "confirm": "All five roles listing the same server confirms the finding.",
    },
]

REMEDIATION = {
    "title": "Distribute FSMO roles across multiple Domain Controllers",
    "steps": [
        {
            "text": "Ensure at least two DCs exist before transferring roles. Build and promote a second DC if one does not exist.",
        },
        {
            "text": "Transfer forest-wide roles (Schema Master, Domain Naming Master) to a suitable DC:",
            "code": "Move-ADDirectoryServerOperationMasterRole -Identity <target-DC> -OperationMasterRole SchemaMaster,DomainNamingMaster",
        },
        {
            "text": "Transfer domain-wide roles (PDC Emulator, RID Master, Infrastructure Master):",
            "code": "Move-ADDirectoryServerOperationMasterRole -Identity <target-DC> -OperationMasterRole PDCEmulator,RIDMaster,InfrastructureMaster",
        },
        {
            "text": "Recommended distribution: PDC Emulator and RID Master on the primary DC; Infrastructure Master on a non-GC DC; Schema Master and Domain Naming Master on a well-secured DC.",
        },
    ],
}


REFERENCES = [
    {"title": "FSMO Roles Overview - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/planning-operations-master-role-placement", "tag": "vendor"},
    {"title": "FSMO Placement Best Practices - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/fsmo-placement-and-optimization-on-ad-dcs", "tag": "vendor"},
    {"title": "MITRE ATT&CK: Domain Controller Compromise", "url": "https://attack.mitre.org/techniques/T1078/002/", "tag": "attack"},
    {"title": "FSMO Role Seizure for Persistence - Active Directory Security", "url": "https://adsecurity.org/?p=3164", "tag": "attack"},
    {"title": "NetDOM - FSMO Role Management Tool", "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/cc731551(v=ws.10)", "tag": "tool"},
    {"title": "FSMO Role Distribution Best Practices - Microsoft", "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/planning-operations-master-role-placement", "tag": "defense"},
    {"title": "AD Resilience and FSMO Placement - TechNet", "url": "https://social.technet.microsoft.com/wiki/contents/articles/14914.active-directory-fsmo-roles-in-windows.aspx", "tag": "research"},
    {"title": "Single Point of Failure Risks with FSMO Concentration", "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/planning-operations-master-role-placement", "tag": "defense"},
]
