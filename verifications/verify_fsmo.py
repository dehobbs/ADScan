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
