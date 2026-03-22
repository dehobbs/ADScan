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
