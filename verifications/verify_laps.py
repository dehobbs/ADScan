"""
verifications/verify_laps.py
Manual Verification and Remediation data for ADScan findings matching: laps
"""

MATCH_KEYS = ["laps"]

TOOLS = [
    {
        "tool": "NetExec",
        "icon": "netexec",
        "desc": "Check if LAPS is deployed and readable on domain computers.",
        "code": "netexec ldap <DC_IP> -u <username> -p <password> -M laps",
        "confirm": "Computers without <strong>ms-Mcs-AdmPwd</strong> populated likely don\'t have LAPS deployed.",
    },
    {
        "tool": "PowerShell",
        "icon": "ps",
        "desc": "Query the LAPS password attribute for all computers.",
        "code": "Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime `\n    | Select-Object Name,\'ms-Mcs-AdmPwd\',\'ms-Mcs-AdmPwdExpirationTime\'",
        "confirm": "Computers with empty <strong>ms-Mcs-AdmPwd</strong> do not have LAPS deployed.",
    },
    {
        "tool": "ADUC (dsa.msc)",
        "icon": "aduc",
        "desc": "Check the LAPS attribute on individual computer objects.",
        "steps": [
            "Open <code>dsa.msc</code> → View → Advanced Features",
            "Locate a computer object → Properties → Attribute Editor",
            "Search for <strong>ms-Mcs-AdmPwd</strong>",
            "If missing or empty, LAPS is not deployed on that computer.",
        ],
    },
    {
        "tool": "Impacket (ldapsearch)",
        "icon": "impacket",
        "desc": "Use ldapsearch to query LAPS attributes via LDAP.",
        "code": "ldapsearch -x -H ldap://<DC_IP> -D '<username>@<domain>' `\n    -w '<password>' -b 'DC=<domain>,DC=<tld>' `\n    '(objectClass=computer)' ms-Mcs-AdmPwd",
        "confirm": "Computers with no <strong>ms-Mcs-AdmPwd</strong> value lack LAPS.",
    },
]

REMEDIATION = {
    "title": "Deploy LAPS (or Windows LAPS) across all domain computers",
    "steps": [
        {
            "text": "Install legacy LAPS (Windows Server 2016/2019) via Group Policy:",
            "code": "# Download LAPS.x64.msi from Microsoft\nInstall-Module -Name LAPS\nUpdate-LapsADSchema\nSet-AdmPwdComputerSelfPermission -OrgUnit \"OU=Workstations,DC=<domain>...\"",
        },
        {
            "text": "For Windows Server 2022 / Windows 11 22H2+, use <strong>Windows LAPS</strong> (built-in) with <code>Set-LapsADComputerSelfPermission</code>.",
        },
        {
            "text": "Restrict who can read <code>ms-Mcs-AdmPwd</code> — only Helpdesk/IT Admins should have read access, not regular users.",
        },
    ],
}
