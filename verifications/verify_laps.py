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


REFERENCES = [
    {"title": "Microsoft LAPS Overview", "url": "https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview", "tag": "vendor"},
    {"title": "Windows LAPS (Built-in) Documentation", "url": "https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview", "tag": "vendor"},
    {"title": "Deploy Legacy LAPS", "url": "https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-deployment-guide", "tag": "vendor"},
    {"title": "MITRE ATT&CK: Credentials from Password Stores (T1555)", "url": "https://attack.mitre.org/techniques/T1555/", "tag": "attack"},
    {"title": "Abusing LAPS - Active Directory Security", "url": "https://adsecurity.org/?p=3164", "tag": "attack"},
    {"title": "LAPS Exploitation with LAPSDumper", "url": "https://github.com/n00py/LAPSDumper", "tag": "tool"},
    {"title": "CIS Benchmark: Ensure LAPS is installed", "url": "https://www.cisecurity.org/benchmark/microsoft_windows_server", "tag": "defense"},
    {"title": "NSA AD Security Guide", "url": "https://media.defense.gov/2023/Jun/22/2003251092/-1/-1/0/CTR_DEFENDING_ACTIVE_DIRECTORY.PDF", "tag": "defense"},
    {"title": "Detecting LAPS Abuse - Defender for Identity", "url": "https://learn.microsoft.com/en-us/defender-for-identity/laps-activity", "tag": "defense"},
]
