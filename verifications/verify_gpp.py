"""
verifications/verify_gpp.py
Manual Verification and Remediation data for ADScan findings matching: gpp
"""

MATCH_KEYS = ["gpp"]

TOOLS = [
    {
        "tool": "NetExec",
        "icon": "netexec",
        "desc": "Search SYSVOL share for Group Policy Preferences files containing cpassword.",
        "code": "netexec smb <DC_IP> -u <username> -p <password> -M gpp_password",
        "confirm": "Any cpassword value found is exploitable using a known AES key.",
    },
    {
        "tool": "Impacket",
        "icon": "impacket",
        "desc": "Mount the SYSVOL share and search for cpassword entries manually.",
        "code": "smbclient.py <domain>/<username>:<password>@<DC_IP>\n# Then browse: \\\\<DC>\\SYSVOL\\<domain>\\Policies\n\n# Or use findstr on Windows:\nfindstr /S /I cpassword \\\\<DC>\\SYSVOL\\<domain>\\Policies\\*.xml",
        "confirm": "Any XML file with a <code>cpassword</code> attribute contains a decryptable credential.",
    },
    {
        "tool": "PowerShell",
        "icon": "ps",
        "desc": "Search SYSVOL for GPP files containing cpassword.",
        "code": "Get-ChildItem -Path \"\\\\<DC>\\SYSVOL\" -Recurse -Filter \"*.xml\" `\n    | Select-String -Pattern \"cpassword\" `\n    | Select-Object Path,Line",
        "confirm": "Any match contains a GPP credential that can be decrypted with the public AES key.",
    },
    {
        "tool": "net use / Explorer",
        "icon": "cmd",
        "desc": "Manually browse SYSVOL for Group Policy XML files.",
        "code": "net use Z: \\\\<DC_IP>\\SYSVOL\ndir Z:\\<domain>\\Policies /s /b | findstr .xml",
        "confirm": "Open any Groups.xml, Services.xml etc. and check for <code>cpassword=</code> attribute.",
    },
]

REMEDIATION = {
    "title": "Remove all GPP cpassword entries and apply MS14-025",
    "steps": [
        {
            "text": "Install <strong>MS14-025</strong> on all Domain Controllers — this prevents creation of new GPP passwords.",
        },
        {
            "text": "Delete existing GPP password entries from SYSVOL: search for and remove all XML files containing <code>cpassword</code> from SYSVOL policies.",
            "code": "Get-ChildItem -Path \"\\\\<DC>\\SYSVOL\" -Recurse -Filter \"*.xml\" `\n    | Select-String \"cpassword\" `\n    | ForEach-Object { Remove-Item $_.Path -WhatIf }",
        },
        {
            "text": "<strong>Reset all passwords</strong> that were stored in GPP — treat them as fully compromised.",
        },
    ],
}


REFERENCES = [
    {"title": "MS14-025: Group Policy Preferences Password Vulnerability - Microsoft", "url": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2014/ms14-025", "tag": "vendor"},
    {"title": "GPP Password Vulnerability Fix - Microsoft KB2962486", "url": "https://support.microsoft.com/en-us/topic/ms14-025-vulnerability-in-group-policy-preferences-could-allow-elevation-of-privilege-may-13-2014-60734e15-af79-26ca-ea53-8cd617073c30", "tag": "vendor"},
    {"title": "MITRE ATT&CK: Unsecured Credentials - Group Policy Preferences (T1552.006)", "url": "https://attack.mitre.org/techniques/T1552/006/", "tag": "attack"},
    {"title": "GPP Password Decryption - Get-GPPPassword", "url": "https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1", "tag": "tool"},
    {"title": "Metasploit - post/windows/gather/credentials/gpp", "url": "https://www.rapid7.com/db/modules/post/windows/gather/credentials/gpp/", "tag": "tool"},
    {"title": "CIS Benchmark: Remove GPP passwords from SYSVOL", "url": "https://www.cisecurity.org/benchmark/microsoft_windows_server", "tag": "defense"},
    {"title": "NSA: Disable Group Policy Preferences Password Storage", "url": "https://media.defense.gov/2023/Jun/22/2003251092/-1/-1/0/CTR_DEFENDING_ACTIVE_DIRECTORY.PDF", "tag": "defense"},
    {"title": "GPP Password Attack Analysis - Active Directory Security", "url": "https://adsecurity.org/?p=2288", "tag": "research"},
]
