"""
verifications/verify_as_rep.py
Manual Verification and Remediation data for ADScan findings matching: as-rep
"""

MATCH_KEYS = ["as-rep"]

TOOLS = [
    {
        "tool": "Impacket",
        "icon": "impacket",
        "desc": "Retrieve AS-REP hashes for accounts with pre-authentication disabled.",
        "code": "GetNPUsers.py <domain>/ -dc-ip <DC_IP> `\n    -usersfile users.txt -request `\n    -outputfile asrep_hashes.txt",
        "confirm": "Each hash output is an AS-REP roastable account.",
    },
    {
        "tool": "NetExec",
        "icon": "netexec",
        "desc": "Enumerate and retrieve AS-REP hashes in one command.",
        "code": "netexec ldap <DC_IP> -u <username> -p <password> --asreproast asrep.txt",
        "confirm": "Any hash in asrep.txt is an AS-REP roastable account.",
    },
    {
        "tool": "PowerShell",
        "icon": "ps",
        "desc": "Find accounts with Kerberos pre-authentication disabled (UAC flag 0x400000).",
        "code": "Get-ADUser -Filter * -Properties DoesNotRequirePreAuth `\n    | Where-Object {$_.DoesNotRequirePreAuth -eq $true} `\n    | Select-Object Name,SamAccountName",
        "confirm": "Each listed account does not require pre-authentication.",
    },
    {
        "tool": "ADUC (dsa.msc)",
        "icon": "aduc",
        "desc": "Check individual user accounts for the pre-auth setting via the GUI.",
        "steps": [
            "Open <code>dsa.msc</code> → user Properties → Account tab",
            "Scroll Account options list",
            "Check if <strong>Do not require Kerberos preauthentication</strong> is ticked",
        ],
    },
]

REMEDIATION = {
    "title": "Enable Kerberos pre-authentication on all affected accounts",
    "steps": [
        {
            "text": "Re-enable pre-authentication for a single account:",
            "code": "Set-ADUser -Identity <username> -DoesNotRequirePreAuth $false",
        },
        {
            "text": "Bulk-fix all affected accounts:",
            "code": "Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} `\n    | Set-ADUser -DoesNotRequirePreAuth $false",
        },
        {
            "text": "Ensure affected account passwords are <strong>reset immediately</strong> — AS-REP hashes captured before remediation are still crackable offline.",
        },
    ],
}


REFERENCES = [
    {"title": "Kerberos Pre-Authentication - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/enforce-user-logon-restrictions", "tag": "vendor"},
    {"title": "AS-REP Roasting Explained - Microsoft Threat Intelligence", "url": "https://www.microsoft.com/en-us/security/blog/2020/08/27/stopping-active-directory-attacks-and-other-post-exploitation-behavior/", "tag": "vendor"},
    {"title": "MITRE ATT&CK: AS-REP Roasting (T1558.004)", "url": "https://attack.mitre.org/techniques/T1558/004/", "tag": "attack"},
    {"title": "Rubeus - AS-REP Roasting Tool", "url": "https://github.com/GhostPack/Rubeus", "tag": "tool"},
    {"title": "Impacket GetNPUsers - AS-REP Roasting", "url": "https://github.com/fortra/impacket", "tag": "tool"},
    {"title": "Hashcat - AS-REP Hash Cracking", "url": "https://hashcat.net/hashcat/", "tag": "tool"},
    {"title": "CIS Benchmark: Enforce Kerberos Pre-Authentication", "url": "https://www.cisecurity.org/benchmark/microsoft_windows_server", "tag": "defense"},
    {"title": "Detecting AS-REP Roasting - Defender for Identity", "url": "https://learn.microsoft.com/en-us/defender-for-identity/reconnaissance-alerts#suspected-as-rep-roasting-attack-external-id-2412", "tag": "defense"},
]
