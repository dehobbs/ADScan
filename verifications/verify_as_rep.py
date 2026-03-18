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
