"""
verifications/verify_default_credential.py
Manual Verification and Remediation data for ADScan findings matching: default credential
"""

MATCH_KEYS = ["rid 500"]

TOOLS = [
    {
        "tool": "NetExec",
        "icon": "netexec",
        "desc": "Test common default credentials against SMB to identify weak accounts.",
        "code": "netexec smb <DC_IP> -u Administrator -p Password1\nnetexec smb <DC_IP> -u Administrator -p Welcome1",
        "confirm": "<strong>[+]</strong> result means the credentials are valid — default password confirmed.",
    },
    {
        "tool": "Impacket",
        "icon": "impacket",
        "desc": "Test credentials using smbclient to verify access.",
        "code": "smbclient.py <domain>/Administrator:Password1@<DC_IP>",
        "confirm": "Successful connection confirms default/weak credentials.",
    },
    {
        "tool": "PowerShell",
        "icon": "ps",
        "desc": "Check when the Administrator account password was last set.",
        "code": "Get-ADUser -Identity Administrator -Properties PasswordLastSet `\n    | Select-Object Name,PasswordLastSet",
        "confirm": "A <strong>PasswordLastSet</strong> date matching initial domain setup suggests the default password was never changed.",
    },
    {
        "tool": "ADUC (dsa.msc)",
        "icon": "aduc",
        "desc": "Check account properties for the built-in Administrator account.",
        "steps": [
            "Open <code>dsa.msc</code>",
            "Navigate to <em>Users</em> container → <strong>Administrator</strong>",
            "Properties → Account tab → check <em>Password never expires</em> and review last password change via Attribute Editor.",
        ],
    },
]

REMEDIATION = {
    "title": "Reset default and weak account passwords immediately",
    "steps": [
        {
            "text": "Reset the built-in Administrator password to a strong, unique value:",
            "code": "Set-ADAccountPassword -Identity Administrator `\n    -NewPassword (ConvertTo-SecureString \"<NewPassword>\" -AsPlainText -Force) `\n    -Reset",
        },
        {
            "text": "Rename the built-in Administrator account to reduce its visibility:",
            "code": "Rename-ADObject -Identity \"CN=Administrator,CN=Users,DC=<domain>...\" -NewName \"<NewName>\"",
        },
        {
            "text": "Deploy <strong>LAPS</strong> for local administrator accounts to ensure unique, auto-rotating passwords per machine.",
        },
    ],
}


REFERENCES = [
    {"title": "Default Local Administrator Account - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/local-accounts", "tag": "vendor"},
    {"title": "Securing the Administrator Account - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-d--securing-built-in-administrator-accounts-in-active-directory", "tag": "vendor"},
    {"title": "MITRE ATT&CK: Default Accounts (T1078.001)", "url": "https://attack.mitre.org/techniques/T1078/001/", "tag": "attack"},
    {"title": "MITRE ATT&CK: Brute Force - Password Spraying (T1110.003)", "url": "https://attack.mitre.org/techniques/T1110/003/", "tag": "attack"},
    {"title": "NetExec - Default Credential Testing", "url": "https://github.com/Pennyw0rth/NetExec", "tag": "tool"},
    {"title": "CrackMapExec - Default Credential Checks", "url": "https://github.com/byt3bl33d3r/CrackMapExec", "tag": "tool"},
    {"title": "CIS Benchmark: Rename and disable built-in Administrator", "url": "https://www.cisecurity.org/benchmark/microsoft_windows_server", "tag": "defense"},
    {"title": "NSA: Securing Default Accounts in AD", "url": "https://media.defense.gov/2023/Jun/22/2003251092/-1/-1/0/CTR_DEFENDING_ACTIVE_DIRECTORY.PDF", "tag": "defense"},
]
