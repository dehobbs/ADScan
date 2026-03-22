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
