"""
verifications/verify_shadow_credential.py
Manual Verification and Remediation data for ADScan findings matching: shadow credential
"""

MATCH_KEYS = ["shadow credential"]

TOOLS = [
    {
        "tool": "Certipy",
        "icon": "impacket",
        "desc": "Enumerate accounts with msDS-KeyCredentialLink set (shadow credentials).",
        "code": "certipy find -u <username>@<domain> -p <password> -dc-ip <DC_IP>",
        "confirm": "Accounts with <strong>Key Credential</strong> entries not set by the OS are suspicious.",
    },
    {
        "tool": "PowerShell",
        "icon": "ps",
        "desc": "Query msDS-KeyCredentialLink attribute on user and computer accounts.",
        "code": "Get-ADUser -Filter * -Properties msDS-KeyCredentialLink `\n    | Where-Object {\'msDS-KeyCredentialLink\' -ne $null} `\n    | Select-Object Name,\'msDS-KeyCredentialLink\'",
        "confirm": "Unexpected entries in <strong>msDS-KeyCredentialLink</strong> indicate shadow credential abuse.",
    },
    {
        "tool": "bloodyAD",
        "icon": "netexec",
        "desc": "Enumerate and manipulate shadow credentials using bloodyAD.",
        "code": "bloodyAD -u <username> -p <password> -d <domain> --host <DC_IP> get object <target> --attr msDS-KeyCredentialLink",
        "confirm": "Non-empty output means shadow credentials are present.",
    },
    {
        "tool": "ADUC (dsa.msc)",
        "icon": "aduc",
        "desc": "Inspect msDS-KeyCredentialLink via the Attribute Editor.",
        "steps": [
            "Open <code>dsa.msc</code> → View → Advanced Features",
            "Locate a user/computer → Properties → Attribute Editor",
            "Find <strong>msDS-KeyCredentialLink</strong>",
            "Any unexpected values indicate shadow credential backdoors.",
        ],
    },
]

REMEDIATION = {
    "title": "Clear unauthorized Key Credential entries",
    "steps": [
        {
            "text": "Clear the msDS-KeyCredentialLink attribute on affected accounts:",
            "code": "Set-ADUser -Identity <username> -Clear msDS-KeyCredentialLink",
        },
        {
            "text": "Audit who has <strong>Write</strong> permission to <code>msDS-KeyCredentialLink</code> — restrict to Domain Admins and the system only.",
        },
        {
            "text": "Enable <strong>Protected Users</strong> security group membership for privileged accounts — this provides additional Kerberos protections.",
        },
    ],
}


REFERENCES = [
    {"title": "msDS-KeyCredentialLink Attribute - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/de61eb56-b75f-4743-b8af-e9be154b47af", "tag": "vendor"},
    {"title": "Windows Hello for Business and PKINIT - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/hello-how-it-works-authentication", "tag": "vendor"},
    {"title": "MITRE ATT&CK: Modify Authentication Process (T1556)", "url": "https://attack.mitre.org/techniques/T1556/", "tag": "attack"},
    {"title": "Shadow Credentials Attack - Elad Shamir Research", "url": "https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab", "tag": "research"},
    {"title": "Whisker - Shadow Credential Tool", "url": "https://github.com/eladshamir/Whisker", "tag": "tool"},
    {"title": "PyWhisker - Python Shadow Credential Tool", "url": "https://github.com/ShutdownRepo/pywhisker", "tag": "tool"},
    {"title": "Detecting Shadow Credential Attacks - Defender for Identity", "url": "https://learn.microsoft.com/en-us/defender-for-identity/credential-access-alerts", "tag": "defense"},
    {"title": "Auditing msDS-KeyCredentialLink Changes", "url": "https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5136", "tag": "defense"},
]
