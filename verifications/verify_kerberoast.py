"""
verifications/verify_kerberoast.py
Manual Verification and Remediation data for ADScan findings matching: kerberoast
"""

MATCH_KEYS = ["kerberoast"]

TOOLS = [
    {
        "tool": "Impacket",
        "icon": "impacket",
        "desc": "Request TGS tickets for all SPNs and save hashes for offline cracking.",
        "code": "GetUserSPNs.py <domain>/<username>:<password> `\n    -dc-ip <DC_IP> -request `\n    -outputfile kerberoast_hashes.txt",
        "confirm": "Each hash file entry represents a Kerberoastable account.",
    },
    {
        "tool": "NetExec",
        "icon": "netexec",
        "desc": "Enumerate Kerberoastable accounts quickly without retrieving hashes.",
        "code": "netexec ldap <DC_IP> -u <username> -p <password> --kerberoasting",
        "confirm": "Any account listed is Kerberoastable.",
    },
    {
        "tool": "PowerShell",
        "icon": "ps",
        "desc": "Find accounts with Service Principal Names set — these are Kerberoastable.",
        "code": "Get-ADUser -Filter {ServicePrincipalName -ne \"$null\"} `\n    -Properties ServicePrincipalName `\n    | Select-Object Name,SamAccountName,ServicePrincipalName",
        "confirm": "Any non-computer account with an SPN is Kerberoastable.",
    },
    {
        "tool": "ADUC (dsa.msc)",
        "icon": "aduc",
        "desc": "Find user accounts with SPNs via the GUI attribute editor.",
        "steps": [
            "Open <code>dsa.msc</code> → View → Advanced Features",
            "Find a user → Properties → Attribute Editor",
            "Locate <strong>servicePrincipalName</strong> attribute",
            "Any non-empty value on a user account (not computer) is Kerberoastable.",
        ],
    },
]

REMEDIATION = {
    "title": "Remove unnecessary SPNs and enforce AES-only encryption",
    "steps": [
        {
            "text": "Audit and remove unnecessary SPNs from user accounts:",
            "code": "Set-ADUser -Identity <username> -ServicePrincipalNames @{Remove='<SPN>'}",
        },
        {
            "text": "Enforce AES-only encryption to make cracking computationally infeasible:",
            "code": "Set-ADUser -Identity <username> `\n    -KerberosEncryptionType AES128,AES256",
        },
        {
            "text": "Migrate service accounts to <strong>Group Managed Service Accounts (gMSAs)</strong> — they use auto-rotating 120-character passwords that cannot be cracked.",
        },
        {
            "text": "Ensure service account passwords are <strong>25+ characters</strong> and randomly generated if gMSAs cannot be used immediately.",
        },
    ],
}
