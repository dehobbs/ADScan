"""
verifications/verify_rc4.py
Manual verification, remediation, and references for RC4 encryption findings.
"""

MATCH_KEYS = [
    "rc4",
    "arcfour",
    "rc4-hmac",
]

TOOLS = [
    {
        "tool": "PowerShell (AD Module)",
        "icon": "ps",
        "desc": "Find accounts where msDS-SupportedEncryptionTypes indicates RC4 is permitted.",
        "code": (            "# 0x4 bit = RC4; 0x18 = AES only\n"            "Get-ADUser -Filter * \\\n"            "  -Properties msDS-SupportedEncryptionTypes, SamAccountName |\n"            "  Where-Object {\n"            "    ($_.'msDS-SupportedEncryptionTypes' -band 0x4) -and\n"            "    -not ($_.'msDS-SupportedEncryptionTypes' -band 0x18)\n"            "  } |\n"            "  Select-Object SamAccountName, 'msDS-SupportedEncryptionTypes'"
        ),
        "confirm": "Any account with RC4 as the only supported encryption type is a Kerberoast / RC4 downgrade risk.",
    },
    {
        "tool": "NetExec",
        "icon": "netexec",
        "desc": "Attempt RC4 Kerberos authentication from Linux to confirm the DC accepts RC4.",
        "code": (            "netexec smb <DC_IP> \\\n"            "  -u <USER> -p <PASSWORD> \\\n"            "  -k --use-kcache"
        ),
        "confirm": "If RC4 authentication succeeds when AES-only is expected, RC4 has not been fully disabled.",
    },
]

REMEDIATION = {
    "title": "Disable RC4 Kerberos encryption domain-wide and enforce AES",
    "steps": [
        {
            "text": "Set msDS-SupportedEncryptionTypes to AES-only (0x18) on all user and computer accounts:",
            "code": (                "Get-ADUser -Filter * | Set-ADUser \\\n"                "  -KerberosEncryptionType AES128,AES256\n"                "Get-ADComputer -Filter * | Set-ADComputer \\\n"                "  -KerberosEncryptionType AES128,AES256"
            ),
        },
        {
            "text": "Disable RC4 at the domain level via GPO: Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options → Network security: Configure encryption types allowed for Kerberos. Uncheck DES and RC4, check AES128 and AES256.",
        },
        {
            "text": "After enforcing AES, test all service accounts and applications for Kerberos authentication failures before broad deployment.",
        },
    ],
}

REFERENCES = [
    {
        "title": "Microsoft — Kerberos Encryption Type Configuration",
        "url": "https://learn.microsoft.com/en-us/windows-server/security/kerberos/preventing-kerberos-change-password-that-uses-rc4-secret-keys",
        "tag": "vendor",
    },
    {
        "title": "MITRE ATT&CK — Steal or Forge Kerberos Tickets: Kerberoasting (T1558.003)",
        "url": "https://attack.mitre.org/techniques/T1558/003/",
        "tag": "attack",
    },
    {
        "title": "CIS Benchmark — Kerberos Encryption Types",
        "url": "https://www.cisecurity.org/benchmark/microsoft_windows_server",
        "tag": "defense",
    },
]
