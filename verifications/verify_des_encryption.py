"""
verifications/verify_des_encryption.py
Manual Verification and Remediation data for ADScan findings matching: des encryption
"""

MATCH_KEYS = ["des encryption"]

TOOLS = [
    {
        "tool": "PowerShell",
        "icon": "ps",
        "desc": "Find accounts with DES-only Kerberos encryption enabled.",
        "code": "Get-ADUser -Filter * -Properties KerberosEncryptionType `\n    | Where-Object {$_.KerberosEncryptionType -band 3} `\n    | Select-Object Name,SamAccountName,KerberosEncryptionType",
        "confirm": "Accounts with DES flags (bits 0x1 or 0x2) in KerberosEncryptionType are vulnerable.",
    },
    {
        "tool": "Impacket",
        "icon": "impacket",
        "desc": "Perform a Kerberos exchange to confirm DES is accepted.",
        "code": "getTGT.py -des <DES_key> <domain>/<username>",
        "confirm": "Successful TGT retrieval with DES confirms the vulnerability.",
    },
    {
        "tool": "ADUC (dsa.msc)",
        "icon": "aduc",
        "desc": "Check account encryption settings via the Account tab.",
        "steps": [
            "Open <code>dsa.msc</code> → user Properties → Account tab",
            "In Account options, check if <strong>Use DES encryption types for this account</strong> is enabled.",
        ],
    },
    {
        "tool": "NetExec",
        "icon": "netexec",
        "desc": "Enumerate accounts with weak Kerberos encryption via LDAP.",
        "code": "netexec ldap <DC_IP> -u <username> -p <password> --users",
        "confirm": "Review userAccountControl flags — bit 0x200000 indicates DES-only.",
    },
]

REMEDIATION = {
    "title": "Disable DES and enforce AES-only Kerberos encryption",
    "steps": [
        {
            "text": "Disable DES on all user accounts:",
            "code": "Get-ADUser -Filter * -Properties KerberosEncryptionType `\n    | Where-Object {$_.KerberosEncryptionType -band 3} `\n    | Set-ADUser -KerberosEncryptionType AES128,AES256",
        },
        {
            "text": "Enforce AES via Group Policy: <em>Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options</em> → <strong>Network security: Configure encryption types allowed for Kerberos</strong> → enable AES128_HMAC_SHA1, AES256_HMAC_SHA1 only.",
        },
        {
            "text": "After enforcing AES, run <code>klist purge</code> on all clients to flush old DES tickets.",
        },
    ],
}


REFERENCES = [
    {"title": "Kerberos Supported Encryption Types - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-configure-encryption-types-allowed-for-kerberos", "tag": "vendor"},
    {"title": "Disabling DES in Kerberos - Microsoft KB", "url": "https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/disable-des-encryption-kerberos", "tag": "vendor"},
    {"title": "MITRE ATT&CK: Steal or Forge Kerberos Tickets (T1558)", "url": "https://attack.mitre.org/techniques/T1558/", "tag": "attack"},
    {"title": "DES Cipher Weakness and Kerberos Exploitation", "url": "https://adsecurity.org/?p=2462", "tag": "attack"},
    {"title": "Impacket - Kerberos Weak Encryption Detection", "url": "https://github.com/fortra/impacket", "tag": "tool"},
    {"title": "CIS Benchmark: Disable DES encryption in Kerberos", "url": "https://www.cisecurity.org/benchmark/microsoft_windows_server", "tag": "defense"},
    {"title": "NSA: Eliminating Obsolete Cryptography", "url": "https://media.defense.gov/2021/Nov/01/2002862946/-1/-1/0/CTR_AVOIDING_OBSOLETE_CRYPTOGRAPHY_20211101.PDF", "tag": "defense"},
    {"title": "NIST: DES Retirement (FIPS 46-3 Withdrawn)", "url": "https://csrc.nist.gov/publications/detail/fips/46/3/final", "tag": "research"},
]
