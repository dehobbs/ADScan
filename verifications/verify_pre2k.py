"""
verifications/verify_pre2k.py
Manual Verification and Remediation data for ADScan findings matching:
pre-Windows 2000 computer accounts with predictable passwords
"""

MATCH_KEYS = [
    "pre-windows 2000",
    "pre2k",
]

TOOLS = [
    {
        "tool": "pre2k",
        "icon": "netexec",
        "desc": "Test whether computer accounts authenticate with their predictable pre-Windows 2000 password.",
        "code": (
            "pre2k auth \\\n"
            "  -u <username> \\\n"
            "  -p <password> \\\n"
            "  -dc-ip <DC_IP> \\\n"
            "  -d <domain> \\\n"
            "  -outputfile pre2k.log"
        ),
        "confirm": (
            "Lines beginning with <strong>[+]</strong> indicate computer accounts that "
            "successfully authenticated with their lowercase account name as the password."
        ),
    },
    {
        "tool": "PowerShell",
        "icon": "ps",
        "desc": "Enumerate computer accounts created with the pre-Windows 2000 compatibility flag via userAccountControl.",
        "code": (
            "# UF_PASSWD_NOTREQD (0x20) is set by the pre-Windows 2000 checkbox\n"
            "# Combined with WORKSTATION_TRUST_ACCOUNT (0x1000) to scope to computer accounts\n"
            "Get-ADComputer -Filter * -Properties userAccountControl, PasswordLastSet |\n"
            "    Where-Object { $_.userAccountControl -band 0x20 } |\n"
            "    Select-Object Name, SamAccountName, userAccountControl, PasswordLastSet"
        ),
        "confirm": (
            "Any computer returned by this query has the PASSWD_NOTREQD flag, "
            "indicating it may have been created with pre-Windows 2000 compatibility enabled."
        ),
    },
    {
        "tool": "NetExec",
        "icon": "netexec",
        "desc": "Enumerate computer accounts and their userAccountControl flags via LDAP.",
        "code": (
            "nxc ldap <DC_IP> -u <username> -p <password> \\\n"
            "  --query \"(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=32))\" \\\n"
            "  \"sAMAccountName userAccountControl\""
        ),
        "confirm": (
            "Accounts returned by this LDAP filter have the PASSWD_NOTREQD (0x20) bit set — "
            "consistent with pre-Windows 2000 computer account creation."
        ),
    },
]

REMEDIATION = {
    "title": "Reset predictable passwords and prevent future pre-Windows 2000 computer account creation",
    "steps": [
        {
            "text": "Identify all affected computer accounts using pre2k or the PowerShell query above.",
            "code": (
                "pre2k auth -u <username> -p <password> -dc-ip <DC_IP> -d <domain> "
                "-outputfile pre2k.log"
            ),
        },
        {
            "text": (
                "For each active machine that is still domain-joined, reset the machine account "
                "password by re-joining the machine to the domain or using <code>netdom</code>:"
            ),
            "code": "netdom resetpwd /server:<DC_FQDN> /userd:<domain>\\<admin> /passwordd:*",
        },
        {
            "text": (
                "Alternatively, force a password reset directly on the computer account "
                "from a domain controller using PowerShell:"
            ),
            "code": (
                "$newPwd = ConvertTo-SecureString -String (New-Guid).ToString() -AsPlainText -Force\n"
                "Set-ADAccountPassword -Identity '<COMPUTER$>' -NewPassword $newPwd -Reset"
            ),
        },
        {
            "text": "Disable or delete computer accounts that belong to decommissioned machines:",
            "code": (
                "Disable-ADAccount -Identity '<COMPUTER$>'\n"
                "# Or to permanently remove:\n"
                "Remove-ADComputer -Identity '<COMPUTER$>'"
            ),
        },
        {
            "text": (
                "Audit computer account pre-creation procedures. Ensure the "
                "<strong>Assign this computer account as a pre-Windows 2000 computer</strong> "
                "checkbox in ADUC is never enabled when creating new computer objects."
            ),
        },
    ],
}

REFERENCES = [
    {
        "title": "pre2k — Pre-Windows 2000 Computer Account Tool (garrettfoster13)",
        "url": "https://github.com/garrettfoster13/pre2k",
        "tag": "tool",
    },
    {
        "title": "Pre-Windows 2000 Compatible Access Group — Microsoft Docs",
        "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#pre-windows-2000-compatible-access",
        "tag": "vendor",
    },
    {
        "title": "MITRE ATT&CK: Valid Accounts — Domain Accounts (T1078.002)",
        "url": "https://attack.mitre.org/techniques/T1078/002/",
        "tag": "attack",
    },
    {
        "title": "Active Directory Security: Pre-Created Computer Accounts",
        "url": "https://adsecurity.org/?p=3658",
        "tag": "research",
    },
]
