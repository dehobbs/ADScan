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
        "desc": (
            "Enumerate all computer accounts and attempt authentication using the "
            "pre-Windows 2000 default password (account name in lowercase, without trailing '$'). "
            "A successful login confirms the account still has its original predictable password."
        ),
        "code": (
            "pre2k auth \\\n"
            "  -u <username> \\\n"
            "  -p <password> \\\n"
            "  -dc-ip <DC_IP> \\\n"
            "  -d <domain> \\\n"
            "  -outputfile pre2k.log"
        ),
        "confirm": (
            "Lines prefixed with <strong>[+]</strong> indicate computer accounts that "
            "authenticated successfully using their lowercase account name as the password. "
            "For example, a computer named <code>WORKSTATION01$</code> would be tested with "
            "the password <code>workstation01</code>. Any <strong>[+]</strong> result is a confirmed vulnerable account."
        ),
    },
    {
        "tool": "PowerShell",
        "icon": "ps",
        "desc": (
            "Query Active Directory for computer accounts with the PASSWD_NOTREQD flag (0x20) set. "
            "This flag is applied when a computer account is pre-created with the "
            "'Assign this computer account as a pre-Windows 2000 computer' checkbox enabled."
        ),
        "code": (
            "# PASSWD_NOTREQD (UF flag 0x20) is set by the pre-Windows 2000 checkbox.\n"
            "# Filter to enabled computer accounts only (exclude disabled accounts).\n"
            "Get-ADComputer -Filter * -Properties userAccountControl, PasswordLastSet, Enabled |\n"
            "    Where-Object { ($_.userAccountControl -band 0x20) -and $_.Enabled } |\n"
            "    Select-Object Name, SamAccountName, PasswordLastSet, userAccountControl |\n"
            "    Sort-Object Name"
        ),
        "confirm": (
            "Each computer returned has the <strong>PASSWD_NOTREQD</strong> flag set, "
            "meaning it was likely created with the pre-Windows 2000 compatibility option. "
            "Cross-reference this list with pre2k output to confirm which accounts "
            "still have the predictable default password in place."
        ),
    },
    {
        "tool": "NetExec",
        "icon": "netexec",
        "desc": (
            "Use an LDAP query to enumerate computer accounts where the PASSWD_NOTREQD bit "
            "(0x20) is set in userAccountControl. The OID filter "
            "1.2.840.113556.1.4.803 performs a bitwise AND match."
        ),
        "code": (
            "nxc ldap <DC_IP> -u <username> -p <password> \\\n"
            "  --query \"(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=32))\" \\\n"
            "  \"sAMAccountName userAccountControl PasswordLastSet\""
        ),
        "confirm": (
            "Any computer account returned has <strong>userAccountControl bit 0x20</strong> set. "
            "Review <code>PasswordLastSet</code> — if it has never been changed since account creation, "
            "the default predictable password is almost certainly still in place."
        ),
    },
]

REMEDIATION = {
    "title": "Reset predictable passwords and prevent future pre-Windows 2000 computer account creation",
    "steps": [
        {
            "text": (
                "Run pre2k to produce a full list of accounts that are confirmed vulnerable "
                "(those that authenticate with their lowercase name as the password):"
            ),
            "code": (
                "pre2k auth -u <username> -p <password> -dc-ip <DC_IP> -d <domain> "
                "-outputfile pre2k.log\n"
                "# Review pre2k.log — [+] lines are confirmed vulnerable accounts"
            ),
        },
        {
            "text": (
                "For each active machine that is still domain-joined, reset the machine account "
                "password by re-joining the machine to the domain. This is the most reliable fix "
                "as it synchronises the password between the machine and Active Directory:"
            ),
            "code": (
                "# Run on the affected machine as a local administrator:\n"
                "Reset-ComputerMachinePassword -Server <DC_FQDN> -Credential (Get-Credential)"
            ),
        },
        {
            "text": (
                "Alternatively, reset the computer account password directly from a Domain Controller. "
                "Generate a random password so it cannot be guessed:"
            ),
            "code": (
                "$newPwd = ConvertTo-SecureString -String ([System.Web.Security.Membership]::GeneratePassword(24,4)) "
                "-AsPlainText -Force\n"
                "Set-ADAccountPassword -Identity '<COMPUTER$>' -NewPassword $newPwd -Reset\n\n"
                "# Or using netdom from the DC:\n"
                "netdom resetpwd /server:<DC_FQDN> /userd:<domain>\\<admin> /passwordd:*"
            ),
        },
        {
            "text": (
                "Disable or delete computer accounts that belong to decommissioned or "
                "unrecognised machines. These should not remain enabled in Active Directory:"
            ),
            "code": (
                "# Disable the account:\n"
                "Disable-ADAccount -Identity '<COMPUTER$>'\n\n"
                "# Or permanently remove:\n"
                "Remove-ADComputer -Identity '<COMPUTER$>' -Confirm:$false"
            ),
        },
        {
            "text": (
                "Clear the PASSWD_NOTREQD flag on remaining computer accounts to ensure "
                "Active Directory enforces the domain password policy on them going forward:"
            ),
            "code": (
                "# Remove the PASSWD_NOTREQD bit (0x20) from userAccountControl:\n"
                "$computer = Get-ADComputer '<COMPUTER$>' -Properties userAccountControl\n"
                "$newUAC = $computer.userAccountControl -band (-bnot 0x20)\n"
                "Set-ADComputer '<COMPUTER$>' -Replace @{userAccountControl = $newUAC}"
            ),
        },
        {
            "text": (
                "Enforce a process change: when pre-creating computer accounts in ADUC (dsa.msc), "
                "ensure the <strong>'Assign this computer account as a pre-Windows 2000 computer'</strong> "
                "checkbox is <strong>never checked</strong>. Audit existing GPOs and provisioning "
                "scripts for any automation that sets this flag."
            ),
        },
    ],
}

REFERENCES = [
    {
        "title": "pre2k — Pre-Windows 2000 Computer Account Tester (garrettfoster13)",
        "url": "https://github.com/garrettfoster13/pre2k",
        "tag": "tool",
    },
    {
        "title": "userAccountControl Flags — Microsoft Docs",
        "url": "https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties",
        "tag": "vendor",
    },
    {
        "title": "Joining a Computer to a Domain — Pre-Windows 2000 Option (Microsoft Docs)",
        "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/deploy/ad-ds-installation-and-removal-wizard-page-descriptions",
        "tag": "vendor",
    },
    {
        "title": "MITRE ATT&CK: Valid Accounts — Domain Accounts (T1078.002)",
        "url": "https://attack.mitre.org/techniques/T1078/002/",
        "tag": "attack",
    },
    {
        "title": "MITRE ATT&CK: Brute Force — Password Spraying (T1110.003)",
        "url": "https://attack.mitre.org/techniques/T1110/003/",
        "tag": "attack",
    },
    {
        "title": "Hunting for Pre-Windows 2000 Computer Objects — TrustedSec",
        "url": "https://www.trustedsec.com/blog/diving-into-pre-created-computer-accounts/",
        "tag": "research",
    },
]
