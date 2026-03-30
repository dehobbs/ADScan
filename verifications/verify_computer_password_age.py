"""
verifications/verify_computer_password_age.py
Manual Verification and Remediation data for ADScan findings matching:
computer accounts with stale machine passwords
"""

MATCH_KEYS = [
    "stale machine password",
    "computer accounts with stale",
]

TOOLS = [
    {
        "tool": "PowerShell",
        "icon": "ps",
        "desc": "Find enabled, non-DC computer accounts whose password has not been set in over 30 days.",
        "code": (
            "$cutoff = (Get-Date).AddDays(-30)\n"
            "Get-ADComputer -Filter \"Enabled -eq `$true -and PasswordLastSet -lt '$cutoff'\" `\n"
            "    -Properties PasswordLastSet, OperatingSystem, UserAccountControl `\n"
            "    | Where-Object { ($_.UserAccountControl -band 0x2000) -eq 0 } `\n"
            "    | Select-Object Name, DNSHostName, PasswordLastSet, OperatingSystem `\n"
            "    | Sort-Object PasswordLastSet"
        ),
        "confirm": "Each listed computer has not rotated its machine account password in over 30 days.",
    },
    {
        "tool": "NetExec",
        "icon": "netexec",
        "desc": "Enumerate computer accounts including password last set dates.",
        "code": "netexec ldap <DC_IP> -u <username> -p <password> --computers",
        "confirm": "Review the <strong>pwd_last_set</strong> column for computers with dates older than 30 days.",
    },
    {
        "tool": "ADUC (dsa.msc)",
        "icon": "aduc",
        "desc": "Inspect password age for individual computer accounts in ADUC.",
        "steps": [
            "Open <code>dsa.msc</code>",
            "Locate a computer object → Properties → Account tab",
            "Check <strong>Password last changed</strong> date",
            "For bulk review, use Active Directory Administrative Center → Global Search with filters",
        ],
    },
]

REMEDIATION = {
    "title": "Repair the Netlogon secure channel and restore automatic password rotation",
    "steps": [
        {
            "text": "Force a machine account password reset from the affected machine (run as local admin):",
            "code": "Reset-ComputerMachinePassword -Server <DC_FQDN> -Credential (Get-Credential)",
        },
        {
            "text": "Alternatively, use <code>netdom</code> from the domain controller:",
            "code": "netdom resetpwd /server:<DC_FQDN> /userd:<domain>\\<admin> /passwordd:*",
        },
        {
            "text": (
                "Check whether automatic password rotation has been disabled via registry "
                "on the affected machine. The following key should either be absent or set to <strong>0</strong>:"
            ),
            "code": (
                "# Check (run on the affected machine):\n"
                "Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters' "
                "-Name DisablePasswordChange -ErrorAction SilentlyContinue\n\n"
                "# Remove the restriction if present:\n"
                "Remove-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters' "
                "-Name DisablePasswordChange"
            ),
        },
        {
            "text": "For machines that cannot be remediated (decommissioned but not cleaned up), disable or delete the computer account:",
            "code": "Disable-ADAccount -Identity '<COMPUTER$>'\n# Or to delete:\nRemove-ADComputer -Identity '<COMPUTER$>'",
        },
    ],
}

REFERENCES = [
    {
        "title": "Machine Account Password Process - Microsoft Docs",
        "url": "https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/machine-account-password-process",
        "tag": "vendor",
    },
    {
        "title": "Reset-ComputerMachinePassword - Microsoft Docs",
        "url": "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/reset-computermachinepassword",
        "tag": "vendor",
    },
    {
        "title": "DisablePasswordChange Registry Key - Microsoft Docs",
        "url": "https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/disable-automatic-password-changes",
        "tag": "vendor",
    },
    {
        "title": "MITRE ATT&CK: Valid Accounts - Domain Accounts (T1078.002)",
        "url": "https://attack.mitre.org/techniques/T1078/002/",
        "tag": "attack",
    },
    {
        "title": "MITRE ATT&CK: Pass the Hash (T1550.002)",
        "url": "https://attack.mitre.org/techniques/T1550/002/",
        "tag": "attack",
    },
    {
        "title": "CIS Benchmark: Ensure machine account password changes are not disabled",
        "url": "https://www.cisecurity.org/benchmark/microsoft_windows_server",
        "tag": "defense",
    },
]
