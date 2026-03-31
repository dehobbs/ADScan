"""
verifications/verify_nopac.py
Manual Verification and Remediation data for ADScan findings matching:
NoPac (CVE-2021-42278/42287) vulnerability
"""

MATCH_KEYS = [
    "nopac",
    "cve-2021-42278",
    "cve-2021-42287",
]

TOOLS = [
    {
        "tool": "NetExec",
        "icon": "netexec",
        "desc": "Use the nopac module to request a TGT with and without a PAC and compare ticket sizes.",
        "code": (
            "nxc smb <DC_IP> \\\n"
            "  -d <domain> \\\n"
            "  -u <username> \\\n"
            "  -p <password> \\\n"
            "  -M nopac"
        ),
        "confirm": (
            "If the output contains a <strong>NOPAC</strong> vulnerable indicator, "
            "the Domain Controller is unpatched. A patched DC will show "
            "<strong>NOT vulnerable</strong> in the NOPAC module output."
        ),
    },
    {
        "tool": "PowerShell",
        "icon": "ps",
        "desc": "Check ms-DS-MachineAccountQuota — a non-zero value is a prerequisite for NoPac exploitation.",
        "code": (
            "Get-ADObject -Identity ((Get-ADDomain).DistinguishedName) "
            "-Properties 'ms-DS-MachineAccountQuota' | "
            "Select-Object 'ms-DS-MachineAccountQuota'"
        ),
        "confirm": (
            "A value of <strong>0</strong> prevents unprivileged users from adding machine accounts "
            "and removes one prerequisite for NoPac. A non-zero value (default is 10) means "
            "domain users can add machine accounts and should be reduced to 0."
        ),
    },
]

REMEDIATION = {
    "title": "Patch all Domain Controllers against NoPac and harden machine account creation",
    "steps": [
        {
            "text": (
                "Apply the November 2021 cumulative security update to <strong>all</strong> "
                "Domain Controllers. The relevant KBs by OS are:"
            ),
            "code": (
                "# Windows Server 2022 / 2019: KB5008380\n"
                "# Windows Server 2016:        KB5008602\n"
                "# Windows Server 2012 R2:     KB5008380\n"
                "# Verify installed KBs:\n"
                "Get-HotFix -Id KB5008380, KB5008602"
            ),
        },
        {
            "text": "After patching, verify each DC is no longer vulnerable by re-running the check:",
            "code": "nxc smb <DC_IP> -d <domain> -u <username> -p <password> -M nopac",
        },
        {
            "text": (
                "Set <strong>ms-DS-MachineAccountQuota</strong> to <strong>0</strong> on the domain "
                "to prevent unprivileged users from joining machines to the domain "
                "(removes a prerequisite for NoPac and related attacks):"
            ),
            "code": (
                "Set-ADDomain -Identity (Get-ADDomain).DistinguishedName "
                "-Replace @{'ms-DS-MachineAccountQuota'='0'}"
            ),
        },
        {
            "text": (
                "Review recent computer account creations for signs of exploitation. "
                "Accounts created with spoofed sAMAccountNames may appear as "
                "existing DC names without a trailing '$':"
            ),
            "code": (
                "Get-ADComputer -Filter * -Properties Created, sAMAccountName |\n"
                "    Where-Object { $_.Created -gt (Get-Date).AddDays(-30) } |\n"
                "    Select-Object Name, sAMAccountName, Created | Sort-Object Created"
            ),
        },
    ],
}

REFERENCES = [
    {
        "title": "CVE-2021-42278 — Active Directory Domain Services Elevation of Privilege",
        "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42278",
        "tag": "vendor",
    },
    {
        "title": "CVE-2021-42287 — Active Directory Domain Services Elevation of Privilege",
        "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42287",
        "tag": "vendor",
    },
    {
        "title": "noPac — Exploit Scanner (Ridter)",
        "url": "https://github.com/Ridter/noPac",
        "tag": "tool",
    },
    {
        "title": "Sam the Admin — NoPac Attack Explained (SecureWorks)",
        "url": "https://www.secureworks.com/blog/nopac-a-tale-of-two-vulnerabilities-that-could-end-in-ransomware",
        "tag": "research",
    },
    {
        "title": "MITRE ATT&CK: Steal or Forge Kerberos Tickets (T1558)",
        "url": "https://attack.mitre.org/techniques/T1558/",
        "tag": "attack",
    },
    {
        "title": "ms-DS-MachineAccountQuota — Microsoft Docs",
        "url": "https://learn.microsoft.com/en-us/windows/win32/adschema/a-ms-ds-machineaccountquota",
        "tag": "vendor",
    },
]
