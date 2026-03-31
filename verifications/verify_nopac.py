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
        "desc": (
            "Use the NetExec nopac module to request a TGT both with and without a PAC "
            "from the target Domain Controller, then compare ticket sizes. "
            "A vulnerable DC will return a smaller ticket when PAC is omitted."
        ),
        "code": (
            "nxc smb <DC_IP> \\\n"
            "  -d <domain> \\\n"
            "  -u <username> \\\n"
            "  -p <password> \\\n"
            "  -M nopac"
        ),
        "confirm": (
            "The module outputs two ticket sizes — look for lines similar to:<br>"
            "<code>TGT with PAC size 1482</code> and <code>TGT without PAC size 1282</code>.<br><br>"
            "If the <strong>sizes differ</strong>, the DC is <strong>vulnerable</strong> — the "
            "smaller PAC-less TGT means the DC will issue tickets that can be abused for privilege escalation.<br>"
            "If both sizes are <strong>equal</strong>, the DC has been patched and is not vulnerable."
        ),
    },
    {
        "tool": "PowerShell",
        "icon": "ps",
        "desc": (
            "The most straightforward defensive check — if the November 2021 patches are missing "
            "from any Domain Controller, that DC is vulnerable. Queries all DCs for the relevant KBs."
        ),
        "code": (
            "$DCs = Get-ADDomainController -Filter *\n"
            "foreach ($DC in $DCs) {\n"
            "    $patches = Get-HotFix -ComputerName $DC.HostName |\n"
            "      Where-Object { $_.HotFixID -in @(\"KB5008102\",\"KB5008380\",\"KB5008602\") }\n"
            "    [PSCustomObject]@{\n"
            "        DomainController = $DC.HostName\n"
            "        PatchesFound     = if ($patches) { ($patches.HotFixID -join \", \") } else { \"None\" }\n"
            "        Vulnerable       = ($patches.Count -eq 0)\n"
            "    }\n"
            "}"
        ),
        "confirm": (
            "If <strong>Vulnerable = True</strong> for any Domain Controller, that DC has not received "
            "the November 9, 2021 patches and is susceptible to NoPac. "
            "Every DC must show <strong>Vulnerable = False</strong> before the environment is considered remediated."
        ),
    },
]

REMEDIATION = {
    "title": "Patch all Domain Controllers against NoPac and harden machine account quota",
    "steps": [
        {
            "text": (
                "Apply the November 2021 cumulative security update to <strong>every</strong> "
                "Domain Controller. NoPac requires only a single unpatched DC to remain exploitable. "
                "The relevant KB by Windows Server version is:"
            ),
            "code": (
                "# Windows Server 2022:   KB5008223\n"
                "# Windows Server 2019:   KB5008218\n"
                "# Windows Server 2016:   KB5008207\n"
                "# Windows Server 2012 R2: KB5008264\n\n"
                "# Verify installed KBs on a DC (run on each DC):\n"
                "Get-HotFix | Where-Object { $_.HotFixID -in @('KB5008223','KB5008218','KB5008207','KB5008264') }"
            ),
        },
        {
            "text": (
                "After patching, re-run the NetExec nopac module against each DC to confirm "
                "the TGT sizes are now equal (indicating the PAC bypass is no longer possible):"
            ),
            "code": "nxc smb <DC_IP> -d <domain> -u <username> -p <password> -M nopac",
        },
        {
            "text": (
                "Set <strong>ms-DS-MachineAccountQuota</strong> to <strong>0</strong> to prevent "
                "unprivileged domain users from joining machines to the domain. "
                "This removes the ability to create the spoofed machine account NoPac relies on, "
                "and also mitigates related attacks such as RBCD abuse:"
            ),
            "code": (
                "Set-ADDomain -Identity (Get-ADDomain).DistinguishedName \\\n"
                "    -Replace @{'ms-DS-MachineAccountQuota' = '0'}\n\n"
                "# Verify the change:\n"
                "Get-ADObject -Identity (Get-ADDomain).DistinguishedName "
                "-Properties 'ms-DS-MachineAccountQuota' | Select-Object 'ms-DS-MachineAccountQuota'"
            ),
        },
        {
            "text": (
                "Review computer accounts created recently for signs of prior exploitation. "
                "NoPac-created accounts typically mimic existing DC names without the trailing '$', "
                "or use random-looking names. Investigate any unexpected computer accounts:"
            ),
            "code": (
                "# List computer accounts created in the last 30 days:\n"
                "Get-ADComputer -Filter * -Properties Created, SamAccountName, Description |\n"
                "    Where-Object { $_.Created -gt (Get-Date).AddDays(-30) } |\n"
                "    Select-Object Name, SamAccountName, Created, Description |\n"
                "    Sort-Object Created -Descending"
            ),
        },
        {
            "text": (
                "Enable and review AD security audit logs for Kerberos AS-REQ events (Event ID 4768) "
                "where the ticket options include the <strong>no-pre-authentication</strong> or "
                "<strong>forwardable</strong> flags from unexpected accounts. "
                "Also monitor for Event ID 4741 (computer account created) from non-admin users."
            ),
        },
    ],
}

REFERENCES = [
    {
        "title": "CVE-2021-42278 — sAMAccountName Spoofing (Microsoft MSRC)",
        "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42278",
        "tag": "vendor",
    },
    {
        "title": "CVE-2021-42287 — Kerberos PAC Validation Bypass (Microsoft MSRC)",
        "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42287",
        "tag": "vendor",
    },
    {
        "title": "KB5008102 — Active Directory Security Accounts Manager Hardening Changes",
        "url": "https://support.microsoft.com/en-us/topic/kb5008102-active-directory-security-accounts-manager-hardening-changes-cve-2021-42278-5975b463-4c95-45e1-831a-d120004e258e",
        "tag": "vendor",
    },
    {
        "title": "noPac — Exploit and Scanner (Ridter)",
        "url": "https://github.com/Ridter/noPac",
        "tag": "tool",
    },
    {
        "title": "Sam the Admin: NoPac Attack Explained (SecureWorks)",
        "url": "https://www.secureworks.com/blog/nopac-a-tale-of-two-vulnerabilities-that-could-end-in-ransomware",
        "tag": "research",
    },
    {
        "title": "MITRE ATT&CK: Steal or Forge Kerberos Tickets (T1558)",
        "url": "https://attack.mitre.org/techniques/T1558/",
        "tag": "attack",
    },
    {
        "title": "MITRE ATT&CK: Valid Accounts — Domain Accounts (T1078.002)",
        "url": "https://attack.mitre.org/techniques/T1078/002/",
        "tag": "attack",
    },
    {
        "title": "ms-DS-MachineAccountQuota — Microsoft Docs",
        "url": "https://learn.microsoft.com/en-us/windows/win32/adschema/a-ms-ds-machineaccountquota",
        "tag": "vendor",
    },
]
