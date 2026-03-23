"""
verifications/verify_deprecated_os.py
Manual verification, remediation, and references for deprecated OS findings.
"""

MATCH_KEYS = [
    "deprecated",
    "end-of-life",
    "end of life",
    "windows xp",
    "windows 7",
    "windows 2003",
    "windows 2008",
    "eol operating system",
]

TOOLS = [
    {
        "tool": "PowerShell (AD Module)",
        "icon": "ps",
        "desc": "Enumerate all computer objects and their reported OS versions.",
        "code": (            "Get-ADComputer -Filter * \\\n"            "  -Properties Name, OperatingSystem,\n"            "    OperatingSystemVersion, LastLogonDate |\n"            "  Select-Object Name, OperatingSystem,\n"            "    OperatingSystemVersion, LastLogonDate |\n"            "  Sort-Object OperatingSystem |\n"            "  Format-Table -AutoSize"
        ),
        "confirm": "Any system running Windows XP, Vista, 7, Server 2003, or Server 2008 is end-of-life and should be upgraded or isolated.",
    },
    {
        "tool": "NetExec",
        "icon": "netexec",
        "desc": "Sweep the network to identify live hosts and their OS versions.",
        "code": (            "netexec smb <subnet>/<prefix> \\\n"            "  -u <USER> -p <PASSWORD> \\\n"            "  --gen-relay-list /tmp/hosts.txt"
        ),
        "confirm": "NetExec output shows OS banner for each responding host. Filter for known EOL strings.",
    },
]

REMEDIATION = {
    "title": "Upgrade or isolate all end-of-life operating systems",
    "steps": [
        {
            "text": "Build an inventory of all EOL systems by owner and business function. Prioritise those accessible from the network.",
        },
        {
            "text": "Upgrade systems to a supported OS version. For systems that cannot be upgraded immediately, enforce network isolation via VLAN segmentation and restrict inbound/outbound access using firewall ACLs.",
        },
        {
            "text": "Apply all available patches to EOL systems. For Windows 7/2008, Microsoft offered Extended Security Updates (ESU) — verify whether they are enrolled.",
        },
        {
            "text": "Disable SMBv1 on EOL systems where possible to reduce EternalBlue exposure: Set-SmbServerConfiguration -EnableSMB1Protocol $false",
        },
    ],
}

REFERENCES = [
    {
        "title": "Microsoft — Windows lifecycle fact sheet",
        "url": "https://support.microsoft.com/en-us/help/13853/windows-lifecycle-fact-sheet",
        "tag": "vendor",
    },
    {
        "title": "MITRE ATT&CK — Exploit Public-Facing Application (T1190)",
        "url": "https://attack.mitre.org/techniques/T1190/",
        "tag": "attack",
    },
    {
        "title": "CISA — End-of-Life Software Guidance",
        "url": "https://www.cisa.gov/resources-tools/resources/end-life-eol-software-guidance",
        "tag": "defense",
    },
]
