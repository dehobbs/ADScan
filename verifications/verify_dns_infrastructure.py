"""
verifications/verify_dns_infrastructure.py
Manual verification, remediation, and references for DNS infrastructure findings.
Covers: ADIDNS wildcard records, insecure dynamic DNS updates (ADIDNS abuse).
"""

MATCH_KEYS = [
    "dns infrastructure",
    "adidns",
    "dns wildcard",
    "dynamic dns",
    "dns poisoning",
]

TOOLS = [
    {
        "tool": "PowerShell (DNS Server Module)",
        "icon": "ps",
        "desc": "Enumerate DNS zones and check for wildcard records or insecure dynamic update settings.",
        "code": (            "# List all DNS zones and their dynamic update setting\n"            "Get-DnsServerZone | Select-Object ZoneName, DynamicUpdate, IsReverseLookupZone\n"            "\n"            "# Check for wildcard records in the forest DNS zone\n"            "Get-DnsServerResourceRecord \\\n"            "  -ZoneName '_msdcs.<domain>' \\\n"            "  -Name '*' -ErrorAction SilentlyContinue"
        ),
        "confirm": "DynamicUpdate = Unsecured or None on internal zones is a risk. Wildcard A records allow spoofing any hostname.",
    },
    {
        "tool": "Impacket (dnstool.py)",
        "icon": "impacket",
        "desc": "Enumerate and add ADIDNS records from Linux (ADIDNS abuse check).",
        "code": (            "# Check whether any authenticated user can add ADIDNS records\n"            "python3 dnstool.py \\\n"            "  -u '<DOMAIN>\\<USER>' -p <PASSWORD> \\\n"            "  --action query \\\n"            "  --record '*' \\\n"            "  <DC_IP>"
        ),
        "confirm": "If any authenticated user can add A records for arbitrary hostnames, ADIDNS abuse is possible (credential capture via LLMNR poisoning bypass).",
    },
]

REMEDIATION = {
    "title": "Secure DNS dynamic updates and remove dangerous wildcard records",
    "steps": [
        {
            "text": "Set all internal DNS zones to Secure dynamic updates only:",
            "code": "Set-DnsServerPrimaryZone -Name <zone> -DynamicUpdate Secure",
        },
        {
            "text": "Remove any wildcard A/CNAME records from ADIDNS zones unless explicitly required.",
            "code": "Remove-DnsServerResourceRecord -ZoneName <zone> -RRType A -Name '*' -Force",
        },
        {
            "text": "Restrict who can create DNS records in ADIDNS by tightening ACLs on the MicrosoftDNS container in AD (CN=MicrosoftDNS,DC=DomainDnsZones,DC=<domain>).",
        },
    ],
}

REFERENCES = [
    {
        "title": "Kevin Robertson — Attacking Active Directory Integrated DNS (ADIDNS)",
        "url": "https://blog.netspi.com/exploiting-adidns/",
        "tag": "research",
    },
    {
        "title": "Microsoft — Set-DnsServerPrimaryZone (DynamicUpdate)",
        "url": "https://learn.microsoft.com/en-us/powershell/module/dnsserver/set-dnsserverprimaryzone",
        "tag": "vendor",
    },
    {
        "title": "MITRE ATT&CK — Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning (T1557.001)",
        "url": "https://attack.mitre.org/techniques/T1557/001/",
        "tag": "attack",
    },
]
