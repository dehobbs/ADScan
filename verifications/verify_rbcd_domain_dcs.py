"""
verifications/verify_rbcd_domain_dcs.py
Manual verification, remediation, and references for the
"RBCD on Domain Object / DCs" finding.
"""

MATCH_KEYS = [
    "rbcd on domain",
    "resource-based constrained delegation",
    "s4u2proxy rights on",
]

TOOLS = [
    {
        "tool": "PowerShell (AD Module)",
        "icon": "ps",
        "desc": "Check whether msDS-AllowedToActOnBehalfOfOtherIdentity is set on the domain NC head or any DC.",
        "code": (            "# Check domain NC head\n"            "Get-ADObject -Identity (Get-ADDomain).DistinguishedName \\\n"            "  -Properties msDS-AllowedToActOnBehalfOfOtherIdentity |\n"            "  Select-Object -ExpandProperty msDS-AllowedToActOnBehalfOfOtherIdentity\n"            "\n"            "# Check all DCs\n"            "Get-ADDomainController -Filter * | ForEach-Object {\n"            "    Get-ADComputer $_.Name \\\n"            "        -Properties msDS-AllowedToActOnBehalfOfOtherIdentity |\n"            "        Select-Object Name, msDS-AllowedToActOnBehalfOfOtherIdentity\n"            "}"
        ),
        "confirm": "Any non-null output indicates an unexpected RBCD entry — investigate immediately.",
    },
    {
        "tool": "Impacket (rbcd.py)",
        "icon": "impacket",
        "desc": "Enumerate RBCD settings on DC objects from Linux using Impacket.",
        "code": (            "rbcd.py -delegate-to 'DC$' \\\n"            "  -action read \\\n"            "  -dc-ip <DC_IP> \\\n"            "  '<DOMAIN>/<USER>:<PASSWORD>'"
        ),
        "confirm": "Any output showing allowed principals indicates RBCD is configured.",
    },
]

REMEDIATION = {
    "title": "Remove unexpected RBCD entries from DCs and domain NC head",
    "steps": [
        {
            "text": "For each Domain Controller with unexpected RBCD:",
            "code": "Set-ADComputer <DC_Name> -Clear msDS-AllowedToActOnBehalfOfOtherIdentity",
        },
        {
            "text": "For the domain NC head if affected:",
            "code": "Set-ADObject -Identity (Get-ADDomain).DistinguishedName -Clear msDS-AllowedToActOnBehalfOfOtherIdentity",
        },
        {
            "text": "Restrict write access to this attribute on all DC and domain NC objects via a targeted deny ACE or Tier-0 PAW model.",
        },
        {
            "text": "Enable auditing on msDS-AllowedToActOnBehalfOfOtherIdentity changes (Event ID 5136 in the Security log).",
        },
    ],
}

REFERENCES = [
    {
        "title": "Elad Shamir — Wagging the Dog: Abusing Resource-Based Constrained Delegation",
        "url": "https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html",
        "tag": "research",
    },
    {
        "title": "Microsoft — msDS-AllowedToActOnBehalfOfOtherIdentity Attribute",
        "url": "https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-allowedtoactonbehalfofotheridentity",
        "tag": "vendor",
    },
    {
        "title": "MITRE ATT&CK — Use Alternate Authentication Material: Kerberos (T1550.003)",
        "url": "https://attack.mitre.org/techniques/T1550/003/",
        "tag": "attack",
    },
    {
        "title": "Impacket rbcd.py — Resource-Based Constrained Delegation Tool",
        "url": "https://github.com/fortra/impacket/blob/master/examples/rbcd.py",
        "tag": "tool",
    },
]
