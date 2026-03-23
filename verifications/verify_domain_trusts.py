"""
verifications/verify_domain_trusts.py
Manual verification, remediation, and references for domain trust findings.
Covers: bidirectional trust without SID filtering, forest trusts, TGT delegation.
"""

MATCH_KEYS = [
    "domain trust",
    "bidirectional trust",
    "forest trust",
    "tgt delegation",
    "sid filtering",
    "external bidirectional trust",
    "mit kerberos realm",
    "trust inventory",
    "domain trust inventory",
]

TOOLS = [
    {
        "tool": "PowerShell (AD Module)",
        "icon": "ps",
        "desc": "Enumerate all domain trusts and their key attributes.",
        "code": (            "Get-ADTrust -Filter * |\n"            "  Select-Object Name, Direction, TrustType, TrustAttributes,\n"            "    DisallowTransivity, SIDFilteringForestAware,\n"            "    SIDFilteringQuarantined |\n"            "  Format-Table -AutoSize"
        ),
        "confirm": "Bidirectional trusts with SIDFilteringQuarantined=False are the highest risk.",
    },
    {
        "tool": "cmd (netdom)",
        "icon": "cmd",
        "desc": "Check SID filtering status on a specific trust.",
        "code": "netdom trust <TrustingDomain> /domain:<TrustedDomain> /quarantine",
        "confirm": "Output shows whether quarantine (SID filtering) is enabled on the trust.",
    },
    {
        "tool": "Impacket (getTrust.py / secretsdump.py)",
        "icon": "impacket",
        "desc": "Enumerate trusts via LDAP from Linux.",
        "code": (            "python3 -c \"\n"            "from impacket.ldap import ldap\n"            "# Use GetADUsers or net rpc or rpcclient to list trusts\"\n"            "\n"            "# Or use rpcclient:\n"            "rpcclient -U '<DOMAIN>/<USER>%<PASSWORD>' <DC_IP> \\\n"            "  -c 'enumtrusts'"
        ),
        "confirm": "Lists all trusts visible from the DC; cross-reference with approved trust documentation.",
    },
]

REMEDIATION = {
    "title": "Enable SID filtering and restrict TGT delegation on all external trusts",
    "steps": [
        {
            "text": "Enable SID filtering (quarantine) on all bidirectional and forest trusts:",
            "code": "netdom trust <TrustingDomain> /domain:<TrustedDomain> /quarantine:yes",
        },
        {
            "text": "Disable TGT delegation across trust boundaries if not required:",
            "code": (                "# Remove TRUST_ATTRIBUTE_ENABLE_TGT_DELEGATION flag\n"                "# Get current trustAttributes value then clear bit 0x400:\n"                "$trust = Get-ADObject -Filter {trustPartner -eq '<partner>'} \\\n"                "  -Properties trustAttributes\n"                "$newVal = $trust.trustAttributes -band (-bnot 0x400)\n"                "Set-ADObject $trust.DistinguishedName -Replace @{trustAttributes=$newVal}"
            ),
        },
        {
            "text": "For forest trusts, enable Selective Authentication to restrict which accounts can authenticate across the trust: Active Directory Domains and Trusts → right-click the trust → Properties → Authentication → Selective Authentication.",
        },
        {
            "text": "Decommission any trust that is no longer operationally required.",
        },
    ],
}

REFERENCES = [
    {
        "title": "Microsoft — How Domain and Forest Trusts Work",
        "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc759554(v=ws.10)",
        "tag": "vendor",
    },
    {
        "title": "Microsoft — netdom trust (SID filtering / quarantine)",
        "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc835085(v=ws.11)",
        "tag": "vendor",
    },
    {
        "title": "MITRE ATT&CK — Domain or Tenant Policy Modification: Domain Trust Modification (T1484.002)",
        "url": "https://attack.mitre.org/techniques/T1484/002/",
        "tag": "attack",
    },
    {
        "title": "harmj0y — A Guide to Attacking Domain Trusts",
        "url": "https://harmj0y.medium.com/a-guide-to-attacking-domain-trusts-ef5f8992bb4e",
        "tag": "research",
    },
    {
        "title": "SpecterOps — SID Filter as a Security Boundary Between Domains (Part 1)",
        "url": "https://posts.specterops.io/sid-filter-as-a-security-boundary-between-domains-part-1-ee9b2a56b99f",
        "tag": "research",
    },
]
