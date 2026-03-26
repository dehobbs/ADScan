"""
verifications/verify_esc13.py
Manual Verification and Remediation data for ADScan findings matching: ESC13
"""

MATCH_KEYS = ["esc13"]

TOOLS = [
    {
        "tool": "PowerShell",
        "icon": "ps",
        "desc": "Enumerate issuance policy OIDs and check for group links via msDS-OIDToGroupLink.",
        "code": "Get-ADObject -SearchBase \"CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<tld>\" \\`\n    -Filter * -Properties displayName,msPKI-Cert-Template-OID,msDS-OIDToGroupLink \\`\n    | Where-Object { $_.msDS-OIDToGroupLink -ne $null } \\`\n    | Select-Object displayName,msPKI-Cert-Template-OID,msDS-OIDToGroupLink",
        "confirm": "Any OID with a non-null <strong>msDS-OIDToGroupLink</strong> value is linked to a group. Confirm that the linked group is not privileged.",
    },
    {
        "tool": "certutil",
        "icon": "cmd",
        "desc": "List all certificate policy OIDs registered in the domain.",
        "code": "certutil -dspolicy",
        "confirm": "Review listed OIDs for any that should not be linked to privileged groups. Run from a domain-joined host.",
    },
]

REMEDIATION = {
    "title": "Remove unnecessary OID-to-group links",
    "steps": [
        {
            "text": "Identify OIDs linked to privileged groups using the PowerShell command above.",
        },
        {
            "text": "For each unnecessary link, clear the <strong>msDS-OIDToGroupLink</strong> attribute on the OID object:",
            "code": "Set-ADObject -Identity \"CN=<OID-Name>,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<tld>\" \\`\n    -Clear msDS-OIDToGroupLink",
        },
        {
            "text": "If the issuance policy OID itself is not required, remove it from the certificate template's <strong>msPKI-Certificate-Application-Policy</strong> attribute.",
        },
    ],
}


REFERENCES = [
    {"title": "AD CS Certificate Template Issuance Policies - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts", "tag": "vendor"},
    {"title": "Issuance Policy OID Linking - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-certificate-requirements-and-enumeration", "tag": "vendor"},
    {"title": "MITRE ATT&CK: Steal or Forge Authentication Certificates (T1649)", "url": "https://attack.mitre.org/techniques/T1649/", "tag": "attack"},
    {"title": "ESC13 - Issuance Policy OID Abuse Research", "url": "https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53", "tag": "research"},
    {"title": "Certipy - ADCS Exploitation Tool", "url": "https://github.com/ly4k/Certipy", "tag": "tool"},
    {"title": "PKI Auditing with certutil", "url": "https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil", "tag": "tool"},
    {"title": "Securing Certificate Template Issuance Policies", "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/active-directory-certificate-services-overview", "tag": "defense"},
    {"title": "AD CS Attack and Defense - Microsoft Security Blog", "url": "https://www.microsoft.com/en-us/security/blog/2022/08/16/defending-against-active-directory-certificate-services-attacks/", "tag": "defense"},
]
