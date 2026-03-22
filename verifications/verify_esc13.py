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
        "code": "Get-ADObject -SearchBase \"CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<tld>\" \`\n    -Filter * -Properties displayName,msPKI-Cert-Template-OID,msDS-OIDToGroupLink \`\n    | Where-Object { $_.msDS-OIDToGroupLink -ne $null } \`\n    | Select-Object displayName,msPKI-Cert-Template-OID,msDS-OIDToGroupLink",
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
            "code": "Set-ADObject -Identity \"CN=<OID-Name>,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<tld>\" \`\n    -Clear msDS-OIDToGroupLink",
        },
        {
            "text": "If the issuance policy OID itself is not required, remove it from the certificate template's <strong>msPKI-Certificate-Application-Policy</strong> attribute.",
        },
    ],
}
