"""
verifications/verify_service_accounts_gmsa.py
Manual Verification and Remediation data for ADScan findings matching: No gMSA Adoption
"""

MATCH_KEYS = ["no gmsa adoption"]

TOOLS = [
    {
        "tool": "PowerShell",
        "icon": "ps",
        "desc": "Identify user accounts with SPNs set (likely service accounts) that are not gMSAs.",
        "code": "Get-ADUser -Filter {ServicePrincipalName -like '*'} -Properties ServicePrincipalName,PasswordNeverExpires,LastLogonDate \`\n    | Select-Object Name,SamAccountName,ServicePrincipalName,PasswordNeverExpires,LastLogonDate",
        "confirm": "Any standard user account (not a gMSA) returned with an SPN is a candidate for migration to gMSA.",
    },
    {
        "tool": "PowerShell",
        "icon": "ps",
        "desc": "List existing Group Managed Service Accounts for comparison.",
        "code": "Get-ADServiceAccount -Filter * -Properties ServicePrincipalName,PrincipalsAllowedToRetrieveManagedPassword \`\n    | Select-Object Name,ServicePrincipalName",
        "confirm": "Compare with the user-based service accounts to identify which services have and have not been migrated.",
    },
]

REMEDIATION = {
    "title": "Migrate service accounts to Group Managed Service Accounts (gMSA)",
    "steps": [
        {
            "text": "Ensure the KDS Root Key exists (required for gMSA password generation):",
            "code": "# Check:\nGet-KdsRootKey\n# Create if absent (immediate availability for lab; use -EffectiveTime for production):\nAdd-KdsRootKey -EffectiveImmediately",
        },
        {
            "text": "Create a gMSA for each service account to be migrated:",
            "code": "New-ADServiceAccount -Name \"<gMSA-Name>\" \`\n    -DNSHostName \"<service-fqdn>\" \`\n    -PrincipalsAllowedToRetrieveManagedPassword \"<HostGroup>\" \`\n    -ServicePrincipalNames \"<SPN>\"",
        },
        {
            "text": "Install the gMSA on the target host and update the service to use it:",
            "code": "Install-ADServiceAccount -Identity <gMSA-Name>\n# Then update the service logon account in services.msc or via SC.exe",
        },
        {
            "text": "Once migrated and verified, disable the original user-based service account and remove its SPN.",
        },
    ],
}
