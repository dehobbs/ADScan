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


REFERENCES = [
    {"title": "Group Managed Service Accounts Overview - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview", "tag": "vendor"},
    {"title": "Getting Started with gMSA - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/getting-started-with-group-managed-service-accounts", "tag": "vendor"},
    {"title": "MITRE ATT&CK: Kerberoasting (T1558.003)", "url": "https://attack.mitre.org/techniques/T1558/003/", "tag": "attack"},
    {"title": "Service Account Abuse - Active Directory Security", "url": "https://adsecurity.org/?p=2544", "tag": "attack"},
    {"title": "Rubeus - Kerberoasting Service Accounts", "url": "https://github.com/GhostPack/Rubeus", "tag": "tool"},
    {"title": "CIS Benchmark: Use gMSA for service accounts", "url": "https://www.cisecurity.org/benchmark/microsoft_windows_server", "tag": "defense"},
    {"title": "NSA: Service Account Hardening", "url": "https://media.defense.gov/2023/Jun/22/2003251092/-1/-1/0/CTR_DEFENDING_ACTIVE_DIRECTORY.PDF", "tag": "defense"},
    {"title": "Migrating to gMSA - Step by Step", "url": "https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/create-the-key-distribution-services-kds-root-key", "tag": "defense"},
]
