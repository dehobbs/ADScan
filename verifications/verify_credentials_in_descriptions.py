"""
verifications/verify_credentials_in_descriptions.py
Manual Verification and Remediation data for ADScan findings matching: Passwords in Descriptions
"""

MATCH_KEYS = ["passwords in descriptions:"]

TOOLS = [
    {
        "tool": "PowerShell",
        "icon": "ps",
        "desc": "Search all user description fields for common credential keywords.",
        "code": "Get-ADUser -Filter * -Properties Description | Where-Object {\n    $_.Description -match 'pass|pwd|cred|secret|key|token'\n} | Select-Object Name,SamAccountName,Description",
        "confirm": "Any user returned with a description matching credential keywords confirms the finding.",
    },
    {
        "tool": "NetExec",
        "icon": "netexec",
        "desc": "Enumerate user descriptions for credential data via LDAP.",
        "code": "netexec ldap <DC_IP> -u <username> -p <password> -M user-desc",
        "confirm": "Review the output for any description fields containing passwords or secrets.",
    },
]

REMEDIATION = {
    "title": "Remove credentials from AD description fields",
    "steps": [
        {
            "text": "For each affected account, clear the description field in <strong>ADUC (dsa.msc)</strong>: locate the account, open Properties, clear the Description field, and save.",
        },
        {
            "text": "Or bulk-clear descriptions via PowerShell:",
            "code": "Set-ADUser -Identity <SamAccountName> -Description $null",
        },
        {
            "text": "Rotate any credentials that were stored in description fields immediately — they should be treated as compromised since all authenticated users can read them.",
        },
        {
            "text": "Establish a process to prevent future storage of credentials in AD attribute fields. Use a dedicated secrets manager instead.",
        },
    ],
}


REFERENCES = [
    {"title": "AD User Account Description Attribute - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/windows/win32/adschema/a-description", "tag": "vendor"},
    {"title": "AD Security Best Practices - Sensitive Data in Descriptions", "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory", "tag": "vendor"},
    {"title": "MITRE ATT&CK: Unsecured Credentials (T1552)", "url": "https://attack.mitre.org/techniques/T1552/", "tag": "attack"},
    {"title": "MITRE ATT&CK: Credentials in Files (T1552.001)", "url": "https://attack.mitre.org/techniques/T1552/001/", "tag": "attack"},
    {"title": "BloodHound - User Description Field Enumeration", "url": "https://github.com/BloodHoundAD/BloodHound", "tag": "tool"},
    {"title": "AD Recon - Sensitive Data Discovery in AD", "url": "https://github.com/sense-of-security/ADRecon", "tag": "tool"},
    {"title": "CIS Benchmark: Do not store credentials in AD descriptions", "url": "https://www.cisecurity.org/benchmark/microsoft_windows_server", "tag": "defense"},
    {"title": "Hunting Cleartext Credentials in Active Directory", "url": "https://adsecurity.org/?p=2362", "tag": "research"},
]
