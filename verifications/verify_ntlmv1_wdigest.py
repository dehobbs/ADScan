"""
verifications/verify_ntlmv1_wdigest.py
Manual Verification and Remediation data for ADScan findings matching: NTLMv1 and WDigest
"""

MATCH_KEYS = ["ntlmv1 and wdigest"]

TOOLS = [
    {
        "tool": "PowerShell",
        "icon": "ps",
        "desc": "Check the LmCompatibilityLevel (NTLMv1) registry value on Domain Controllers.",
        "code": "Invoke-Command -ComputerName <DC_FQDN> -ScriptBlock {\n    Get-ItemProperty \\`\n        -Path \"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" \\`\n        -Name LmCompatibilityLevel -ErrorAction SilentlyContinue\n}",
        "confirm": "Values below <strong>3</strong> allow NTLMv1. A value of <strong>5</strong> is recommended (send NTLMv2 only, refuse LM and NTLMv1).",
    },
    {
        "tool": "PowerShell",
        "icon": "ps",
        "desc": "Check if WDigest authentication is enabled (UseLogonCredential = 1 stores cleartext in LSASS).",
        "code": "Invoke-Command -ComputerName <DC_FQDN> -ScriptBlock {\n    Get-ItemProperty \\`\n        -Path \"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\" \\`\n        -Name UseLogonCredential -ErrorAction SilentlyContinue\n}",
        "confirm": "A value of <strong>1</strong> means WDigest is enabled and cleartext credentials are cached in memory. Absence of the key or a value of <strong>0</strong> means it is disabled.",
    },
]

REMEDIATION = {
    "title": "Disable NTLMv1 and WDigest via Group Policy",
    "steps": [
        {
            "text": "Set <strong>LmCompatibilityLevel = 5</strong> via GPO to enforce NTLMv2 only:",
            "code": "Computer Configuration -> Windows Settings -> Security Settings\n-> Local Policies -> Security Options\n-> Network security: LAN Manager authentication level\n-> Set to: Send NTLMv2 response only. Refuse LM & NTLM",
        },
        {
            "text": "Disable WDigest authentication via GPO registry preference:",
            "code": "Computer Configuration -> Administrative Templates -> MS Security Guide\n-> WDigest Authentication -> Disabled\n# Or via registry:\nreg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\" /v UseLogonCredential /t REG_DWORD /d 0 /f",
        },
        {
            "text": "Test NTLMv1 compatibility with existing applications before enforcing. Use <strong>Event ID 4776</strong> in the Security log to identify NTLMv1 authentication attempts.",
        },
    ],
}


REFERENCES = [
    {"title": "Disable NTLMv1 - Microsoft Security Advisory", "url": "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level", "tag": "vendor"},
    {"title": "WDigest Authentication - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection", "tag": "vendor"},
    {"title": "MITRE ATT&CK: OS Credential Dumping (T1003)", "url": "https://attack.mitre.org/techniques/T1003/", "tag": "attack"},
    {"title": "Mimikatz - WDigest Credential Extraction", "url": "https://github.com/gentilkiwi/mimikatz", "tag": "tool"},
    {"title": "Responder - NTLMv1 Capture and Cracking", "url": "https://github.com/lgandx/Responder", "tag": "tool"},
    {"title": "CIS Benchmark: Disable NTLMv1 and WDigest", "url": "https://www.cisecurity.org/benchmark/microsoft_windows_server", "tag": "defense"},
    {"title": "NSA: Eliminating Obsolete Transport Layer Security - NTLMv1", "url": "https://media.defense.gov/2023/Jun/22/2003251092/-1/-1/0/CTR_DEFENDING_ACTIVE_DIRECTORY.PDF", "tag": "defense"},
    {"title": "Detecting WDigest Abuse - Splunk Research", "url": "https://research.splunk.com/endpoint/d09c7e3e-8d98-4dc3-b58a-0012534c0f87/", "tag": "defense"},
]
