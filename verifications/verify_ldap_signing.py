"""
verifications/verify_ldap_signing.py
Manual Verification and Remediation data for ADScan findings matching: LDAP Signing
"""

MATCH_KEYS = ["ldap signing"]

TOOLS = [
    {
        "tool": "PowerShell",
        "icon": "ps",
        "desc": "Check the LDAP server signing requirement registry value on Domain Controllers.",
        "code": 'Invoke-Command -ComputerName <DC_FQDN> -ScriptBlock {\n    Get-ItemProperty -Path HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters `\n        -Name LDAPServerIntegrity -ErrorAction SilentlyContinue\n}',
        "confirm": "A value of <strong>2</strong> means signing is required. <strong>1</strong> = negotiated (weak), <strong>0</strong> = none. Values below 2 confirm the finding.",
    },
    {
        "tool": "PowerShell",
        "icon": "ps",
        "desc": "Check the Channel Binding Token (CBT) policy via GPO registry.",
        "code": 'Invoke-Command -ComputerName <DC_FQDN> -ScriptBlock {\n    Get-ItemProperty -Path HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters `\n        -Name LdapEnforceChannelBinding -ErrorAction SilentlyContinue\n}',
        "confirm": "A value of <strong>2</strong> means channel binding is always required. <strong>1</strong> = when supported, <strong>0</strong> = disabled. Values below 2 confirm the finding.",
    },
]

REMEDIATION = {
    "title": "Enforce LDAP signing and channel binding via Group Policy",
    "steps": [
        {
            "text": "Create or edit a GPO linked to the <strong>Domain Controllers OU</strong> and navigate to:",
            "code": "Computer Configuration -> Windows Settings -> Security Settings\n-> Local Policies -> Security Options\n-> Domain controller: LDAP server signing requirements -> Require signing",
        },
        {
            "text": "Enable LDAP Channel Binding via the same GPO:",
            "code": "Computer Configuration -> Administrative Templates\n-> System -> KDC\n-> Domain Controller: LDAP server channel binding token requirements -> Always",
        },
        {
            "text": "Verify no legacy LDAP clients rely on unsigned LDAP before enforcing. Use event ID <strong>2886</strong> and <strong>2887</strong> in the Directory Service event log to identify non-compliant clients.",
        },
    ],
}


REFERENCES = [
    {"title": "Microsoft: LDAP Signing Requirements (ADV190023)", "url": "https://support.microsoft.com/en-us/topic/2020-ldap-channel-binding-and-ldap-signing-requirements-for-windows-ef185fb8-00f7-167d-744c-f299a66fc00a", "tag": "vendor"},
    {"title": "LDAP Channel Binding and Signing - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/domain-controller-ldap-server-signing-requirements", "tag": "vendor"},
    {"title": "MITRE ATT&CK: Adversary-in-the-Middle (T1557)", "url": "https://attack.mitre.org/techniques/T1557/", "tag": "attack"},
    {"title": "LDAP Relay Attack via LdapRelayScan", "url": "https://github.com/zyn3rgy/LdapRelayScan", "tag": "tool"},
    {"title": "Responder - LLMNR/NBT-NS Poisoning Tool", "url": "https://github.com/lgandx/Responder", "tag": "tool"},
    {"title": "CIS Benchmark: Ensure LDAP signing is required", "url": "https://www.cisecurity.org/benchmark/microsoft_windows_server", "tag": "defense"},
    {"title": "NSA: Hardening Active Directory - LDAP Signing", "url": "https://media.defense.gov/2023/Jun/22/2003251092/-1/-1/0/CTR_DEFENDING_ACTIVE_DIRECTORY.PDF", "tag": "defense"},
    {"title": "Audit LDAP Channel Binding Events", "url": "https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-2889", "tag": "defense"},
]
