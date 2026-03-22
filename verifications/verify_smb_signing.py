"""
verifications/verify_smb_signing.py
Manual Verification and Remediation data for ADScan findings matching: smb signing
"""

MATCH_KEYS = ["smb signing"]

TOOLS = [
    {
        "tool": "NetExec",
        "icon": "netexec",
        "desc": "Check SMB signing status across all domain hosts.",
        "code": "netexec smb <subnet>/24 -u <username> -p <password> --gen-relay-list relay_targets.txt",
        "confirm": "Hosts in relay_targets.txt do not require SMB signing — vulnerable to relay attacks.",
    },
    {
        "tool": "Impacket",
        "icon": "impacket",
        "desc": "Use Responder + ntlmrelayx to demonstrate the relay risk (authorised testing only).",
        "code": "# Step 1: Enable Responder\nResponder.py -I <interface> -rdw\n\n# Step 2: Relay to target\nntlmrelayx.py -tf relay_targets.txt -smb2support",
        "confirm": "Successful relay confirms SMB signing is not enforced.",
    },
    {
        "tool": "PowerShell",
        "icon": "ps",
        "desc": "Check SMB signing configuration on the local machine or a remote host.",
        "code": "Get-SmbServerConfiguration | Select-Object RequireSecuritySignature,EnableSecuritySignature\n\n# For remote host:\nGet-SmbServerConfiguration -CimSession <hostname>",
        "confirm": "<strong>RequireSecuritySignature: False</strong> confirms SMB signing is not enforced.",
    },
    {
        "tool": "nmap",
        "icon": "cmd",
        "desc": "Scan for SMB signing status using nmap scripts.",
        "code": "nmap --script smb2-security-mode -p 445 <subnet>/24",
        "confirm": "Look for <strong>Message signing enabled but not required</strong> — this confirms the vulnerability.",
    },
]

REMEDIATION = {
    "title": "Enforce SMB signing via Group Policy",
    "steps": [
        {
            "text": "Enable SMB signing via PowerShell on the server:",
            "code": "Set-SmbServerConfiguration -RequireSecuritySignature $true -Force\nSet-SmbClientConfiguration -RequireSecuritySignature $true -Force",
        },
        {
            "text": "Enforce via Group Policy: <em>Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options</em> → set <strong>Microsoft network server: Digitally sign communications (always)</strong> to <strong>Enabled</strong>.",
        },
        {
            "text": "Prioritise enforcement on <strong>Domain Controllers and file servers</strong> first — these are the highest-value relay targets.",
        },
    ],
}


REFERENCES = [
    {"title": "SMB Signing Configuration - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing-overview", "tag": "vendor"},
    {"title": "Configure SMB Signing with Group Policy", "url": "https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing-deployment", "tag": "vendor"},
    {"title": "MITRE ATT&CK: NTLM Relay (T1557.001)", "url": "https://attack.mitre.org/techniques/T1557/001/", "tag": "attack"},
    {"title": "Responder - SMB Relay Attack Framework", "url": "https://github.com/lgandx/Responder", "tag": "tool"},
    {"title": "Impacket ntlmrelayx - SMB Relay Tool", "url": "https://github.com/fortra/impacket", "tag": "tool"},
    {"title": "NetExec - SMB Signing Check", "url": "https://github.com/Pennyw0rth/NetExec", "tag": "tool"},
    {"title": "CIS Benchmark: Require SMB Signing", "url": "https://www.cisecurity.org/benchmark/microsoft_windows_server", "tag": "defense"},
    {"title": "NSA: SMB Security Hardening Guide", "url": "https://media.defense.gov/2023/Jun/22/2003251092/-1/-1/0/CTR_DEFENDING_ACTIVE_DIRECTORY.PDF", "tag": "defense"},
]
