"""
verifications/verify_smbv1.py
Manual Verification and Remediation data for ADScan findings matching:
smbv1 enabled
"""

MATCH_KEYS = [
    "smbv1",
    "smb1",
    "smb version 1",
    "eternalblue",
]

TOOLS = [
    {
        "tool": "NetExec",
        "icon": "netexec",
        "desc": "Detect SMBv1 support on all domain hosts.",
        "code": "netexec smb <target_range> --gen-relay-list /tmp/smb_targets.txt\nnetexec smb <target_range> -u <username> -p <password> --smb-timeout 3",
        "confirm": "Hosts reporting <strong>SMBv1:True</strong> in the output have SMBv1 enabled and are potentially vulnerable to EternalBlue/WannaCry-class exploits.",
    },
    {
        "tool": "PowerShell (local check)",
        "icon": "ps",
        "desc": "Check if SMBv1 is enabled on the local host.",
        "code": "Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol\nGet-WindowsOptionalFeature -Online -FeatureName SMB1Protocol",
        "confirm": "<strong>EnableSMB1Protocol: True</strong> or feature state <strong>Enabled</strong> confirms SMBv1 is active.",
    },
    {
        "tool": "PowerShell (remote check)",
        "icon": "ps",
        "desc": "Check SMBv1 status on multiple remote hosts.",
        "code": "$computers = Get-ADComputer -Filter {Enabled -eq $true} | Select-Object -ExpandProperty Name\nforeach ($pc in $computers) {\n    try {\n        $cfg = Invoke-Command -ComputerName $pc -ScriptBlock {\n            Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol\n        } -ErrorAction Stop\n        [PSCustomObject]@{Host=$pc; SMBv1=$cfg.EnableSMB1Protocol}\n    } catch { [PSCustomObject]@{Host=$pc; SMBv1='ERROR'} }\n} | Where-Object { $_.SMBv1 -eq $true }",
        "confirm": "Each host in the output has SMBv1 enabled and should be remediated.",
    },
    {
        "tool": "Nmap",
        "icon": "netexec",
        "desc": "Scan for SMBv1 using Nmap scripting engine.",
        "code": "nmap -p 445 --script smb-protocols <target_range>",
        "confirm": "Hosts listing <strong>NT LM 0.12 (SMBv1)</strong> as a supported dialect are vulnerable.",
    },
]

REMEDIATION = {
    "title": "Disable SMBv1 on all hosts",
    "steps": [
        {
            "text": "<strong>Windows 10 / Server 2016+ (Feature):</strong> Disable via Windows Features:",
            "code": "# Disable SMBv1 server feature:\nDisable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart\n\n# Or via PowerShell for server:\nSet-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
        },
        {
            "text": "<strong>Windows 8.1 / Server 2012 R2 and older:</strong> Disable via registry and SMB server config:",
            "code": "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force\n\n# Also disable SMBv1 client:\nSet-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters' SMB1 -Type DWORD -Value 0 -Force",
        },
        {
            "text": "Deploy via <strong>Group Policy</strong> for domain-wide enforcement:",
            "code": "# In a GPO startup script or via ADMX:\n# Computer Configuration → Preferences → Windows Settings → Registry\n# Key: HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters\n# Value: SMB1 = 0 (DWORD)",
        },
        {
            "text": "<strong>Verify</strong> no legacy systems require SMBv1 (old NAS devices, printers, Windows XP/2003) — if they do, isolate them on a separate VLAN and block port 445 from the rest of the network.",
        },
    ],
}

REFERENCES = [
    {"title": "How to detect, enable and disable SMBv1, SMBv2, and SMBv3 - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3", "tag": "vendor"},
    {"title": "Stop using SMB1 - Microsoft Security Blog", "url": "https://techcommunity.microsoft.com/t5/storage-at-microsoft/stop-using-smb1/ba-p/425858", "tag": "vendor"},
    {"title": "MITRE ATT&CK: Exploitation for Credential Access (T1212)", "url": "https://attack.mitre.org/techniques/T1212/", "tag": "attack"},
    {"title": "EternalBlue Exploit Overview - MS17-010", "url": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010", "tag": "vendor"},
    {"title": "WannaCry Ransomware and SMBv1 - CISA Alert", "url": "https://www.cisa.gov/news-events/alerts/2017/05/12/indicators-associated-wannacry-ransomware", "tag": "research"},
    {"title": "CIS Benchmark: Ensure SMBv1 is disabled", "url": "https://www.cisecurity.org/benchmark/microsoft_windows_server", "tag": "defense"},
    {"title": "NSA: Network Infrastructure Security Guidance - Disable SMBv1", "url": "https://media.defense.gov/2023/Jun/22/2003251092/-1/-1/0/CTR_DEFENDING_ACTIVE_DIRECTORY.PDF", "tag": "defense"},
]
