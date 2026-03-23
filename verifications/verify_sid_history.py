"""
verifications/verify_sid_history.py
Manual verification, remediation, and references for the SID History finding.
"""

MATCH_KEYS = [
    "sid history",
    "sIDHistory",
]

TOOLS = [
    {
        "tool": "PowerShell (AD Module)",
        "icon": "ps",
        "desc": "Enumerate all accounts with a populated SID History attribute.",
        "code": (            "Get-ADUser -Filter {SIDHistory -ne \"\"}\\\n"            "  -Properties SIDHistory, SamAccountName, Enabled |\n"            "  Select-Object SamAccountName, Enabled, SIDHistory\n"            "\n"            "# Also check computer objects:\n"            "Get-ADComputer -Filter {SIDHistory -ne \"\"} \\\n"            "  -Properties SIDHistory |\n"            "  Select-Object Name, SIDHistory"
        ),
        "confirm": "Any non-empty SIDHistory should be reviewed. SIDs matching privileged groups (e.g. Domain Admins S-1-5-21-*-512) are critical.",
    },
    {
        "tool": "NetExec",
        "icon": "netexec",
        "desc": "Use NetExec LDAP module to dump SID History from Linux.",
        "code": (            "netexec ldap <DC_IP> \\\n"            "  -u <USER> -p <PASSWORD> \\\n"            "  -M get-sid-history"
        ),
        "confirm": "Any SID matching a high-privilege group RID (e.g. -512 Domain Admins, -519 Enterprise Admins) is a critical finding.",
    },
]

REMEDIATION = {
    "title": "Remove unauthorised SID History entries from all accounts",
    "steps": [
        {
            "text": "Identify accounts with SID History and determine whether the historical SIDs are legitimate (e.g. from a completed domain migration).",
        },
        {
            "text": "Remove SID History from accounts where it is no longer operationally required:",
            "code": (                "# Requires Domain Admin and AD module\n"                "Set-ADUser <username> -Remove @{SIDHistory='<SID_to_remove>'}"
            ),
        },
        {
            "text": "Enable SID filtering (quarantine) on all cross-domain trusts to prevent SID history injection across trust boundaries: netdom trust <domain> /domain:<partner> /quarantine:yes",
        },
        {
            "text": "Monitor for SID History additions using Event ID 4765 (SID History added) and 4766 (SID History addition attempt failed) in the Security log.",
        },
    ],
}

REFERENCES = [
    {
        "title": "Microsoft — SID History (sIDHistory attribute)",
        "url": "https://learn.microsoft.com/en-us/windows/win32/adschema/a-sidhistory",
        "tag": "vendor",
    },
    {
        "title": "MITRE ATT&CK — Access Token Manipulation: SID History Injection (T1134.005)",
        "url": "https://attack.mitre.org/techniques/T1134/005/",
        "tag": "attack",
    },
    {
        "title": "Sean Metcalf — Sneaky Active Directory Persistence Tricks (SID History)",
        "url": "https://adsecurity.org/?p=1772",
        "tag": "research",
    },
    {
        "title": "Microsoft — How to Use SID Filtering to Prevent Elevation of Privilege",
        "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc961997(v=technet.10)",
        "tag": "defense",
    },
]
