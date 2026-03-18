""" lib/report.py - ADScan HTML Report Generator
Generates a self-contained HTML dashboard with:
  - Light/Dark mode toggle
  - Security score gauge
  - LEFT SIDEBAR: category navigation (alphabetical, collapsible, ordered by severity)
  - Clickable, multi-select severity filter chips
  - Per-finding cards with severity badges
  - Scan metadata table
  - Manual Verification tool cards (per finding)
  - Remediation guidance (per finding)
"""
from datetime import datetime
import html as html_mod

# ---------------------------------------------------------------------------
# Severity colour mapping
# ---------------------------------------------------------------------------
SEVERITY_COLORS = {
    "critical": ("#dc2626", "#fef2f2", "#7f1d1d"),
    "high":     ("#ea580c", "#fff7ed", "#7c2d12"),
    "medium":   ("#d97706", "#fffbeb", "#78350f"),
    "low":      ("#2563eb", "#eff6ff", "#1e3a8a"),
    "info":     ("#6b7280", "#f9fafb", "#374151"),
}

SEV_ORDER = ["critical", "high", "medium", "low", "info"]
_SEV_RANK = {s: i for i, s in enumerate(SEV_ORDER)}


def _score_color(score):
    if score >= 90: return "#16a34a"
    if score >= 75: return "#84cc16"
    if score >= 60: return "#eab308"
    if score >= 40: return "#f97316"
    return "#dc2626"


def _grade(score):
    if score >= 90: return "A"
    if score >= 75: return "B"
    if score >= 60: return "C"
    if score >= 40: return "D"
    return "F"


def _severity_badge_html(severity):
    sev = severity.lower()
    bg_light, _, _ = SEVERITY_COLORS.get(sev, ("#6b7280", "#f9fafb", "#374151"))
    return (
        f'<span class="badge badge-{sev}" '
        f'style="background:{bg_light};color:#fff;'
        f'padding:2px 10px;border-radius:12px;font-size:0.78rem;'
        f'font-weight:600;letter-spacing:0.05em;text-transform:uppercase;">'
        f'{html_mod.escape(severity.upper())}</span>'
    )


# ---------------------------------------------------------------------------
# Manual Verification & Remediation Database
# ---------------------------------------------------------------------------
# Keys are lowercase substrings matched against finding["title"].lower().
# First match wins. Tools list drives the 2-column verification grid.
# ---------------------------------------------------------------------------
VERIFICATION_DB = {
    # -----------------------------------------------------------------------
    # Password Policy – Account Lockout
    # -----------------------------------------------------------------------
    "account lockout": {
        "tools": [
            {
                "tool": "NetExec",
                "icon": "netexec",
                "desc": "Query the password policy remotely from any machine with a valid domain account.",
                "code": "netexec smb <DC_IP> \\\n    -u <username> \\\n    -p <password> \\\n    --pass-pol",
                "confirm": "Look for <strong>Account Lockout Threshold: None</strong> or <strong>0</strong> in the output.",
            },
            {
                "tool": "net accounts",
                "icon": "cmd",
                "desc": "Run from any domain-joined Windows host. No special privileges needed beyond a standard domain account.",
                "code": "net accounts /domain",
                "confirm": "A value of <strong>Never</strong> or <strong>0</strong> next to <em>Lockout threshold</em> confirms the finding.",
            },
            {
                "tool": "ADUC (dsa.msc)",
                "icon": "aduc",
                "desc": "GUI method via Active Directory Users and Computers on a domain-joined machine with RSAT installed.",
                "steps": [
                    "Open <code>dsa.msc</code>",
                    "Right-click domain root → <em>Properties</em>",
                    "Group Policy tab → open <em>Default Domain Policy</em>",
                    "Navigate to: <code>Computer Configuration → Windows Settings → Security Settings → Account Policies → Account Lockout Policy</code>",
                    "<em>Account lockout threshold</em> = <strong>0</strong> confirms the finding.",
                ],
            },
            {
                "tool": "PowerShell",
                "icon": "ps",
                "desc": "Run from a domain-joined host with the ActiveDirectory module available.",
                "code": "Get-ADDefaultDomainPasswordPolicy `\n    | Select-Object LockoutThreshold,\n        LockoutDuration,\n        LockoutObservationWindow",
                "confirm": "A <strong>LockoutThreshold</strong> of <strong>0</strong> confirms no lockout policy is in effect.",
            },
        ],
        "remediation": {
            "title": "Set lockout threshold to 5–10 attempts",
            "steps": [
                {
                    "text": "Apply via PowerShell on the domain controller:",
                    "code": "Set-ADDefaultDomainPasswordPolicy `\n    -Identity <domain.fqdn> `\n    -LockoutThreshold 5 `\n    -LockoutDuration 00:30:00 `\n    -LockoutObservationWindow 00:30:00",
                },
                {
                    "text": "Or apply via Group Policy Editor (<code>gpedit.msc</code>) on the Domain Controller under <em>Default Domain Policy</em> at the path shown in the ADUC step above.",
                },
                {
                    "text": "For privileged accounts requiring a stricter policy, use <strong>Fine-Grained Password Policies (PSOs)</strong> to apply a lower threshold (e.g. 3 attempts) to Domain Admins without affecting all users.",
                },
            ],
        },
    },
    # -----------------------------------------------------------------------
    # Password Policy – Complexity / Length / Expiry
    # -----------------------------------------------------------------------
    "password complexity": {
        "tools": [
            {
                "tool": "NetExec",
                "icon": "netexec",
                "desc": "Retrieve full password policy including complexity flag from any authenticated host.",
                "code": "netexec smb <DC_IP> -u <username> -p <password> --pass-pol",
                "confirm": "Look for <strong>Password Complexity: Disabled</strong> in the output.",
            },
            {
                "tool": "net accounts",
                "icon": "cmd",
                "desc": "Quick check from any domain-joined Windows machine.",
                "code": "net accounts /domain",
                "confirm": "Run from a DC and check <strong>Password Complexity</strong> in Group Policy.",
            },
            {
                "tool": "PowerShell",
                "icon": "ps",
                "desc": "Query the default domain password policy object directly.",
                "code": "Get-ADDefaultDomainPasswordPolicy `\n    | Select-Object ComplexityEnabled,MinPasswordLength,MaxPasswordAge",
                "confirm": "<strong>ComplexityEnabled: False</strong> confirms the finding.",
            },
            {
                "tool": "ADUC (dsa.msc)",
                "icon": "aduc",
                "desc": "Navigate to the Default Domain Policy GPO and inspect Account Policies.",
                "steps": [
                    "Open <code>gpmc.msc</code>",
                    "Navigate to <em>Default Domain Policy</em> → Edit",
                    "Computer Configuration → Windows Settings → Security Settings → Account Policies → Password Policy",
                    "<strong>Password must meet complexity requirements: Disabled</strong> confirms the finding.",
                ],
            },
        ],
        "remediation": {
            "title": "Enable password complexity and set minimum length ≥ 14",
            "steps": [
                {
                    "text": "Enable complexity and set minimum length via PowerShell:",
                    "code": "Set-ADDefaultDomainPasswordPolicy `\n    -Identity <domain.fqdn> `\n    -ComplexityEnabled $true `\n    -MinPasswordLength 14",
                },
                {
                    "text": "Alternatively configure via <code>gpedit.msc</code> under <em>Default Domain Policy → Password Policy</em>.",
                },
                {
                    "text": "Consider deploying a <strong>passphrase policy</strong> (e.g. 3-word phrases, min 20 chars) for better usability and security.",
                },
            ],
        },
    },
    "minimum password length": {
        "tools": [
            {
                "tool": "NetExec",
                "icon": "netexec",
                "desc": "Enumerate password policy remotely to see the minimum length setting.",
                "code": "netexec smb <DC_IP> -u <username> -p <password> --pass-pol",
                "confirm": "Check <strong>Minimum password length</strong> value in the output.",
            },
            {
                "tool": "PowerShell",
                "icon": "ps",
                "desc": "Query minimum password length from the default domain password policy.",
                "code": "Get-ADDefaultDomainPasswordPolicy | Select-Object MinPasswordLength",
                "confirm": "A value below <strong>14</strong> confirms the finding.",
            },
            {
                "tool": "net accounts",
                "icon": "cmd",
                "desc": "Run from any domain-joined Windows host.",
                "code": "net accounts /domain",
                "confirm": "Check the <strong>Minimum password length</strong> row.",
            },
            {
                "tool": "ADUC (dsa.msc)",
                "icon": "aduc",
                "desc": "Inspect the Default Domain Policy GPO for password settings.",
                "steps": [
                    "Open <code>gpmc.msc</code> → Default Domain Policy → Edit",
                    "Computer Configuration → Windows Settings → Security Settings → Account Policies → Password Policy",
                    "Check <strong>Minimum password length</strong>.",
                ],
            },
        ],
        "remediation": {
            "title": "Set minimum password length to 14+ characters",
            "steps": [
                {
                    "text": "Update via PowerShell:",
                    "code": "Set-ADDefaultDomainPasswordPolicy -Identity <domain.fqdn> -MinPasswordLength 14",
                },
                {
                    "text": "Enforce via Group Policy under <em>Default Domain Policy → Password Policy</em>.",
                },
                {
                    "text": "Use <strong>Fine-Grained Password Policies (PSOs)</strong> to enforce stricter lengths for privileged accounts.",
                },
            ],
        },
    },
    "password never expires": {
        "tools": [
            {
                "tool": "PowerShell",
                "icon": "ps",
                "desc": "Find all accounts with the PasswordNeverExpires flag set.",
                "code": "Get-ADUser -Filter {PasswordNeverExpires -eq $true} `\n    -Properties PasswordNeverExpires `\n    | Select-Object Name,SamAccountName",
                "confirm": "Each account listed has a non-expiring password.",
            },
            {
                "tool": "NetExec",
                "icon": "netexec",
                "desc": "Enumerate users with password-never-expires flag via LDAP.",
                "code": "netexec ldap <DC_IP> -u <username> -p <password> --password-not-required",
                "confirm": "Accounts listed have the flag set.",
            },
            {
                "tool": "ADUC (dsa.msc)",
                "icon": "aduc",
                "desc": "Search for accounts with password never expires via the GUI.",
                "steps": [
                    "Open <code>dsa.msc</code>",
                    "Action → Find → select <em>Users</em>",
                    "Advanced tab → Field: <em>Password Never Expires</em> = <em>True</em>",
                ],
            },
            {
                "tool": "net user",
                "icon": "cmd",
                "desc": "Check a specific user account for the password expiry setting.",
                "code": "net user <username> /domain",
                "confirm": "Look for <strong>Password expires: Never</strong> in the output.",
            },
        ],
        "remediation": {
            "title": "Enable password expiration for non-service accounts",
            "steps": [
                {
                    "text": "Enable password expiry for a single user:",
                    "code": "Set-ADUser -Identity <username> -PasswordNeverExpires $false",
                },
                {
                    "text": "Bulk-fix all non-service accounts:",
                    "code": "Get-ADUser -Filter {PasswordNeverExpires -eq $true} `\n    | Where-Object {$_.SamAccountName -notlike '*svc*'} `\n    | Set-ADUser -PasswordNeverExpires $false",
                },
                {
                    "text": "For <strong>service accounts</strong>, use <strong>Group Managed Service Accounts (gMSAs)</strong> which rotate passwords automatically — eliminating the need for PasswordNeverExpires.",
                },
            ],
        },
    },
    # -----------------------------------------------------------------------
    # Kerberoasting
    # -----------------------------------------------------------------------
    "kerberoast": {
        "tools": [
            {
                "tool": "Impacket",
                "icon": "impacket",
                "desc": "Request TGS tickets for all SPNs and save hashes for offline cracking.",
                "code": "GetUserSPNs.py <domain>/<username>:<password> `\n    -dc-ip <DC_IP> -request `\n    -outputfile kerberoast_hashes.txt",
                "confirm": "Each hash file entry represents a Kerberoastable account.",
            },
            {
                "tool": "NetExec",
                "icon": "netexec",
                "desc": "Enumerate Kerberoastable accounts quickly without retrieving hashes.",
                "code": "netexec ldap <DC_IP> -u <username> -p <password> --kerberoasting",
                "confirm": "Any account listed is Kerberoastable.",
            },
            {
                "tool": "PowerShell",
                "icon": "ps",
                "desc": "Find accounts with Service Principal Names set — these are Kerberoastable.",
                "code": "Get-ADUser -Filter {ServicePrincipalName -ne \"$null\"} `\n    -Properties ServicePrincipalName `\n    | Select-Object Name,SamAccountName,ServicePrincipalName",
                "confirm": "Any non-computer account with an SPN is Kerberoastable.",
            },
            {
                "tool": "ADUC (dsa.msc)",
                "icon": "aduc",
                "desc": "Find user accounts with SPNs via the GUI attribute editor.",
                "steps": [
                    "Open <code>dsa.msc</code> → View → Advanced Features",
                    "Find a user → Properties → Attribute Editor",
                    "Locate <strong>servicePrincipalName</strong> attribute",
                    "Any non-empty value on a user account (not computer) is Kerberoastable.",
                ],
            },
        ],
        "remediation": {
            "title": "Remove unnecessary SPNs and enforce AES-only encryption",
            "steps": [
                {
                    "text": "Audit and remove unnecessary SPNs from user accounts:",
                    "code": "Set-ADUser -Identity <username> -ServicePrincipalNames @{Remove='<SPN>'}",
                },
                {
                    "text": "Enforce AES-only encryption to make cracking computationally infeasible:",
                    "code": "Set-ADUser -Identity <username> `\n    -KerberosEncryptionType AES128,AES256",
                },
                {
                    "text": "Migrate service accounts to <strong>Group Managed Service Accounts (gMSAs)</strong> — they use auto-rotating 120-character passwords that cannot be cracked.",
                },
                {
                    "text": "Ensure service account passwords are <strong>25+ characters</strong> and randomly generated if gMSAs cannot be used immediately.",
                },
            ],
        },
    },
    # -----------------------------------------------------------------------
    # AS-REP Roasting
    # -----------------------------------------------------------------------
    "as-rep": {
        "tools": [
            {
                "tool": "Impacket",
                "icon": "impacket",
                "desc": "Retrieve AS-REP hashes for accounts with pre-authentication disabled.",
                "code": "GetNPUsers.py <domain>/ -dc-ip <DC_IP> `\n    -usersfile users.txt -request `\n    -outputfile asrep_hashes.txt",
                "confirm": "Each hash output is an AS-REP roastable account.",
            },
            {
                "tool": "NetExec",
                "icon": "netexec",
                "desc": "Enumerate and retrieve AS-REP hashes in one command.",
                "code": "netexec ldap <DC_IP> -u <username> -p <password> --asreproast asrep.txt",
                "confirm": "Any hash in asrep.txt is an AS-REP roastable account.",
            },
            {
                "tool": "PowerShell",
                "icon": "ps",
                "desc": "Find accounts with Kerberos pre-authentication disabled (UAC flag 0x400000).",
                "code": "Get-ADUser -Filter * -Properties DoesNotRequirePreAuth `\n    | Where-Object {$_.DoesNotRequirePreAuth -eq $true} `\n    | Select-Object Name,SamAccountName",
                "confirm": "Each listed account does not require pre-authentication.",
            },
            {
                "tool": "ADUC (dsa.msc)",
                "icon": "aduc",
                "desc": "Check individual user accounts for the pre-auth setting via the GUI.",
                "steps": [
                    "Open <code>dsa.msc</code> → user Properties → Account tab",
                    "Scroll Account options list",
                    "Check if <strong>Do not require Kerberos preauthentication</strong> is ticked",
                ],
            },
        ],
        "remediation": {
            "title": "Enable Kerberos pre-authentication on all affected accounts",
            "steps": [
                {
                    "text": "Re-enable pre-authentication for a single account:",
                    "code": "Set-ADUser -Identity <username> -DoesNotRequirePreAuth $false",
                },
                {
                    "text": "Bulk-fix all affected accounts:",
                    "code": "Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} `\n    | Set-ADUser -DoesNotRequirePreAuth $false",
                },
                {
                    "text": "Ensure affected account passwords are <strong>reset immediately</strong> — AS-REP hashes captured before remediation are still crackable offline.",
                },
            ],
        },
    },
    # -----------------------------------------------------------------------
    # Unconstrained Delegation
    # -----------------------------------------------------------------------
    "unconstrained delegation": {
        "tools": [
            {
                "tool": "NetExec",
                "icon": "netexec",
                "desc": "Enumerate computers and users configured with unconstrained delegation.",
                "code": "netexec ldap <DC_IP> -u <username> -p <password> --trusted-for-delegation",
                "confirm": "Any non-DC host listed has unconstrained delegation — a critical risk.",
            },
            {
                "tool": "Impacket",
                "icon": "impacket",
                "desc": "Use findDelegation to enumerate all delegation types in the domain.",
                "code": "findDelegation.py <domain>/<username>:<password> -dc-ip <DC_IP>",
                "confirm": "Look for <strong>Unconstrained</strong> in the Delegation Type column for non-DC hosts.",
            },
            {
                "tool": "PowerShell",
                "icon": "ps",
                "desc": "Query AD for computers and users with TrustedForDelegation set.",
                "code": "Get-ADComputer -Filter {TrustedForDelegation -eq $true} `\n    -Properties TrustedForDelegation `\n    | Where-Object {$_.Name -notlike '*DC*'} `\n    | Select-Object Name,DNSHostName\n\nGet-ADUser -Filter {TrustedForDelegation -eq $true} `\n    | Select-Object Name,SamAccountName",
                "confirm": "Any computer (excluding DCs) or user listed has unconstrained delegation.",
            },
            {
                "tool": "ADUC (dsa.msc)",
                "icon": "aduc",
                "desc": "Check delegation settings on individual computer or user objects.",
                "steps": [
                    "Open <code>dsa.msc</code> → View → Advanced Features",
                    "Locate the computer or user object → Properties → Delegation tab",
                    "<strong>Trust this computer/user for delegation to any service (Kerberos only)</strong> = Unconstrained",
                ],
            },
        ],
        "remediation": {
            "title": "Migrate to constrained or resource-based constrained delegation",
            "steps": [
                {
                    "text": "Remove unconstrained delegation flag from a computer:",
                    "code": "Set-ADComputer -Identity <computername> -TrustedForDelegation $false",
                },
                {
                    "text": "Replace with constrained delegation (specific SPNs only):",
                    "code": "Set-ADComputer -Identity <computername> `\n    -TrustedToAuthForDelegation $true `\n    -ServicePrincipalNames @{Add='cifs/<target>'}",
                },
                {
                    "text": "Add affected computer and user accounts to the <strong>Protected Users</strong> security group — members cannot be configured for unconstrained delegation.",
                },
                {
                    "text": "Enable <strong>Account is sensitive and cannot be delegated</strong> on all privileged accounts via ADUC or PowerShell: <code>Set-ADUser -Identity &lt;admin&gt; -AccountNotDelegated $true</code>",
                },
            ],
        },
    },
    # -----------------------------------------------------------------------
    # LAPS
    # -----------------------------------------------------------------------
    "laps": {
        "tools": [
            {
                "tool": "NetExec",
                "icon": "netexec",
                "desc": "Check if LAPS is deployed and readable on domain computers.",
                "code": "netexec ldap <DC_IP> -u <username> -p <password> --laps",
                "confirm": "Computers without <strong>ms-Mcs-AdmPwd</strong> populated likely don\'t have LAPS deployed.",
            },
            {
                "tool": "PowerShell",
                "icon": "ps",
                "desc": "Query the LAPS password attribute for all computers.",
                "code": "Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime `\n    | Select-Object Name,\'ms-Mcs-AdmPwd\',\'ms-Mcs-AdmPwdExpirationTime\'",
                "confirm": "Computers with empty <strong>ms-Mcs-AdmPwd</strong> do not have LAPS deployed.",
            },
            {
                "tool": "ADUC (dsa.msc)",
                "icon": "aduc",
                "desc": "Check the LAPS attribute on individual computer objects.",
                "steps": [
                    "Open <code>dsa.msc</code> → View → Advanced Features",
                    "Locate a computer object → Properties → Attribute Editor",
                    "Search for <strong>ms-Mcs-AdmPwd</strong>",
                    "If missing or empty, LAPS is not deployed on that computer.",
                ],
            },
            {
                "tool": "Impacket (ldapsearch)",
                "icon": "impacket",
                "desc": "Use ldapsearch to query LAPS attributes via LDAP.",
                "code": "ldapsearch -x -H ldap://<DC_IP> -D '<username>@<domain>' `\n    -w '<password>' -b 'DC=<domain>,DC=<tld>' `\n    '(objectClass=computer)' ms-Mcs-AdmPwd",
                "confirm": "Computers with no <strong>ms-Mcs-AdmPwd</strong> value lack LAPS.",
            },
        ],
        "remediation": {
            "title": "Deploy LAPS (or Windows LAPS) across all domain computers",
            "steps": [
                {
                    "text": "Install legacy LAPS (Windows Server 2016/2019) via Group Policy:",
                    "code": "# Download LAPS.x64.msi from Microsoft\nInstall-Module -Name LAPS\nUpdate-LapsADSchema\nSet-AdmPwdComputerSelfPermission -OrgUnit \"OU=Workstations,DC=<domain>...\"",
                },
                {
                    "text": "For Windows Server 2022 / Windows 11 22H2+, use <strong>Windows LAPS</strong> (built-in) with <code>Set-LapsADComputerSelfPermission</code>.",
                },
                {
                    "text": "Restrict who can read <code>ms-Mcs-AdmPwd</code> — only Helpdesk/IT Admins should have read access, not regular users.",
                },
            ],
        },
    },
    # -----------------------------------------------------------------------
    # SMB Signing
    # -----------------------------------------------------------------------
    "smb signing": {
        "tools": [
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
        ],
        "remediation": {
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
        },
    },
    # -----------------------------------------------------------------------
    # GPP cPassword
    # -----------------------------------------------------------------------
    "gpp": {
        "tools": [
            {
                "tool": "NetExec",
                "icon": "netexec",
                "desc": "Search SYSVOL share for Group Policy Preferences files containing cpassword.",
                "code": "netexec smb <DC_IP> -u <username> -p <password> -M gpp_password",
                "confirm": "Any cpassword value found is exploitable using a known AES key.",
            },
            {
                "tool": "Impacket",
                "icon": "impacket",
                "desc": "Mount the SYSVOL share and search for cpassword entries manually.",
                "code": "smbclient.py <domain>/<username>:<password>@<DC_IP>\n# Then browse: \\\\<DC>\\SYSVOL\\<domain>\\Policies\n\n# Or use findstr on Windows:\nfindstr /S /I cpassword \\\\<DC>\\SYSVOL\\<domain>\\Policies\\*.xml",
                "confirm": "Any XML file with a <code>cpassword</code> attribute contains a decryptable credential.",
            },
            {
                "tool": "PowerShell",
                "icon": "ps",
                "desc": "Search SYSVOL for GPP files containing cpassword.",
                "code": "Get-ChildItem -Path \"\\\\<DC>\\SYSVOL\" -Recurse -Filter \"*.xml\" `\n    | Select-String -Pattern \"cpassword\" `\n    | Select-Object Path,Line",
                "confirm": "Any match contains a GPP credential that can be decrypted with the public AES key.",
            },
            {
                "tool": "net use / Explorer",
                "icon": "cmd",
                "desc": "Manually browse SYSVOL for Group Policy XML files.",
                "code": "net use Z: \\\\<DC_IP>\\SYSVOL\ndir Z:\\<domain>\\Policies /s /b | findstr .xml",
                "confirm": "Open any Groups.xml, Services.xml etc. and check for <code>cpassword=</code> attribute.",
            },
        ],
        "remediation": {
            "title": "Remove all GPP cpassword entries and apply MS14-025",
            "steps": [
                {
                    "text": "Install <strong>MS14-025</strong> on all Domain Controllers — this prevents creation of new GPP passwords.",
                },
                {
                    "text": "Delete existing GPP password entries from SYSVOL: search for and remove all XML files containing <code>cpassword</code> from SYSVOL policies.",
                    "code": "Get-ChildItem -Path \"\\\\<DC>\\SYSVOL\" -Recurse -Filter \"*.xml\" `\n    | Select-String \"cpassword\" `\n    | ForEach-Object { Remove-Item $_.Path -WhatIf }",
                },
                {
                    "text": "<strong>Reset all passwords</strong> that were stored in GPP — treat them as fully compromised.",
                },
            ],
        },
    },
    # -----------------------------------------------------------------------
    # Shadow Credentials / msDS-KeyCredentialLink
    # -----------------------------------------------------------------------
    "shadow credential": {
        "tools": [
            {
                "tool": "Certipy",
                "icon": "impacket",
                "desc": "Enumerate accounts with msDS-KeyCredentialLink set (shadow credentials).",
                "code": "certipy find -u <username>@<domain> -p <password> -dc-ip <DC_IP>",
                "confirm": "Accounts with <strong>Key Credential</strong> entries not set by the OS are suspicious.",
            },
            {
                "tool": "PowerShell",
                "icon": "ps",
                "desc": "Query msDS-KeyCredentialLink attribute on user and computer accounts.",
                "code": "Get-ADUser -Filter * -Properties msDS-KeyCredentialLink `\n    | Where-Object {\'msDS-KeyCredentialLink\' -ne $null} `\n    | Select-Object Name,\'msDS-KeyCredentialLink\'",
                "confirm": "Unexpected entries in <strong>msDS-KeyCredentialLink</strong> indicate shadow credential abuse.",
            },
            {
                "tool": "bloodyAD",
                "icon": "netexec",
                "desc": "Enumerate and manipulate shadow credentials using bloodyAD.",
                "code": "bloodyAD -u <username> -p <password> -d <domain> --host <DC_IP> get object <target> --attr msDS-KeyCredentialLink",
                "confirm": "Non-empty output means shadow credentials are present.",
            },
            {
                "tool": "ADUC (dsa.msc)",
                "icon": "aduc",
                "desc": "Inspect msDS-KeyCredentialLink via the Attribute Editor.",
                "steps": [
                    "Open <code>dsa.msc</code> → View → Advanced Features",
                    "Locate a user/computer → Properties → Attribute Editor",
                    "Find <strong>msDS-KeyCredentialLink</strong>",
                    "Any unexpected values indicate shadow credential backdoors.",
                ],
            },
        ],
        "remediation": {
            "title": "Clear unauthorized Key Credential entries",
            "steps": [
                {
                    "text": "Clear the msDS-KeyCredentialLink attribute on affected accounts:",
                    "code": "Set-ADUser -Identity <username> -Clear msDS-KeyCredentialLink",
                },
                {
                    "text": "Audit who has <strong>Write</strong> permission to <code>msDS-KeyCredentialLink</code> — restrict to Domain Admins and the system only.",
                },
                {
                    "text": "Enable <strong>Protected Users</strong> security group membership for privileged accounts — this provides additional Kerberos protections.",
                },
            ],
        },
    },
    # -----------------------------------------------------------------------
    # AdminSDHolder / ACL Abuse
    # -----------------------------------------------------------------------
    "adminsdholder": {
        "tools": [
            {
                "tool": "Impacket",
                "icon": "impacket",
                "desc": "Enumerate ACLs on the AdminSDHolder container using dacledit.",
                "code": "dacledit.py <domain>/<username>:<password> -dc-ip <DC_IP> `\n    -target-dn \"CN=AdminSDHolder,CN=System,DC=<domain>,DC=<tld>\"`\n    -action read",
                "confirm": "Unexpected accounts with GenericAll, WriteDACL, or GenericWrite permissions are a critical finding.",
            },
            {
                "tool": "PowerShell",
                "icon": "ps",
                "desc": "Read ACL on the AdminSDHolder object.",
                "code": "Get-ACL \"AD:\\CN=AdminSDHolder,CN=System,$(([adsi]\'\')).distinguishedName\" `\n    | Select-Object -Expand Access `\n    | Where-Object {$_.ActiveDirectoryRights -match \"GenericAll|WriteDACL|WriteOwner\"}",
                "confirm": "Non-admin accounts in the ACL output represent a persistence/escalation path.",
            },
            {
                "tool": "BloodHound / SharpHound",
                "icon": "netexec",
                "desc": "Collect ACL data and visualise AdminSDHolder attack paths.",
                "code": "SharpHound.exe -c All\n# Import to BloodHound and search:\n# MATCH p=()-[:GenericAll]->(n:Group {name:\"ADMINSDHOLDER@DOMAIN\"}) RETURN p",
                "confirm": "Any inbound edge to AdminSDHolder in BloodHound is exploitable.",
            },
            {
                "tool": "ADUC (dsa.msc)",
                "icon": "aduc",
                "desc": "View AdminSDHolder ACL via the Security tab in ADUC.",
                "steps": [
                    "Open <code>dsa.msc</code> → View → Advanced Features",
                    "Navigate to <em>System → AdminSDHolder</em>",
                    "Properties → Security → Advanced",
                    "Review all entries — only Domain Admins and SYSTEM should have full control.",
                ],
            },
        ],
        "remediation": {
            "title": "Remove unauthorized ACEs from AdminSDHolder",
            "steps": [
                {
                    "text": "Remove a specific ACE using PowerShell (requires Domain Admin):",
                    "code": "$acl = Get-ACL \"AD:\\CN=AdminSDHolder,CN=System,DC=<domain>,DC=<tld>\"\n$ace = $acl.Access | Where-Object {$_.IdentityReference -match \"<attacker_account>\"}\n$acl.RemoveAccessRule($ace)\nSet-ACL -Path \"AD:\\CN=AdminSDHolder...\" -AclObject $acl",
                },
                {
                    "text": "Force SDProp to propagate corrected ACLs immediately:",
                    "code": "Invoke-Expression -Command \"Repair-ADObject -Identity (Get-ADObject -SearchBase 'CN=AdminSDHolder,CN=System,DC=<domain>,DC=<tld>' -Filter *)\"",
                },
                {
                    "text": "Audit SDProp propagation regularly using <strong>Active Directory Auditing</strong> — enable object modification auditing on AdminSDHolder.",
                },
            ],
        },
    },
    # -----------------------------------------------------------------------
    # ADCS / Certificate Services
    # -----------------------------------------------------------------------
    "esc": {
        "tools": [
            {
                "tool": "Certipy",
                "icon": "impacket",
                "desc": "Comprehensive ADCS enumeration — finds ESC1-ESC11 misconfigurations.",
                "code": "certipy find -u <username>@<domain> -p <password> -dc-ip <DC_IP> -vulnerable",
                "confirm": "Any template listed under <strong>Certificate Templates</strong> with ESC flags is exploitable.",
            },
            {
                "tool": "NetExec",
                "icon": "netexec",
                "desc": "Enumerate ADCS certificate authorities and templates.",
                "code": "netexec ldap <DC_IP> -u <username> -p <password> -M adcs",
                "confirm": "Lists Certificate Authorities and templates available for enrollment.",
            },
            {
                "tool": "PowerShell",
                "icon": "ps",
                "desc": "Enumerate certificate templates via the PKI module.",
                "code": "Get-ADObject -SearchBase \"CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<tld>\" `\n    -Filter * -Properties * `\n    | Select-Object Name,msPKI-Certificate-Name-Flag,msPKI-Enrollment-Flag",
                "confirm": "Templates with <strong>ENROLLEE_SUPPLIES_SUBJECT</strong> flag and broad enrollment rights are ESC1-vulnerable.",
            },
            {
                "tool": "certutil",
                "icon": "cmd",
                "desc": "Enumerate Certificate Authorities and templates from Windows.",
                "code": "certutil -config - -ping\ncertutil -catemplates",
                "confirm": "Lists available templates — compare against Certipy output to identify misconfigurations.",
            },
        ],
        "remediation": {
            "title": "Remediate vulnerable certificate templates",
            "steps": [
                {
                    "text": "For <strong>ESC1</strong> (ENROLLEE_SUPPLIES_SUBJECT): Disable the flag in Certificate Template Manager (<code>certtmpl.msc</code>) — uncheck <em>Supply in the request</em> under Subject Name tab.",
                },
                {
                    "text": "For <strong>ESC2/ESC3</strong>: Restrict who can enroll — remove broad enrollment rights (e.g. Domain Users) and limit to specific service accounts or groups.",
                },
                {
                    "text": "Enable <strong>CA Manager Approval</strong> (pending certificate issuance) for high-privilege templates.",
                    "code": "# In Certificate Template Properties → Issuance Requirements\n# Check: \"CA certificate manager approval\"",
                },
                {
                    "text": "Run Certipy regularly to re-audit: <code>certipy find -vulnerable</code> — this should be part of your change management process.",
                },
            ],
        },
    },
    # -----------------------------------------------------------------------
    # Protected Users Group
    # -----------------------------------------------------------------------
    "protected users": {
        "tools": [
            {
                "tool": "PowerShell",
                "icon": "ps",
                "desc": "Check membership of the Protected Users security group.",
                "code": "Get-ADGroupMember -Identity \"Protected Users\" | Select-Object Name,SamAccountName,objectClass",
                "confirm": "If the group is empty or missing privileged accounts, those accounts lack enhanced protections.",
            },
            {
                "tool": "NetExec",
                "icon": "netexec",
                "desc": "Enumerate group membership via LDAP.",
                "code": "netexec ldap <DC_IP> -u <username> -p <password> -M groupmembership -o GROUP=\"Protected Users\"",
                "confirm": "An empty group means no accounts benefit from Protected Users mitigations.",
            },
            {
                "tool": "ADUC (dsa.msc)",
                "icon": "aduc",
                "desc": "View Protected Users group membership in the GUI.",
                "steps": [
                    "Open <code>dsa.msc</code>",
                    "Navigate to <em>Users</em> container",
                    "Find <strong>Protected Users</strong> group → Properties → Members tab",
                    "Verify all privileged accounts (Domain Admins, Enterprise Admins, etc.) are listed.",
                ],
            },
            {
                "tool": "net group",
                "icon": "cmd",
                "desc": "Check Protected Users group membership from command line.",
                "code": "net group \"Protected Users\" /domain",
                "confirm": "Empty output means no accounts are protected.",
            },
        ],
        "remediation": {
            "title": "Add privileged accounts to the Protected Users group",
            "steps": [
                {
                    "text": "Add a privileged account to Protected Users:",
                    "code": "Add-ADGroupMember -Identity \"Protected Users\" -Members <username>",
                },
                {
                    "text": "Bulk-add all Domain Admins:",
                    "code": "Get-ADGroupMember -Identity \"Domain Admins\" `\n    | ForEach-Object { Add-ADGroupMember -Identity \"Protected Users\" -Members $_ }",
                },
                {
                    "text": "<strong>Test before production deployment</strong> — Protected Users disables NTLM authentication, DES/RC4 Kerberos, and credential caching. Service accounts that rely on these will break.",
                },
            ],
        },
    },
    # -----------------------------------------------------------------------
    # Constrained Delegation
    # -----------------------------------------------------------------------
    "constrained delegation": {
        "tools": [
            {
                "tool": "Impacket",
                "icon": "impacket",
                "desc": "Enumerate all delegation configurations in the domain.",
                "code": "findDelegation.py <domain>/<username>:<password> -dc-ip <DC_IP>",
                "confirm": "Accounts with <strong>Constrained w/ Protocol Transition</strong> allow S4U2Self — a privilege escalation risk.",
            },
            {
                "tool": "PowerShell",
                "icon": "ps",
                "desc": "Find accounts trusted for constrained delegation.",
                "code": "Get-ADObject -Filter {msDS-AllowedToDelegateTo -like \"*\"} `\n    -Properties msDS-AllowedToDelegateTo `\n    | Select-Object Name,msDS-AllowedToDelegateTo",
                "confirm": "Each listed account can impersonate any user to the specified service.",
            },
            {
                "tool": "NetExec",
                "icon": "netexec",
                "desc": "Enumerate delegation via LDAP enumeration.",
                "code": "netexec ldap <DC_IP> -u <username> -p <password> --trusted-for-delegation",
                "confirm": "Any non-DC account with delegation configured warrants review.",
            },
            {
                "tool": "ADUC (dsa.msc)",
                "icon": "aduc",
                "desc": "Check delegation tab on computer and user objects.",
                "steps": [
                    "Open <code>dsa.msc</code> → View → Advanced Features",
                    "Locate the object → Properties → Delegation tab",
                    "<strong>Trust this computer for delegation to specified services only</strong> = Constrained",
                    "Review the service list for any unexpected or overly-broad services.",
                ],
            },
        ],
        "remediation": {
            "title": "Audit and tighten constrained delegation scope",
            "steps": [
                {
                    "text": "Remove protocol transition (S4U2Self) where not required:",
                    "code": "Set-ADComputer -Identity <computername> -TrustedToAuthForDelegation $false",
                },
                {
                    "text": "Switch to <strong>Resource-Based Constrained Delegation (RBCD)</strong> where possible — it\'s more granular and auditable.",
                },
                {
                    "text": "Set <strong>AccountNotDelegated = $true</strong> on all privileged accounts to prevent delegation abuse.",
                    "code": "Set-ADUser -Identity <admin_user> -AccountNotDelegated $true",
                },
            ],
        },
    },
    # -----------------------------------------------------------------------
    # Inactive / Stale Accounts
    # -----------------------------------------------------------------------
    "inactive": {
        "tools": [
            {
                "tool": "PowerShell",
                "icon": "ps",
                "desc": "Find user accounts that have not logged in for 90+ days.",
                "code": "$cutoff = (Get-Date).AddDays(-90)\nGet-ADUser -Filter {LastLogonDate -lt $cutoff -and Enabled -eq $true} `\n    -Properties LastLogonDate `\n    | Select-Object Name,SamAccountName,LastLogonDate",
                "confirm": "Each listed account is stale and an attack surface for password spray or brute-force.",
            },
            {
                "tool": "NetExec",
                "icon": "netexec",
                "desc": "Enumerate all enabled user accounts to identify stale ones.",
                "code": "netexec ldap <DC_IP> -u <username> -p <password> --users",
                "confirm": "Cross-reference last logon dates against 90-day threshold.",
            },
            {
                "tool": "ADUC (dsa.msc)",
                "icon": "aduc",
                "desc": "Use the built-in stale account query in ADUC.",
                "steps": [
                    "Open <code>dsa.msc</code>",
                    "Action → Find → Custom Search → Advanced tab",
                    "LDAP query: <code>(&(objectClass=user)(lastLogon<=&lt;cutoff_timestamp&gt;)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))</code>",
                    "Review results for accounts not used in 90+ days.",
                ],
            },
            {
                "tool": "net user",
                "icon": "cmd",
                "desc": "Check last logon for a specific account.",
                "code": "net user <username> /domain",
                "confirm": "Check <strong>Last logon</strong> date in the output.",
            },
        ],
        "remediation": {
            "title": "Disable and quarantine stale accounts",
            "steps": [
                {
                    "text": "Disable stale accounts (safer than immediate deletion):",
                    "code": "$cutoff = (Get-Date).AddDays(-90)\nGet-ADUser -Filter {LastLogonDate -lt $cutoff -and Enabled -eq $true} `\n    -Properties LastLogonDate `\n    | Disable-ADAccount",
                },
                {
                    "text": "Move disabled accounts to a dedicated <strong>Disabled Users OU</strong> for 30-day quarantine before deletion.",
                    "code": "Get-ADUser -SearchBase \"OU=Disabled,DC=<domain>...\" -Filter * `\n    | Move-ADObject -TargetPath \"OU=Quarantine,DC=<domain>...\"",
                },
                {
                    "text": "Implement a <strong>User Lifecycle Management process</strong> — automate disabling accounts when users leave (integrate with HR system).",
                },
            ],
        },
    },
    # -----------------------------------------------------------------------
    # Default / Weak Credentials
    # -----------------------------------------------------------------------
    "default credential": {
        "tools": [
            {
                "tool": "NetExec",
                "icon": "netexec",
                "desc": "Test common default credentials against SMB to identify weak accounts.",
                "code": "netexec smb <DC_IP> -u Administrator -p Password1\nnetexec smb <DC_IP> -u Administrator -p Welcome1",
                "confirm": "<strong>[+]</strong> result means the credentials are valid — default password confirmed.",
            },
            {
                "tool": "Impacket",
                "icon": "impacket",
                "desc": "Test credentials using smbclient to verify access.",
                "code": "smbclient.py <domain>/Administrator:Password1@<DC_IP>",
                "confirm": "Successful connection confirms default/weak credentials.",
            },
            {
                "tool": "PowerShell",
                "icon": "ps",
                "desc": "Check when the Administrator account password was last set.",
                "code": "Get-ADUser -Identity Administrator -Properties PasswordLastSet `\n    | Select-Object Name,PasswordLastSet",
                "confirm": "A <strong>PasswordLastSet</strong> date matching initial domain setup suggests the default password was never changed.",
            },
            {
                "tool": "ADUC (dsa.msc)",
                "icon": "aduc",
                "desc": "Check account properties for the built-in Administrator account.",
                "steps": [
                    "Open <code>dsa.msc</code>",
                    "Navigate to <em>Users</em> container → <strong>Administrator</strong>",
                    "Properties → Account tab → check <em>Password never expires</em> and review last password change via Attribute Editor.",
                ],
            },
        ],
        "remediation": {
            "title": "Reset default and weak account passwords immediately",
            "steps": [
                {
                    "text": "Reset the built-in Administrator password to a strong, unique value:",
                    "code": "Set-ADAccountPassword -Identity Administrator `\n    -NewPassword (ConvertTo-SecureString \"<NewPassword>\" -AsPlainText -Force) `\n    -Reset",
                },
                {
                    "text": "Rename the built-in Administrator account to reduce its visibility:",
                    "code": "Rename-ADObject -Identity \"CN=Administrator,CN=Users,DC=<domain>...\" -NewName \"<NewName>\"",
                },
                {
                    "text": "Deploy <strong>LAPS</strong> for local administrator accounts to ensure unique, auto-rotating passwords per machine.",
                },
            ],
        },
    },
    # -----------------------------------------------------------------------
    # DES Encryption
    # -----------------------------------------------------------------------
    "des encryption": {
        "tools": [
            {
                "tool": "PowerShell",
                "icon": "ps",
                "desc": "Find accounts with DES-only Kerberos encryption enabled.",
                "code": "Get-ADUser -Filter * -Properties KerberosEncryptionType `\n    | Where-Object {$_.KerberosEncryptionType -band 3} `\n    | Select-Object Name,SamAccountName,KerberosEncryptionType",
                "confirm": "Accounts with DES flags (bits 0x1 or 0x2) in KerberosEncryptionType are vulnerable.",
            },
            {
                "tool": "Impacket",
                "icon": "impacket",
                "desc": "Perform a Kerberos exchange to confirm DES is accepted.",
                "code": "getTGT.py -des <DES_key> <domain>/<username>",
                "confirm": "Successful TGT retrieval with DES confirms the vulnerability.",
            },
            {
                "tool": "ADUC (dsa.msc)",
                "icon": "aduc",
                "desc": "Check account encryption settings via the Account tab.",
                "steps": [
                    "Open <code>dsa.msc</code> → user Properties → Account tab",
                    "In Account options, check if <strong>Use DES encryption types for this account</strong> is enabled.",
                ],
            },
            {
                "tool": "NetExec",
                "icon": "netexec",
                "desc": "Enumerate accounts with weak Kerberos encryption via LDAP.",
                "code": "netexec ldap <DC_IP> -u <username> -p <password> --users",
                "confirm": "Review userAccountControl flags — bit 0x200000 indicates DES-only.",
            },
        ],
        "remediation": {
            "title": "Disable DES and enforce AES-only Kerberos encryption",
            "steps": [
                {
                    "text": "Disable DES on all user accounts:",
                    "code": "Get-ADUser -Filter * -Properties KerberosEncryptionType `\n    | Where-Object {$_.KerberosEncryptionType -band 3} `\n    | Set-ADUser -KerberosEncryptionType AES128,AES256",
                },
                {
                    "text": "Enforce AES via Group Policy: <em>Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options</em> → <strong>Network security: Configure encryption types allowed for Kerberos</strong> → enable AES128_HMAC_SHA1, AES256_HMAC_SHA1 only.",
                },
                {
                    "text": "After enforcing AES, run <code>klist purge</code> on all clients to flush old DES tickets.",
                },
            ],
        },
    },
}


def _get_verification(finding):
    """Return the VERIFICATION_DB entry that matches this finding, or None."""
    title = finding.get("title", "").lower()
    for key, data in VERIFICATION_DB.items():
        if key in title:
            return data
    return None


def _tool_icon_html(icon_type):
    """Return a small coloured SVG/text icon square for a tool card header."""
    icons = {
        "netexec": (
            "#1a1a2e",
            '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="white">'
            '<rect x="2" y="2" width="4" height="4" rx="1"/><rect x="10" y="2" width="4" height="4" rx="1"/>'
            '<rect x="18" y="2" width="4" height="4" rx="1"/><rect x="2" y="10" width="4" height="4" rx="1"/>'
            '<rect x="10" y="10" width="4" height="4" rx="1"/><rect x="18" y="10" width="4" height="4" rx="1"/>'
            '<rect x="2" y="18" width="4" height="4" rx="1"/><rect x="10" y="18" width="4" height="4" rx="1"/>'
            '<rect x="18" y="18" width="4" height="4" rx="1"/></svg>'
        ),
        "impacket": (
            "#2d3748",
            '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="white">'
            '<path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>'
        ),
        "ps": (
            "#012456",
            '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="white">'
            '<text x="2" y="17" font-family="monospace" font-size="12" font-weight="bold">PS</text></svg>'
        ),
        "cmd": (
            "#1a1a1a",
            '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="white">'
            '<polyline points="4 9 9 12 4 15" stroke="white" stroke-width="2" fill="none" stroke-linecap="round"/>'
            '<line x1="12" y1="15" x2="20" y2="15" stroke="white" stroke-width="2" stroke-linecap="round"/></svg>'
        ),
        "aduc": (
            "#c9943a",
            '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="white">'
            '<text x="3" y="17" font-family="serif" font-size="15" font-weight="bold">A</text></svg>'
        ),
    }
    bg, svg = icons.get(icon_type, icons["cmd"])
    return (
        f'<span class="verif-icon" style="background:{bg};">{svg}</span>'
    )


def _tool_card_html(tool_data):
    """Render one tool verification card."""
    icon_html = _tool_icon_html(tool_data.get("icon", "cmd"))
    tool_name = html_mod.escape(tool_data.get("tool", "Tool"))

    body_parts = []

    # Description
    desc = tool_data.get("desc", "")
    if desc:
        body_parts.append(f'<p class="verif-desc">{desc}</p>')

    # Numbered steps (for ADUC-style cards)
    steps = tool_data.get("steps", [])
    if steps:
        steps_html = "".join(
            f'<li>{s}</li>' for s in steps
        )
        body_parts.append(f'<ol class="verif-steps">{steps_html}</ol>')

    # Code block
    code = tool_data.get("code", "")
    if code:
        body_parts.append(
            f'<pre class="verif-code"><code>{html_mod.escape(code)}</code></pre>'
        )

    # Confirmation text
    confirm = tool_data.get("confirm", "")
    if confirm:
        body_parts.append(f'<p class="verif-confirm"><em>{confirm}</em></p>')

    body_html = "\n".join(body_parts)

    return f"""<div class="verif-card">
  <div class="verif-card-header">
    {icon_html}
    <span class="verif-tool-name">{tool_name}</span>
  </div>
  {body_html}
</div>"""


def _manual_verification_html(finding):
    """Render the full Manual Verification section for a finding."""
    vdata = _get_verification(finding)
    if not vdata or not vdata.get("tools"):
        return ""

    tools = vdata["tools"]
    # Build cards in pairs (2-column grid)
    cards_html = "\n".join(_tool_card_html(t) for t in tools)

    return f"""<div class="verif-section">
  <div class="verif-header">Manual Verification</div>
  <div class="verif-grid">
{cards_html}
  </div>
</div>"""


def _remediation_html(finding):
    """Render the Remediation section for a finding."""
    vdata = _get_verification(finding)
    if not vdata or not vdata.get("remediation"):
        return ""

    remed = vdata["remediation"]
    title = html_mod.escape(remed.get("title", "Remediation"))
    steps = remed.get("steps", [])

    steps_html = ""
    for i, step in enumerate(steps, 1):
        text = step.get("text", "")
        code = step.get("code", "")
        code_block = ""
        if code:
            code_block = f'<pre class="verif-code remed-code"><code>{html_mod.escape(code)}</code></pre>'
        steps_html += f"""<div class="remed-step">
  <span class="remed-num">{i}</span>
  <div class="remed-step-body">
    <p>{text}</p>
    {code_block}
  </div>
</div>"""

    return f"""<div class="remed-section">
  <div class="remed-header">Remediation</div>
  <div class="remed-box">
    <div class="remed-title">Recommended: {title}</div>
{steps_html}
  </div>
</div>"""


def _severity_badge_html(severity):
    sev = severity.lower()
    bg_light, _, _ = SEVERITY_COLORS.get(sev, ("#6b7280", "#f9fafb", "#374151"))
    return (
        f'<span class="badge badge-{sev}" '
        f'style="background:{bg_light};color:#fff;'
        f'padding:2px 10px;border-radius:12px;font-size:0.78rem;'
        f'font-weight:600;letter-spacing:0.05em;text-transform:uppercase;">'
        f'{html_mod.escape(severity.upper())}</span>'
    )


def _finding_card(finding, idx):
    severity = finding.get("severity", "info").lower()
    sev_colors = SEVERITY_COLORS.get(severity, SEVERITY_COLORS["info"])
    accent = sev_colors[0]
    category = finding.get("category", "Uncategorized")
    if isinstance(category, str):
        cat_list = [category]
    else:
        cat_list = list(category)

    details_html = ""
    if finding.get("details"):
        items = "".join(
            f"<li style='margin:2px 0;font-family:monospace;font-size:0.85rem;'>"
            f"{html_mod.escape(str(d)).replace('[[REDACTED]]', '<span style=\"color:#e53e3e;font-weight:bold\">REDACTED</span>')}</li>"
            for d in finding["details"][:50]
        )
        more = ""
        if len(finding["details"]) > 50:
            more = f"<li><em>... and {len(finding['details']) - 50} more</em></li>"
        details_html = f"""
    <details style='margin-top:12px;'>
      <summary style='cursor:pointer;font-weight:600;color:{accent};'>
        Affected Objects ({finding.get('affected_count', len(finding['details']))})
      </summary>
      <ul style='margin:8px 0 0 16px;padding:0;'>{items}{more}</ul>
    </details>"""

    verif_html = _manual_verification_html(finding)
    remed_html = _remediation_html(finding)

    cat_slug = cat_list[0].lower().replace(" ", "-").replace("&", "and").replace("/", "-")
    return f"""
<div class="finding-card" id="finding-{idx}"
     data-severity="{severity}"
     data-category="{" ".join(c.lower().replace(" ", "-").replace("&", "and").replace("/", "-") for c in cat_list)}"
     style="border-left:4px solid {accent};background:var(--card-bg);
            padding:20px 24px;margin-bottom:16px;border-radius:8px;
            box-shadow:var(--card-shadow);">
  <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:8px;">
    <div>
      <h3 style="margin:0 0 6px;font-size:1.05rem;">{html_mod.escape(finding.get('title',''))}</h3>
      {_severity_badge_html(severity)}
      <span style="margin-left:8px;font-size:0.85rem;color:var(--text-muted);">
        Risk Deduction: <strong style="color:{accent};">-{finding.get('deduction', 0)} pts</strong>
      </span>
      <span style="margin-left:8px;font-size:0.78rem;color:var(--text-muted);
                   background:var(--rec-bg);border-radius:10px;padding:2px 8px;">
        {html_mod.escape(", ".join(cat_list))}
      </span>
    </div>
  </div>
  <p style="margin:14px 0 8px;line-height:1.6;color:var(--text-secondary);">
    {html_mod.escape(finding.get('description', ''))}
  </p>
  <div style="background:var(--rec-bg);border-radius:6px;padding:10px 14px;margin-top:8px;">
    <strong style="font-size:0.85rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.05em;">
      Recommendation
    </strong>
    <p style="margin:4px 0 0;font-size:0.92rem;line-height:1.5;">
      {html_mod.escape(finding.get('recommendation', 'Review and remediate this finding.'))}
    </p>
  </div>
  {details_html}
  {verif_html}
  {remed_html}
</div>"""


def generate_report(output_file, domain, dc_host, username, protocols, findings, score):
    """Generate a self-contained HTML report dashboard with sidebar navigation."""
    from collections import defaultdict
    scan_time = __import__('datetime').datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    score_color = _score_color(score)
    grade = _grade(score)
    radius = 80
    circumference = 2 * 3.14159 * radius
    dash_offset = circumference * (1 - score / 100)

    # Severity counts
    sev_counts = {s: 0 for s in SEV_ORDER}
    for f in findings:
        sev = f.get("severity", "info").lower()
        if sev in sev_counts:
            sev_counts[sev] += 1

    # Sort findings: critical -> high -> medium -> low -> info
    findings = sorted(
        findings,
        key=lambda f: (
            _SEV_RANK.get(f.get("severity", "info").lower(), 99),
            -f.get("deduction", 0),
        ),
    )

    # ---- Sidebar ----
    cat_findings = defaultdict(list)
    for i, f in enumerate(findings):
        cats = f.get("category", "Uncategorized")
        if isinstance(cats, str):
            cats = [cats]
        for cat in cats:
            cat_findings[cat].append((i, f))

    sidebar_items_html = ""
    for cat in sorted(cat_findings.keys()):
        cat_id = cat.lower().replace(" ", "-").replace("&", "").replace("/", "-").replace(".", "")
        item_links = ""
        for idx, f in cat_findings[cat]:
            sev = f.get("severity", "info").lower()
            sev_color = SEVERITY_COLORS.get(sev, SEVERITY_COLORS["info"])[0]
            title_escaped = html_mod.escape(f.get("title", ""))
            item_links += (
                f'<a href="#finding-{idx}" class="sidebar-item" data-severity="{sev}"'
                f' onclick="sidebarNav(this,event)" title="{title_escaped}">'
                f'<span class="sev-dot" style="background:{sev_color};"></span>'
                f'<span class="sidebar-item-text">{title_escaped}</span>'
                f'</a>\n'
            )
        count = len(cat_findings[cat])
        sidebar_items_html += (
            f'<div class="cat-group" id="cat-{cat_id}">'
            f'<button class="cat-toggle" onclick="toggleCat(this)" aria-expanded="false">'
            f'<span class="cat-arrow">&#9660;</span>'
            f'<span class="cat-name">{html_mod.escape(cat)}</span>'
            f'<span class="cat-count">{count}</span>'
            f'</button>'
            f'<div class="cat-items collapsed">{item_links}</div>'
            f'</div>\n'
        )

    if not sidebar_items_html:
        sidebar_items_html = '<p class="sidebar-empty">No findings to navigate.</p>'

    # ---- Finding cards ----
    if findings:
        cards_html = "".join(_finding_card(f, i) for i, f in enumerate(findings))
    else:
        cards_html = (
            '<div style="text-align:center;padding:60px;color:var(--text-muted);">'
            '<div style="font-size:3rem;margin-bottom:16px;">&#10003;</div>'
            '<h3>No Vulnerabilities Found</h3>'
            '<p>All checks passed successfully.</p>'
            '</div>'
        )

    # ---- Severity chips ----
    severity_chips = ""
    for sev in SEV_ORDER:
        count = sev_counts.get(sev, 0)
        if count > 0:
            color = SEVERITY_COLORS[sev][0]
            cap_sev = sev.capitalize()
            severity_chips += (
                f'<button class="sev-chip" data-sev="{sev}" data-color="{color}"'
                f' onclick="toggleSeverityFilter(this)"'
                f' title="Filter: {cap_sev} (multi-select)">'
                f'<span class="chip-dot" style="background:{color};"></span>'
                f'<span class="chip-count">{count}</span>'
                f'<span class="chip-label">{cap_sev}</span>'
                f'</button>'
            )
    if not severity_chips:
        severity_chips = '<span style="color:var(--text-muted);">No issues found.</span>'

    # ---- Score summary ----
    if not findings:
        score_summary = "The domain passed all checks with an excellent security posture."
    else:
        score_summary = f"{len(findings)} finding(s) identified. Click a severity chip to filter."

    # ================================================================
    # CSS (plain string — no f-string, no {{ }} escaping needed)
    # ================================================================
    css = """
:root {
  --bg:#f8fafc; --card-bg:#ffffff;
  --card-shadow:0 1px 3px rgba(0,0,0,0.08),0 1px 2px rgba(0,0,0,0.04);
  --text-primary:#1e293b; --text-secondary:#475569; --text-muted:#94a3b8;
  --border:#e2e8f0; --header-bg:#1e293b; --header-text:#f8fafc;
  --rec-bg:#f1f5f9; --toggle-bg:#e2e8f0; --toggle-knob:#ffffff;
  --sidebar-bg:#1e293b; --sidebar-text:#cbd5e1; --sidebar-active:#3b82f6;
  --sidebar-hover:rgba(255,255,255,0.08); --sidebar-border:#334155;
  --sidebar-width:280px;
}
[data-theme="dark"] {
  --bg:#0f172a; --card-bg:#1e293b;
  --card-shadow:0 1px 3px rgba(0,0,0,0.4);
  --text-primary:#f1f5f9; --text-secondary:#94a3b8; --text-muted:#64748b;
  --border:#334155; --header-bg:#020617; --header-text:#f1f5f9;
  --rec-bg:#0f172a; --toggle-bg:#3b82f6; --toggle-knob:#ffffff;
  --sidebar-bg:#020617; --sidebar-text:#94a3b8; --sidebar-active:#60a5fa;
  --sidebar-hover:rgba(255,255,255,0.06); --sidebar-border:#1e293b;
}
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
  background:var(--bg);color:var(--text-primary);
  transition:background .3s,color .3s;min-height:100vh;}
.app-shell{display:flex;min-height:100vh;}
.sidebar{width:var(--sidebar-width);min-width:var(--sidebar-width);
  background:var(--sidebar-bg);color:var(--sidebar-text);
  position:sticky;top:0;height:100vh;overflow-y:auto;
  display:flex;flex-direction:column;
  border-right:1px solid var(--sidebar-border);
  transition:width .25s;z-index:90;}
.sidebar.collapsed{width:0;min-width:0;overflow:hidden;}
.main-col{flex:1;min-width:0;display:flex;flex-direction:column;}
header{background:var(--header-bg);color:var(--header-text);
  padding:16px 24px;display:flex;justify-content:space-between;
  align-items:center;flex-wrap:wrap;gap:12px;
  position:sticky;top:0;z-index:80;box-shadow:0 2px 8px rgba(0,0,0,.3);}
header h1{font-size:1.3rem;font-weight:700;letter-spacing:-.02em;}
.subtitle{font-size:.82rem;opacity:.65;margin-top:2px;}
.header-right{display:flex;align-items:center;gap:16px;}
.sb-toggle-btn{background:none;border:1px solid rgba(255,255,255,.2);
  color:var(--header-text);border-radius:6px;padding:6px 10px;
  cursor:pointer;font-size:1rem;line-height:1;}
.toggle-wrapper{display:flex;align-items:center;gap:8px;font-size:.85rem;}
.toggle-label{color:var(--header-text);opacity:.85;}
.toggle{position:relative;width:44px;height:24px;cursor:pointer;}
.toggle input{opacity:0;width:0;height:0;}
.toggle-track{position:absolute;inset:0;background:var(--toggle-bg);
  border-radius:24px;transition:background .3s;}
.toggle-track::after{content:'';position:absolute;width:18px;height:18px;
  background:var(--toggle-knob);border-radius:50%;
  top:3px;left:3px;transition:transform .3s;
  box-shadow:0 1px 3px rgba(0,0,0,.2);}
input:checked + .toggle-track::after{transform:translateX(20px);}
.sidebar-header{padding:16px 16px 12px;border-bottom:1px solid var(--sidebar-border);
  font-size:.7rem;font-weight:700;letter-spacing:.1em;
  text-transform:uppercase;opacity:.6;}
.sidebar-search{margin:10px 12px;position:relative;}
.sidebar-search input{width:100%;background:rgba(255,255,255,.07);
  border:1px solid var(--sidebar-border);border-radius:6px;
  padding:6px 10px;color:var(--sidebar-text);
  font-size:.8rem;outline:none;}
.sidebar-search input::placeholder{opacity:.4;}
.sidebar-nav{flex:1;overflow-y:auto;padding:8px 0;}
.cat-group{margin-bottom:2px;}
.cat-toggle{width:100%;background:none;border:none;cursor:pointer;
  display:flex;align-items:center;gap:8px;padding:8px 16px;
  color:var(--sidebar-text);font-size:.82rem;font-weight:600;
  text-align:left;transition:background .15s;}
.cat-toggle:hover{background:var(--sidebar-hover);}
.cat-arrow{font-size:.65rem;transition:transform .2s;flex-shrink:0;opacity:.7;}
.cat-toggle[aria-expanded="false"] .cat-arrow{transform:rotate(-90deg);}
.cat-name{flex:1;text-overflow:ellipsis;overflow:hidden;white-space:nowrap;}
.cat-count{background:rgba(255,255,255,.12);border-radius:10px;
  padding:1px 7px;font-size:.72rem;flex-shrink:0;}
.cat-items{overflow:hidden;transition:max-height .25s ease;}
.cat-items.collapsed{max-height:0;}
.sidebar-item{display:flex;align-items:center;gap:8px;padding:6px 16px 6px 24px;
  font-size:.78rem;color:var(--sidebar-text);text-decoration:none;
  transition:background .12s;cursor:pointer;
  border-left:2px solid transparent;}
.sidebar-item:hover{background:var(--sidebar-hover);}
.sidebar-item.active{background:rgba(59,130,246,.15);
  border-left-color:var(--sidebar-active);color:#fff;}
.sev-dot{width:7px;height:7px;border-radius:50%;flex-shrink:0;}
.sidebar-item-text{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.sidebar-empty{padding:16px;font-size:.82rem;opacity:.5;}
.sidebar-footer{padding:10px 16px;border-top:1px solid var(--sidebar-border);
  font-size:.7rem;opacity:.4;}
.container{max-width:960px;margin:0 auto;padding:28px 20px;}
.score-section{display:flex;align-items:center;gap:36px;
  background:var(--card-bg);border-radius:12px;
  padding:28px 36px;margin-bottom:24px;
  box-shadow:var(--card-shadow);flex-wrap:wrap;}
.gauge-wrap{position:relative;width:180px;height:180px;flex-shrink:0;}
.gauge-wrap svg{transform:rotate(-90deg);}
.gauge-center{position:absolute;inset:0;display:flex;flex-direction:column;
  align-items:center;justify-content:center;}
.gauge-score{font-size:2.8rem;font-weight:800;line-height:1;}
.gauge-label{font-size:.78rem;color:var(--text-muted);margin-top:4px;}
.gauge-grade{font-size:1.6rem;font-weight:700;width:40px;height:40px;
  border-radius:50%;display:flex;align-items:center;
  justify-content:center;color:#fff;margin-top:6px;}
.score-info h2{font-size:1.2rem;margin-bottom:12px;}
.chips-area{display:flex;flex-wrap:wrap;gap:4px;margin-top:12px;}
.sev-chip{display:inline-flex;align-items:center;gap:6px;
  border:2px solid transparent;border-radius:20px;
  padding:6px 14px;cursor:pointer;font-size:.9rem;
  background:var(--card-bg);color:var(--text-primary);
  transition:all .18s ease;outline:none;
  box-shadow:var(--card-shadow);}
.sev-chip:hover{transform:translateY(-1px);
  box-shadow:0 4px 10px rgba(0,0,0,.15);}
.sev-chip.active{transform:translateY(-1px);}
.chip-dot{width:10px;height:10px;border-radius:50%;flex-shrink:0;}
.chip-count{font-weight:700;}
.chip-label{text-transform:capitalize;color:var(--text-muted);}
.meta-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));
  gap:12px;background:var(--card-bg);border-radius:12px;
  padding:20px;margin-bottom:24px;box-shadow:var(--card-shadow);}
.meta-key{font-size:.72rem;text-transform:uppercase;letter-spacing:.08em;
  color:var(--text-muted);margin-bottom:4px;}
.meta-val{font-weight:600;font-size:.9rem;word-break:break-all;}
.section-header{display:flex;align-items:center;justify-content:space-between;
  margin-bottom:14px;flex-wrap:wrap;gap:8px;}
.section-header h2{font-size:1.1rem;}
.finding-card{transition:box-shadow .2s;}
.finding-card:hover{box-shadow:0 4px 12px rgba(0,0,0,.12)!important;}
.filter-hint{font-size:.82rem;color:var(--text-muted);font-style:italic;}
.clear-btn{background:none;border:1px solid var(--border);border-radius:12px;
  padding:3px 12px;font-size:.8rem;color:var(--text-muted);
  cursor:pointer;display:none;}
.clear-btn:hover{color:var(--text-primary);border-color:var(--text-primary);}
#no-results{display:none;text-align:center;padding:40px;
  color:var(--text-muted);font-size:.95rem;}
footer{text-align:center;padding:20px;color:var(--text-muted);font-size:.8rem;
  border-top:1px solid var(--border);margin-top:36px;}
@media(max-width:768px){
  .sidebar{position:fixed;left:0;top:0;height:100vh;
    transform:translateX(-100%);transition:transform .25s;}
  .sidebar:not(.collapsed){transform:translateX(0);}
}
/* ---- Manual Verification ---- */
.verif-section { margin-top: 24px; }
.verif-header {
  font-size: 0.7rem; font-weight: 700; letter-spacing: 0.12em;
  text-transform: uppercase; color: var(--text-muted); margin-bottom: 12px;
}
.verif-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
@media(max-width: 640px) { .verif-grid { grid-template-columns: 1fr; } }
.verif-card {
  border: 1px solid var(--border); border-radius: 10px;
  padding: 16px; background: var(--card-bg);
  box-shadow: 0 1px 3px rgba(0,0,0,0.06);
}
.verif-card-header { display: flex; align-items: center; gap: 10px; margin-bottom: 10px; }
.verif-icon {
  width: 32px; height: 32px; border-radius: 7px;
  display: flex; align-items: center; justify-content: center; flex-shrink: 0;
}
.verif-tool-name { font-weight: 700; font-size: 0.95rem; }
.verif-desc { font-size: 0.87rem; color: var(--text-secondary); margin: 0 0 10px; line-height: 1.55; }
.verif-steps { font-size: 0.87rem; color: var(--text-secondary); margin: 0 0 10px; padding-left: 18px; line-height: 1.6; }
.verif-code {
  background: #f5f5f5; border-radius: 6px; padding: 10px 12px;
  font-size: 0.82rem; font-family: ui-monospace,'Cascadia Code',Menlo,monospace;
  overflow-x: auto; white-space: pre; margin: 0 0 8px; color: #1e293b;
}
[data-theme="dark"] .verif-code { background: #0f172a; color: #e2e8f0; }
.verif-confirm { font-size: 0.83rem; color: var(--text-secondary); margin: 6px 0 0; line-height: 1.5; }
/* ---- Remediation ---- */
.remed-section { margin-top: 20px; }
.remed-header {
  font-size: 0.7rem; font-weight: 700; letter-spacing: 0.12em;
  text-transform: uppercase; color: var(--text-muted); margin-bottom: 12px;
}
.remed-box {
  border: 1.5px solid #86efac; border-radius: 10px;
  padding: 18px 20px; background: rgba(240,253,244,0.5);
}
[data-theme="dark"] .remed-box { background: rgba(20,83,45,0.15); border-color: #166534; }
.remed-title { font-weight: 700; font-size: 0.95rem; color: #16a34a; margin-bottom: 16px; }
[data-theme="dark"] .remed-title { color: #4ade80; }
.remed-step { display: flex; align-items: flex-start; gap: 14px; margin-bottom: 14px; }
.remed-num {
  width: 26px; height: 26px; border-radius: 50%;
  border: 2px solid #86efac; color: #16a34a; font-weight: 700;
  font-size: 0.8rem; display: flex; align-items: center;
  justify-content: center; flex-shrink: 0; margin-top: 1px;
}
[data-theme="dark"] .remed-num { border-color: #166534; color: #4ade80; }
.remed-step-body { flex: 1; }
.remed-step-body p { font-size: 0.88rem; color: var(--text-secondary); line-height: 1.55; margin: 0 0 8px; }
.remed-code { margin-top: 6px; }
""".strip()

    # ================================================================
    # JavaScript (plain string — no f-string, no {{ }} escaping needed)
    # ================================================================
    js = """
// ---- Theme ----
(function() {
  var saved = localStorage.getItem('adscan-theme');
  if (saved === 'dark') {
    document.documentElement.setAttribute('data-theme', 'dark');
    var t = document.getElementById('darkToggle');
    if (t) t.checked = true;
  }
})();
function toggleTheme(el) {
  var d = el.checked;
  document.documentElement.setAttribute('data-theme', d ? 'dark' : 'light');
  localStorage.setItem('adscan-theme', d ? 'dark' : 'light');
}
// ---- Sidebar ----
function toggleSidebar() {
  document.getElementById('sidebar').classList.toggle('collapsed');
}
// ---- Category collapse ----
function toggleCat(btn) {
  var expanded = btn.getAttribute('aria-expanded') === 'true';
  btn.setAttribute('aria-expanded', expanded ? 'false' : 'true');
  var items = btn.nextElementSibling;
  if (expanded) {
    items.style.maxHeight = items.scrollHeight + 'px';
    items.style.overflow = 'hidden';
    requestAnimationFrame(function() {
      requestAnimationFrame(function() { items.style.maxHeight = '0'; });
    });
    items.addEventListener('transitionend', function h() {
      items.classList.add('collapsed'); items.style.maxHeight = '';
      items.removeEventListener('transitionend', h);
    });
  } else {
    items.classList.remove('collapsed');
    items.style.overflow = 'hidden';
    items.style.maxHeight = items.scrollHeight + 'px';
    items.addEventListener('transitionend', function h() {
      items.style.maxHeight = 'none'; items.style.overflow = '';
      items.removeEventListener('transitionend', h);
    });
  }
}
// ---- Sidebar search ----
function sidebarSearchFilter(val) {
  var q = val.toLowerCase().trim();
  document.querySelectorAll('.cat-group').forEach(function(grp) {
    var any = false;
    grp.querySelectorAll('.sidebar-item').forEach(function(item) {
      var match = !q || item.querySelector('.sidebar-item-text').textContent.toLowerCase().includes(q);
      item.style.display = match ? '' : 'none';
      if (match) any = true;
    });
    grp.style.display = any ? '' : 'none';
  });
}
// ---- Sidebar active ----
function sidebarNav(link, e) {
  document.querySelectorAll('.sidebar-item').forEach(function(a) { a.classList.remove('active'); });
  link.classList.add('active');
}
// ---- Intersection observer ----
(function() {
  var cards = document.querySelectorAll('.finding-card[id]');
  if (!cards.length) return;
  var obs = new IntersectionObserver(function(entries) {
    entries.forEach(function(entry) {
      if (!entry.isIntersecting) return;
      var id = entry.target.id;
      document.querySelectorAll('.sidebar-item').forEach(function(a) {
        var match = a.getAttribute('href') === '#' + id;
        a.classList.toggle('active', match);
        if (match) a.scrollIntoView({block:'nearest',behavior:'smooth'});
      });
    });
  }, {threshold: 0.35});
  cards.forEach(function(c) { obs.observe(c); });
})();
// ---- Severity chip filter ----
var activeFilters = {};
function toggleSeverityFilter(btn) {
  var sev = btn.getAttribute('data-sev');
  var color = btn.getAttribute('data-color') || '#6b7280';
  if (activeFilters[sev]) {
    delete activeFilters[sev];
    btn.classList.remove('active');
    btn.style.borderColor = 'transparent';
    btn.style.color = '';
  } else {
    activeFilters[sev] = true;
    btn.classList.add('active');
    btn.style.borderColor = color;
    btn.style.color = color;
  }
  applyFilters();
}
function applyFilters() {
  var keys = Object.keys(activeFilters);
  var cards = document.querySelectorAll('.finding-card');
  var clearBtn = document.getElementById('clear-btn');
  var hintEl = document.getElementById('filter-hint');
  var countEl = document.getElementById('visible-count');
  var noRes = document.getElementById('no-results');
  var vis = 0;
  if (keys.length === 0) {
    cards.forEach(function(c) { c.style.display = ''; });
    vis = cards.length;
    if (clearBtn) clearBtn.style.display = 'none';
    if (hintEl) hintEl.textContent = '';
  } else {
    cards.forEach(function(c) {
      var match = !!activeFilters[c.getAttribute('data-severity')];
      c.style.display = match ? '' : 'none';
      if (match) vis++;
    });
    if (clearBtn) clearBtn.style.display = 'inline-block';
    if (hintEl) hintEl.textContent = 'Showing: ' + keys.join(', ');
  }
  if (countEl) countEl.textContent = vis;
  if (noRes) noRes.style.display = vis === 0 ? 'block' : 'none';
}
function clearFilters() {
  activeFilters = {};
  document.querySelectorAll('.sev-chip').forEach(function(b) {
    b.classList.remove('active');
    b.style.borderColor = 'transparent';
    b.style.color = '';
  });
  applyFilters();
}
""".strip()

    # ================================================================
    # HTML (f-string only for Python values — NO JS or CSS braces)
    # ================================================================
    html_content = f"""<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ADScan Report - {html_mod.escape(domain)}</title>
  <style>{css}</style>
</head>
<body>
<div class="app-shell">
  <aside class="sidebar" id="sidebar">
    <div class="sidebar-header">Category Navigator</div>
    <div class="sidebar-search">
      <input type="text" id="sidebarSearch" placeholder="&#128269; Filter checks..."
             oninput="sidebarSearchFilter(this.value)">
    </div>
    <nav class="sidebar-nav" id="sidebarNav">
      {sidebar_items_html}
    </nav>
    <div class="sidebar-footer">ADScan &bull; {html_mod.escape(domain)}</div>
  </aside>
  <div class="main-col">
    <header>
      <div style="display:flex;align-items:center;gap:12px;">
        <button class="sb-toggle-btn" onclick="toggleSidebar()" title="Toggle sidebar">&#9776;</button>
        <div>
          <h1>&#x1F6E1; ADScan Report</h1>
          <div class="subtitle">Active Directory Vulnerability Assessment &mdash; {html_mod.escape(domain)}</div>
        </div>
      </div>
      <div class="header-right">
        <div class="toggle-wrapper">
          <span class="toggle-label">&#9788;</span>
          <label class="toggle">
            <input type="checkbox" id="darkToggle" onchange="toggleTheme(this)">
            <span class="toggle-track"></span>
          </label>
          <span class="toggle-label">&#9790;</span>
        </div>
      </div>
    </header>
    <div class="container">
      <div class="score-section">
        <div class="gauge-wrap">
          <svg width="180" height="180" viewBox="0 0 200 200">
            <circle cx="100" cy="100" r="{radius}" fill="none" stroke="var(--border)" stroke-width="16"/>
            <circle cx="100" cy="100" r="{radius}" fill="none" stroke="{score_color}" stroke-width="16"
              stroke-dasharray="{circumference:.2f}" stroke-dashoffset="{dash_offset:.2f}"
              stroke-linecap="round"/>
          </svg>
          <div class="gauge-center">
            <div class="gauge-score" style="color:{score_color};">{score}</div>
            <div class="gauge-label">/ 100</div>
            <div class="gauge-grade" style="background:{score_color};">{grade}</div>
          </div>
        </div>
        <div class="score-info">
          <h2>Security Score</h2>
          <p style="color:var(--text-secondary);margin-bottom:14px;line-height:1.6;">{score_summary}</p>
          <div class="chips-area">{severity_chips}</div>
        </div>
      </div>
      <div class="meta-grid">
        <div><div class="meta-key">Domain</div><div class="meta-val">{html_mod.escape(domain)}</div></div>
        <div><div class="meta-key">Domain Controller</div><div class="meta-val">{html_mod.escape(dc_host)}</div></div>
        <div><div class="meta-key">Username</div><div class="meta-val">{html_mod.escape(username)}</div></div>
        <div><div class="meta-key">Protocol(s)</div><div class="meta-val">{html_mod.escape(', '.join(p.upper() for p in protocols))}</div></div>
        <div><div class="meta-key">Scan Time</div><div class="meta-val">{html_mod.escape(scan_time)}</div></div>
        <div><div class="meta-key">Total Findings</div><div class="meta-val">{len(findings)}</div></div>
      </div>
      <div class="section-header">
        <h2>Findings (<span id="visible-count">{len(findings)}</span>)</h2>
        <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
          <span class="filter-hint" id="filter-hint"></span>
          <button class="clear-btn" id="clear-btn" onclick="clearFilters()">&times; Clear filter</button>
        </div>
      </div>
      <div id="no-results">No findings match the selected filter(s).
        <a href="#" onclick="clearFilters();return false;" style="color:inherit;">Clear</a>
      </div>
      {cards_html}
    </div>
    <footer>
      Generated by <strong>ADScan</strong> &mdash; {html_mod.escape(scan_time)} &mdash;
      <a href="https://github.com/BrocktonPointSolutions/ADScan"
         style="color:inherit;text-decoration:underline;" target="_blank">
        github.com/BrocktonPointSolutions/ADScan
      </a>
    </footer>
  </div>
</div>
<script>{js}</script>
</body>
</html>"""

    with open(output_file, "w", encoding="utf-8") as fh:
        fh.write(html_content)


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------
def generate_json_report(output_file, domain, dc_host, username, protocols, findings, score):
    """Write a machine-readable JSON report."""
    import json
    from datetime import datetime

    def _grade(s):
        if s >= 90: return "A"
        if s >= 75: return "B"
        if s >= 60: return "C"
        if s >= 40: return "D"
        return "F"

    payload = {
        "meta": {
            "tool": "ADScan",
            "version": "1.0",
            "scan_time": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
            "domain": domain,
            "dc_host": dc_host,
            "username": username,
            "protocols": protocols,
        },
        "score": {
            "value": score,
            "grade": _grade(score),
        },
        "summary": {
            "total_findings": len(findings),
            "critical": sum(1 for f in findings if f.get("severity", "").lower() == "critical"),
            "high":     sum(1 for f in findings if f.get("severity", "").lower() == "high"),
            "medium":   sum(1 for f in findings if f.get("severity", "").lower() == "medium"),
            "low":      sum(1 for f in findings if f.get("severity", "").lower() == "low"),
            "info":     sum(1 for f in findings if f.get("severity", "").lower() == "info"),
        },
        "findings": [
            {
                "title":          f.get("title", ""),
                "severity":       f.get("severity", "info"),
                "category":       f.get("category", "Uncategorized"),
                "deduction":      f.get("deduction", 0),
                "description":    f.get("description", ""),
                "recommendation": f.get("recommendation", ""),
                "affected_count": f.get("affected_count", len(f.get("details", []))),
                "details":        f.get("details", []),
            }
            for f in findings
        ],
    }

    with open(output_file, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, default=str)


# ---------------------------------------------------------------------------
# CSV output
# ---------------------------------------------------------------------------
def generate_csv_report(output_file, domain, dc_host, username, protocols, findings, score):
    """Write a flat CSV report — one row per finding."""
    import csv
    from datetime import datetime

    fieldnames = [
        "scan_time", "domain", "dc_host", "username", "protocols", "score",
        "title", "severity", "category", "deduction",
        "description", "recommendation", "affected_count", "details_sample",
    ]
    scan_time = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    proto_str = ", ".join(protocols)

    with open(output_file, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()

        if not findings:
            writer.writerow({
                "scan_time": scan_time, "domain": domain, "dc_host": dc_host,
                "username": username, "protocols": proto_str, "score": score,
                "title": "No findings", "severity": "", "category": "",
                "deduction": 0, "description": "", "recommendation": "",
                "affected_count": 0, "details_sample": "",
            })
            return

        for f in findings:
            details = f.get("details", [])
            sample = " | ".join(str(d) for d in details[:5])
            if len(details) > 5:
                sample += f" ... (+{len(details) - 5} more)"
            cats = f.get("category", "Uncategorized")
            if not isinstance(cats, str):
                cats = ", ".join(cats)
            writer.writerow({
                "scan_time":      scan_time,
                "domain":         domain,
                "dc_host":        dc_host,
                "username":       username,
                "protocols":      proto_str,
                "score":          score,
                "title":          f.get("title", ""),
                "severity":       f.get("severity", "info"),
                "category":       cats,
                "deduction":      f.get("deduction", 0),
                "description":    f.get("description", ""),
                "recommendation": f.get("recommendation", ""),
                "affected_count": f.get("affected_count", len(details)),
                "details_sample": sample,
            })
