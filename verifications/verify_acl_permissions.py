"""
verifications/verify_acl_permissions.py
Manual verification, remediation, and references for ACL/permissions findings.
Covers: DCSync rights, ESC4/ESC5/ESC7 ADCS ACL abuse, RBCD delegation ACLs.
"""

MATCH_KEYS = [
    "acl / permissions",
    "dcsync",
    "ds-replication",
    "esc4",
    "esc5",
    "esc7",
    "resource-based constrained delegation (rbcd) configured",
    "protected users group",
]

TOOLS = [
    {
        "tool": "PowerShell (AD Module + RSAT)",
        "icon": "ps",
        "desc": "Identify accounts with DS-Replication rights (DCSync) on the domain object.",
        "code": (            "# Find DCSync-capable principals\n"            "(Get-ACL 'AD:\\DC=corp,DC=local').Access |\n"            "  Where-Object {\n"            "    $_.ObjectType -in @(\n"            "      '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',\n"            "      '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'\n"            "    ) -and $_.AccessControlType -eq 'Allow'\n"            "  } |\n"            "  Select-Object IdentityReference, ActiveDirectoryRights"
        ),
        "confirm": "Only Domain Admins, SYSTEM, and Enterprise DCs should appear. Any other principal is a DCSync risk.",
    },
    {
        "tool": "NetExec",
        "icon": "netexec",
        "desc": "Enumerate ACL permissions and DCSync-capable accounts from Linux.",
        "code": (            "# Enumerate domain object ACL\n"            "netexec ldap <DC_IP> \\\n"            "  -u <USER> -p <PASSWORD> \\\n"            "  -M daclread --options TARGET=<base_dn>"
        ),
        "confirm": "Look for unexpected GenericAll, WriteDACL, or DS-Replication-Get-Changes-All rights.",
    },
    {
        "tool": "Impacket (secretsdump.py)",
        "icon": "impacket",
        "desc": "Confirm DCSync is exploitable by attempting a credential dump.",
        "code": (            "# WARNING: This performs an actual DCSync\n"            "secretsdump.py \\\n"            "  '<DOMAIN>/<USER>:<PASSWORD>'@<DC_IP> \\\n"            "  -just-dc-ntlm -just-dc-user krbtgt"
        ),
        "confirm": "If the krbtgt hash is returned without Domain Admin rights, DCSync is misconfigured.",
    },
]

REMEDIATION = {
    "title": "Remove unauthorised DCSync, certificate template, and delegation ACL entries",
    "steps": [
        {
            "text": "Revoke unauthorised DS-Replication rights from the domain object:",
            "code": (                "$domainDN = (Get-ADDomain).DistinguishedName\n"                "$acl = Get-Acl \"AD:\\$domainDN\"\n"                "# Remove the specific ACE for the unauthorised principal\n"                "$ace = $acl.Access | Where-Object {$_.IdentityReference -eq 'DOMAIN\\BadAccount'}\n"                "$acl.RemoveAccessRule($ace)\n"                "Set-Acl -AclObject $acl \"AD:\\$domainDN\""
            ),
        },
        {
            "text": "Review and harden certificate template ACLs (ESC4). Remove GenericWrite, WriteDACL, WriteOwner from non-PKI-admin accounts using the Certificate Authority MMC (certsrv.msc) or:",
            "code": "certutil -setreg policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2",
        },
        {
            "text": "For RBCD misconfigurations: remove the msDS-AllowedToActOnBehalfOfOtherIdentity attribute from any computer account where it is not intentionally set.",
            "code": "Set-ADComputer <ComputerName> -Clear msDS-AllowedToActOnBehalfOfOtherIdentity",
        },
        {
            "text": "Populate the Protected Users group with all Tier-0 accounts (Domain Admins, Enterprise Admins, Schema Admins, krbtgt). Test for service impact before bulk addition.",
        },
    ],
}

REFERENCES = [
    {
        "title": "Microsoft — DS-Replication-Get-Changes Extended Right",
        "url": "https://learn.microsoft.com/en-us/windows/win32/adschema/r-ds-replication-get-changes",
        "tag": "vendor",
    },
    {
        "title": "MITRE ATT&CK — OS Credential Dumping: DCSync (T1003.006)",
        "url": "https://attack.mitre.org/techniques/T1003/006/",
        "tag": "attack",
    },
    {
        "title": "SpecterOps — Certified Pre-Owned (ADCS Abuse, ESC4/5/7)",
        "url": "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
        "tag": "research",
    },
    {
        "title": "Microsoft — Protected Users Security Group",
        "url": "https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group",
        "tag": "defense",
    },
    {
        "title": "Impacket secretsdump.py — DCSync",
        "url": "https://github.com/fortra/impacket/blob/master/examples/secretsdump.py",
        "tag": "tool",
    },
]
