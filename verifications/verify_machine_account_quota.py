"""
verifications/verify_machine_account_quota.py
Manual Verification and Remediation data for ADScan findings matching: Machine Account Quota
"""

MATCH_KEYS = ["machine account quota"]

TOOLS = [
    {
        "tool": "PowerShell",
        "icon": "ps",
        "desc": "Read the ms-DS-MachineAccountQuota attribute on the domain root.",
        "code": "Get-ADObject -Identity (Get-ADDomain).DistinguishedName \`\n    -Properties ms-DS-MachineAccountQuota \`\n    | Select-Object ms-DS-MachineAccountQuota",
        "confirm": "Any value other than <strong>0</strong> confirms the finding. Default is 10.",
    },
    {
        "tool": "NetExec",
        "icon": "netexec",
        "desc": "Query MAQ remotely without domain credentials.",
        "code": "netexec ldap <DC_IP> -u <username> -p <password> -M maq",
        "confirm": "Output shows the current MachineAccountQuota value. Any value above 0 is a risk.",
    },
]

REMEDIATION = {
    "title": "Set Machine Account Quota to 0",
    "steps": [
        {
            "text": "Set <strong>ms-DS-MachineAccountQuota</strong> to <strong>0</strong> to prevent standard users from joining machines to the domain:",
            "code": "Set-ADDomain -Identity (Get-ADDomain) -Replace @{'ms-DS-MachineAccountQuota' = 0}",
        },
        {
            "text": "This can also be set via <strong>ADSI Edit</strong>: connect to the domain root, open Properties, find <code>ms-DS-MachineAccountQuota</code> and set it to <code>0</code>.",
        },
        {
            "text": "Delegate machine-join rights explicitly to a specific group or account via the OU-level <strong>Add workstations to domain</strong> user right, rather than relying on the domain-wide quota.",
        },
    ],
}
