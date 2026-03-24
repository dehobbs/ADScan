"""
verifications/verify_subnets_not_assigned.py
Manual Verification and Remediation data for ADScan findings matching:
subnets not assigned to a site
"""

MATCH_KEYS = [
    "subnets not assigned to a site",
    "subnet not assigned",
    "unassigned subnet",
]

TOOLS = [
    {
        "tool": "PowerShell",
        "icon": "ps",
        "desc": "List all AD subnets not assigned to a site.",
        "code": "Get-ADObject -SearchBase (Get-ADRootDSE).configurationNamingContext \\\n    -Filter {objectClass -eq 'subnet'} \\\n    -Properties siteObject, name |\n    Where-Object { -not $_.siteObject } |\n    Select-Object Name, @{n='Site';e={'(none)'}}",
        "confirm": "Each listed subnet is not mapped to any AD site — DC locator queries from hosts in these ranges will fail to find a local DC and will fall back to any available DC.",
    },
    {
        "tool": "ADSS (dssite.msc)",
        "icon": "aduc",
        "desc": "View and assign subnets to sites using Active Directory Sites and Services.",
        "steps": [
            "Open <code>dssite.msc</code>",
            "Expand <strong>Sites</strong> → <strong>Subnets</strong>",
            "Subnets without a site assignment show <strong>(none)</strong> in the Site column",
            "Right-click each unassigned subnet → Properties → Site tab → assign to the correct site",
        ],
    },
    {
        "tool": "nltest",
        "icon": "cmd",
        "desc": "Verify DC locator is finding the correct site for a client.",
        "code": "nltest /dsgetsite\nnltest /dsgetdc:<domain> /site:<sitename>",
        "confirm": "If the returned site is incorrect or the command fails, subnet-to-site mapping is broken for that client.",
    },
    {
        "tool": "PowerShell (site lookup)",
        "icon": "ps",
        "desc": "Check which site a specific host resolves to.",
        "code": "[System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite().Name",
        "confirm": "Compare the returned site name against expected topology. <strong>Default-First-Site-Name</strong> often indicates a missing subnet-to-site mapping.",
    },
]

REMEDIATION = {
    "title": "Assign all subnets to the correct AD site",
    "steps": [
        {
            "text": "Audit all IP subnets in use and map each to its correct AD site via <code>dssite.msc</code> or PowerShell:",
            "code": "New-ADObject -Name '10.10.20.0/24' -Type subnet \\\n    -Path 'CN=Subnets,CN=Sites,CN=Configuration,DC=<domain>,DC=<tld>' \\\n    -OtherAttributes @{siteObject='CN=BranchSite,CN=Sites,CN=Configuration,DC=<domain>,DC=<tld>'}",
        },
        {
            "text": "For existing subnet objects without a site assignment, set the <strong>siteObject</strong> attribute:",
            "code": "$subnet = Get-ADObject -Filter {name -eq '10.10.20.0/24'} \\\n    -SearchBase (Get-ADRootDSE).configurationNamingContext\nSet-ADObject $subnet -Replace @{siteObject='CN=BranchSite,CN=Sites,CN=Configuration,DC=<domain>,DC=<tld>'}",
        },
        {
            "text": "Correct subnet-to-site mapping ensures clients authenticate against the nearest DC, reduces WAN authentication traffic, and improves Group Policy processing time.",
        },
    ],
}

REFERENCES = [
    {"title": "Active Directory Sites and Subnets - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/understanding-active-directory-site-topology", "tag": "vendor"},
    {"title": "Subnet Objects in Active Directory - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/windows/win32/adschema/c-subnet", "tag": "vendor"},
    {"title": "DC Locator Process - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/how-domain-controllers-are-located", "tag": "vendor"},
    {"title": "CIS Benchmark: Maintain accurate AD Sites and Services topology", "url": "https://www.cisecurity.org/benchmark/microsoft_windows_server", "tag": "defense"},
]
