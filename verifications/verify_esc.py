"""
verifications/verify_esc.py
Manual Verification and Remediation data for ADScan findings matching: esc
"""

MATCH_KEYS = ["esc"]

TOOLS = [
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
        "code": "netexec ldap <DC_IP> -u <username> -p <password> -M certipy-find",
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
]

REMEDIATION = {
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
}
