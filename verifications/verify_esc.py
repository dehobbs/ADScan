"""
verifications/verify_esc.py
Manual Verification and Remediation data for ADScan findings matching: ESC1-3, ESC4, ESC6-9, ESC16
"""

MATCH_KEYS = ["esc1", "esc2", "esc3", "esc4", "esc6", "esc7", "esc8", "esc9", "esc16"]

TOOLS = [
    {
        "tool": "Certipy",
        "icon": "impacket",
        "desc": "Comprehensive ADCS enumeration — finds ESC misconfigurations including template and CA-level issues.",
        "code": "certipy find -u <username>@<domain> -p <password> -dc-ip <DC_IP> -enabled -vulnerable",
        "confirm": "Any template or CA listed with ESC flags in the output is exploitable.",
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
        "desc": "Enumerate certificate templates via LDAP.",
        "code": "Get-ADObject -SearchBase \"CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<tld>\" `\n    -Filter * -Properties * `\n    | Select-Object Name,msPKI-Certificate-Name-Flag,msPKI-Enrollment-Flag",
        "confirm": "Templates with <strong>ENROLLEE_SUPPLIES_SUBJECT</strong> flag and broad enrollment rights are ESC1-vulnerable.",
    },
    {
        "tool": "certutil",
        "icon": "cmd",
        "desc": "Enumerate Certificate Authorities and templates from Windows.",
        "code": "certutil -config - -ping\ncertutil -catemplates",
        "confirm": "Lists available templates — compare against Certipy output to identify misconfigurations. This must be performed on the Certificate Authority (CA) Server.",
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
            "code": "# In Certificate Template Properties \u2192 Issuance Requirements\n# Check: \"CA certificate manager approval\"",
        },
        {
            "text": "Run Certipy regularly to re-audit: <code>certipy find -vulnerable</code> — this should be part of your change management process.",
        },
    ],
}
