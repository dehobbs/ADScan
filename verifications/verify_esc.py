"""
verifications/verify_esc.py
Manual Verification and Remediation data for ADScan findings matching: ESC1-3, ESC4, ESC6-9, ESC16
"""

MATCH_KEYS = [
    "enrollee-supplied san",
    "any-purpose",
    "enrollment agent",
    "editf_attributesubjectaltname2",
    "web enrollment endpoint",
    "ct_flag_no_security_extension",
    "write access to a certificate template",
    "manageca or managecertificates",
    "szoid_ntds_ca_security_ext globally",
    "esc1:",
    "esc2:",
    "esc3:",
    "esc4:",
    "esc5:",
    "esc6:",
    "esc7:",
    "esc8:",
    "esc9:",
]

TOOLS = [
    {
        "tool": "Certipy",
        "icon": "impacket",
        "desc": "Comprehensive ADCS enumeration — finds ESC misconfigurations including template and CA-level issues.",
        "code": "certipy-ad find -u <username>@<domain> -p <password> -dc-ip <DC_IP> -enabled -vulnerable",
        "confirm": "Any template or CA listed with ESC flags in the output is exploitable.",
    },
    {
        "tool": "NetExec",
        "icon": "netexec",
        "desc": "Enumerate ADCS certificate authorities and templates.",
        "code": "netexec ldap <DC_IP> -u <username> -p <password> -M certipy-ad",
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
            "text": "Run Certipy regularly to re-audit: <code>certipy-ad find -vulnerable</code> — this should be part of your change management process.",
        },
    ],
}


REFERENCES = [
    {"title": "Active Directory Certificate Services Overview - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/active-directory-certificate-services-overview", "tag": "vendor"},
    {"title": "Certificate Template Security - Microsoft Docs", "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts", "tag": "vendor"},
    {"title": "MITRE ATT&CK: Steal or Forge Authentication Certificates (T1649)", "url": "https://attack.mitre.org/techniques/T1649/", "tag": "attack"},
    {"title": "Certified Pre-Owned - SpecterOps ADCS Research", "url": "https://posts.specterops.io/certified-pre-owned-d95910965cd2", "tag": "research"},
    {"title": "Certipy - ADCS Enumeration and Exploitation", "url": "https://github.com/ly4k/Certipy", "tag": "tool"},
    {"title": "Certify - ADCS Vulnerability Tool", "url": "https://github.com/GhostPack/Certify", "tag": "tool"},
    {"title": "NetExec - ADCS Enumeration Module", "url": "https://github.com/Pennyw0rth/NetExec", "tag": "tool"},
    {"title": "CIS Benchmark: AD CS Hardening", "url": "https://www.cisecurity.org/benchmark/microsoft_windows_server", "tag": "defense"},
    {"title": "Defending AD CS - Microsoft Security Blog", "url": "https://www.microsoft.com/en-us/security/blog/2022/08/16/defending-against-active-directory-certificate-services-attacks/", "tag": "defense"},
    {"title": "Defender for Identity: ADCS Alerts", "url": "https://learn.microsoft.com/en-us/defender-for-identity/credential-access-alerts", "tag": "defense"},
]
