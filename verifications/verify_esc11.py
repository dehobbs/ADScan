"""
verifications/verify_esc11.py
Manual Verification and Remediation data for ADScan findings matching: ESC11
"""

MATCH_KEYS = ["esc11"]

TOOLS = [
    {
        "tool": "PowerShell",
        "icon": "ps",
        "desc": "Check the IF_ENFORCEENCRYPTICERTREQUEST flag on each CA via LDAP.",
        "code": "Get-ADObject -SearchBase \"CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<tld>\" \`\n    -Filter * -Properties flags \`\n    | Select-Object Name,flags",
        "confirm": "If the <strong>flags</strong> value does not have bit 0x200 set (i.e. <code>flags -band 0x200</code> returns 0), the CA is vulnerable.",
    },
    {
        "tool": "certutil",
        "icon": "cmd",
        "desc": "Read the CA InterfaceFlags registry value directly on the CA server.",
        "code": "certutil -config <CA> -getreg CA\\InterfaceFlags",
        "confirm": "If <strong>IF_ENFORCEENCRYPTICERTREQUEST</strong> is not listed in the output, encrypted requests are not enforced and the CA is vulnerable.",
    },
]

REMEDIATION = {
    "title": "Enable encrypted ICPR certificate requests on the CA",
    "steps": [
        {
            "text": "Run the following command on the CA server to enable the flag, then restart the CertSvc service:",
            "code": "certutil -config <CA> -setreg CA\\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST\nnet stop certsvc && net start certsvc",
        },
        {
            "text": "Enable <strong>SMB signing</strong> domain-wide to mitigate NTLM relay more broadly.",
        },
        {
            "text": "Enable <strong>Extended Protection for Authentication (EPA)</strong> on the CA where applicable.",
        },
    ],
}
