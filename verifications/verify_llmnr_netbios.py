"""
verifications/verify_llmnr_netbios.py
Manual Verification and Remediation data for ADScan findings matching: LLMNR and NetBIOS
"""

MATCH_KEYS = ["llmnr and netbios"]

TOOLS = [
    {
        "tool": "PowerShell",
        "icon": "ps",
        "desc": "Check if LLMNR is disabled via Group Policy registry value.",
        "code": "Get-ItemProperty -Path \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\" \`\n    -Name EnableMulticast -ErrorAction SilentlyContinue",
        "confirm": "A value of <strong>0</strong> means LLMNR is disabled. If the key is absent, LLMNR is enabled by default.",
    },
    {
        "tool": "PowerShell",
        "icon": "ps",
        "desc": "Check if NetBIOS over TCP/IP is disabled on all network adapters.",
        "code": "Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {$_.TcpipNetbiosOptions -ne 2} | Select-Object Description,TcpipNetbiosOptions",
        "confirm": "A <strong>TcpipNetbiosOptions</strong> value of <strong>2</strong> means NetBIOS-NS is disabled. Values of <strong>0</strong> (default via DHCP) or <strong>1</strong> (enabled) confirm the finding.",
    },
    {
        "tool": "Responder",
        "icon": "impacket",
        "desc": "Passively confirm LLMNR/NBT-NS is active on the network segment.",
        "code": "# Run in analyse mode (no poisoning) from a Linux host:\npython3 Responder.py -I <interface> -A",
        "confirm": "If Responder reports LLMNR or NBT-NS queries being received, the protocols are active on the network.",
    },
]

REMEDIATION = {
    "title": "Disable LLMNR and NetBIOS-NS via Group Policy",
    "steps": [
        {
            "text": "Disable LLMNR via GPO:",
            "code": "Computer Configuration -> Administrative Templates\n-> Network -> DNS Client\n-> Turn off multicast name resolution -> Enabled",
        },
        {
            "text": "Disable NetBIOS over TCP/IP via GPO DHCP option or registry preference:",
            "code": "Computer Configuration -> Preferences -> Windows Settings -> Registry\nKey: HKLM\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces\\Tcpip_*\nValue: NetbiosOptions = 2 (REG_DWORD)",
        },
        {
            "text": "Verify no legacy applications depend on NetBIOS name resolution. Check for any hosts relying on WINS or NetBIOS browsing before disabling.",
        },
    ],
}
