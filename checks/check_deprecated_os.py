"""
checks/check_deprecated_os.py - Deprecated / End-of-Life Operating System checks

Checks:
  - Enabled computer accounts running EOL Windows workstation OS                -20 (critical)
  - Enabled computer accounts running EOL Windows Server OS                     -20 (critical)
  - Enabled computer accounts running older-but-common server OSes (2012/R2)    -15 (high)

EOL reference dates (Microsoft):
  Windows XP         : April 2014
  Windows Vista      : April 2017
  Windows 7          : January 2020
  Windows 8          : January 2016
  Windows 8.1        : January 2023
  Windows Server 2003: July 2015
  Windows Server 2008: January 2020
  Windows Server 2008 R2: January 2020
  Windows Server 2012: October 2023
  Windows Server 2012 R2: October 2023
"""

CHECK_NAME = "Deprecated Operating Systems"
CHECK_ORDER = 20
CHECK_CATEGORY = ["Deprecated Operating Systems"]

# Strings to match against operatingSystem attribute (case-insensitive substring)
EOL_CRITICAL_WORKSTATIONS = [
    "windows xp",
    "windows vista",
    "windows 7",
    "windows 8 ",    # Windows 8 (not 8.1)
    "windows 8.1",
]

EOL_CRITICAL_SERVERS = [
    "windows server 2003",
    "windows server 2008",   # covers 2008 and 2008 R2
]

EOL_HIGH_SERVERS = [
    "windows server 2012",   # covers 2012 and 2012 R2
]


def _match(os_str, patterns):
    os_lower = os_str.lower()
    return any(p in os_lower for p in patterns)


def run_check(connector, verbose=False):
    findings = []

    try:
        computers = connector.ldap_search(
            connector.base_dn,
            "(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            ["cn", "operatingSystem", "operatingSystemVersion", "dNSHostName"],
        ) or []
    except Exception as exc:
        if verbose:
            print(f"[DeprecatedOS] LDAP error: {exc}")
        return findings

    if verbose:
        print(f"[DeprecatedOS] Total enabled computers: {len(computers)}")

    # Categorise
    critical_workstations = []
    critical_servers = []
    high_servers = []

    for comp in computers:
        os_name = comp.get("operatingSystem", "") or ""
        if not os_name:
            continue
        name = comp.get("cn", comp.get("dNSHostName", "Unknown"))
        os_ver = comp.get("operatingSystemVersion", "")
        label = f"{name} ({os_name}{' ' + os_ver if os_ver else ''})"

        if _match(os_name, EOL_CRITICAL_WORKSTATIONS):
            critical_workstations.append(label)
        elif _match(os_name, EOL_CRITICAL_SERVERS):
            critical_servers.append(label)
        elif _match(os_name, EOL_HIGH_SERVERS):
            high_servers.append(label)

    if critical_workstations:
        findings.append({
            "title": "End-of-Life Workstation OS Detected",
            "severity": "critical",
            "deduction": 20,
            "description": (
                f"{len(critical_workstations)} enabled computer account(s) are running "
                "end-of-life Windows workstation operating systems (XP, Vista, 7, 8, or 8.1). "
                "These receive no security updates and are highly susceptible to known exploits "
                "including EternalBlue (MS17-010) and many others."
            ),
            "recommendation": (
                "Immediately upgrade or decommission all EOL workstations. "
                "If a system cannot be upgraded, isolate it from the network using VLANs or firewall rules "
                "and apply compensating controls (EDR, application whitelisting)."
            ),
            "details": critical_workstations,
        })

    if critical_servers:
        findings.append({
            "title": "End-of-Life Server OS Detected",
            "severity": "critical",
            "deduction": 20,
            "description": (
                f"{len(critical_servers)} enabled computer account(s) are running "
                "end-of-life Windows Server operating systems (2003, 2008, or 2008 R2). "
                "These servers receive no security patches and are directly exploitable "
                "by a large number of publicly known vulnerabilities."
            ),
            "recommendation": (
                "Upgrade end-of-life servers to Windows Server 2019 or 2022 immediately. "
                "If migration is not immediately possible, apply Extended Security Updates (ESU) "
                "where available, isolate from production networks, and monitor closely."
            ),
            "details": critical_servers,
        })

    if high_servers:
        findings.append({
            "title": "Near-EOL Server OS Detected (Server 2012/2012 R2)",
            "severity": "high",
            "deduction": 15,
            "description": (
                f"{len(high_servers)} enabled computer account(s) are running "
                "Windows Server 2012 or 2012 R2, which reached end of life in October 2023. "
                "These systems no longer receive free security updates."
            ),
            "recommendation": (
                "Plan and execute migration to Windows Server 2019 or 2022. "
                "Microsoft offers Extended Security Updates (ESU) for Server 2012/R2 "
                "through Azure Arc or direct purchase as a short-term bridge."
            ),
            "details": high_servers,
        })

    if not critical_workstations and not critical_servers and not high_servers:
        if verbose:
            print("[DeprecatedOS] No deprecated operating systems detected.")

    return findings
