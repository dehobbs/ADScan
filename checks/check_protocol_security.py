"""
checks/check_protocol_security.py - Protocol Security Check

Checks:
  1. Domain and Forest Functional Level
  2. DC Operating System versions
  3. LDAP signing and channel binding guidance
  4. NTLMv1 and WDigest guidance

Risk Deductions:
  Critical (-20): Domain functional level below Windows Server 2012 R2
  High    (-15): DC running legacy OS (pre-2016)
  High    (-15): Forest functional level below Windows Server 2012 R2
  Medium   (-8): LDAP signing / channel binding verification required
  Medium   (-8): NTLMv1 / WDigest verification required
  Low      (-5): Domain functional level below Windows Server 2016
"""

CHECK_NAME = "Protocol Security"
CHECK_ORDER = 9
CHECK_CATEGORY = ["Protocol Security"]

_FUNC_LEVELS = {
    0: "Windows 2000",
    1: "Windows Server 2003 Interim",
    2: "Windows Server 2003",
    3: "Windows Server 2008",
    4: "Windows Server 2008 R2",
    5: "Windows Server 2012",
    6: "Windows Server 2012 R2",
    7: "Windows Server 2016/2019/2022",
}

_LEGACY_OS_KEYWORDS = [
    "windows server 2003",
    "windows server 2008",
    "windows 2000",
    "windows nt",
    "windows xp",
    "windows 7",
    "windows vista",
    "windows server 2012",
]


def _get_str(entry, attr, default=""):
    try:
        v = entry[attr].value
        return str(v) if v else default
    except Exception:
        return default


def _is_legacy_os(os_str):
    os_l = os_str.lower()
    return any(kw in os_l for kw in _LEGACY_OS_KEYWORDS)


def run_check(connector, verbose=False):
    findings = []

    # Domain functional level
    domain_entries = connector.ldap_search(
        search_filter="(objectClass=domainDNS)",
        attributes=["msDS-Behavior-Version"],
    ) or []

    domain_level = None
    if domain_entries:
        try:
            domain_level = int(domain_entries[0]["msDS-Behavior-Version"].value)
        except Exception:
            pass

    # Forest functional level (via crossRefContainer in config)
    config_dn = "CN=Configuration," + connector.base_dn
    forest_entries = connector.ldap_search(
        search_filter="(objectClass=crossRefContainer)",
        attributes=["msDS-Behavior-Version"],
        search_base=config_dn,
    ) or []

    forest_level = None
    if forest_entries:
        try:
            forest_level = int(forest_entries[0]["msDS-Behavior-Version"].value)
        except Exception:
            pass

    if verbose:
        print(f"  DFL: {domain_level} ({_FUNC_LEVELS.get(domain_level, '?')})")
        print(f"  FFL: {forest_level} ({_FUNC_LEVELS.get(forest_level, '?')})")

    if domain_level is not None:
        name = _FUNC_LEVELS.get(domain_level, f"Level {domain_level}")
        if domain_level < 6:
            findings.append({
                "title": f"Domain Functional Level Too Low: {name}",
                "severity": "critical",
                "deduction": 20,
                "description": (
                    f"Domain functional level is {name} (level {domain_level}). "
                    "Levels below 6 (2012 R2) lack Protected Users group enforcement, "
                    "fine-grained Kerberos controls, and Authentication Policies."
                ),
                "recommendation": (
                    "Raise the DFL to Windows Server 2016 (level 7). "
                    "Prerequisite: all DCs must run WS2016+. "
                    "Set-ADDomainMode -Identity <domain> -DomainMode Windows2016Domain"
                ),
                "details": [f"Current: {name} (level {domain_level})", "Recommended: level 7 (WS2016)"],
            })
        elif domain_level < 7:
            findings.append({
                "title": f"Domain Functional Level Below Recommended: {name}",
                "severity": "low",
                "deduction": 5,
                "description": (
                    f"DFL is {name} (level {domain_level}). "
                    "Raising to level 7 (WS2016) enables Authentication Policy Silos "
                    "and Kerberos armoring for privileged accounts."
                ),
                "recommendation": (
                    "Plan upgrade to DFL level 7. "
                    "Set-ADDomainMode -Identity <domain> -DomainMode Windows2016Domain"
                ),
                "details": [f"Current: {name} (level {domain_level})", "Recommended: level 7 (WS2016)"],
            })

    if forest_level is not None and forest_level < 6:
        name = _FUNC_LEVELS.get(forest_level, f"Level {forest_level}")
        findings.append({
            "title": f"Forest Functional Level Too Low: {name}",
            "severity": "high",
            "deduction": 15,
            "description": (
                f"Forest functional level is {name} (level {forest_level}). "
                "Low FFL disables AD Recycle Bin (requires 4+), PAM feature (requires 7), "
                "and forest-wide security enhancements."
            ),
            "recommendation": (
                "Raise the FFL after all domains are at the target DFL. "
                "Set-ADForestMode -Identity <forest> -ForestMode Windows2016Forest"
            ),
            "details": [f"Current: {name} (level {forest_level})", "Recommended: level 7"],
        })

    # DC OS check
    dc_entries = connector.ldap_search(
        search_filter="(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
        attributes=["sAMAccountName", "operatingSystem"],
    ) or []

    legacy_dcs = []
    for e in dc_entries:
        os_str = _get_str(e, "operatingSystem")
        sam    = _get_str(e, "sAMAccountName")
        if os_str and _is_legacy_os(os_str):
            legacy_dcs.append(f"{sam}: {os_str}")
        if verbose:
            print(f"  DC: {sam} | OS: {os_str or 'unknown'}")

    if legacy_dcs:
        findings.append({
            "title": "Domain Controllers Running Legacy OS",
            "severity": "high",
            "deduction": 15,
            "description": (
                f"{len(legacy_dcs)} DC(s) are running OS versions older than WS2016. "
                "Legacy DCs lack Credential Guard, VBS, and enhanced Kerberos enforcement."
            ),
            "recommendation": (
                "Upgrade all DCs to Windows Server 2022 or 2019. "
                "Decommission legacy DCs following a tested upgrade plan."
            ),
            "details": legacy_dcs,
        })

    # LDAP signing guidance
    findings.append({
        "title": "Verify LDAP Signing and Channel Binding Enforcement",
        "severity": "medium",
        "deduction": 8,
        "description": (
            "LDAP signing and channel binding cannot be verified passively. "
            "Without enforced LDAP signing, NTLM relay to LDAP (via tools like ntlmrelayx) "
            "allows attackers to modify AD objects or perform DCSync. "
            "Without channel binding, LDAPS sessions may be relayed."
        ),
        "recommendation": (
            "GPO: Computer Config > Windows Settings > Security Settings > "
            "Local Policies > Security Options > "
            "Domain controller: LDAP server signing requirements = Require signing. "
            "Registry: HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters\\"
            "LdapEnforceChannelBinding = 2. "
            "See KB4520412 / ADV190023."
        ),
        "details": [
            "LDAPServerIntegrity: HKLM\\SYSTEM\\CurrentControlSet\\Services\\"
            "NTDS\\Parameters\\LDAPServerIntegrity",
            "LdapEnforceChannelBinding: HKLM\\SYSTEM\\CurrentControlSet\\Services\\"
            "NTDS\\Parameters\\LdapEnforceChannelBinding",
        ],
    })

    # NTLMv1/WDigest guidance
    findings.append({
        "title": "Verify NTLMv1 and WDigest Are Disabled",
        "severity": "medium",
        "deduction": 8,
        "description": (
            "NTLMv1 and WDigest configuration require registry / GPO verification on each host. "
            "NTLMv1 hashes are crackable in seconds. "
            "WDigest (if enabled) stores plaintext credentials in LSASS, recoverable via Mimikatz."
        ),
        "recommendation": (
            "Disable NTLMv1: GPO LmCompatibilityLevel = 5. "
            "Disable WDigest: HKLM\\SYSTEM\\CurrentControlSet\\Control\\"
            "SecurityProviders\\WDigest\\UseLogonCredential = 0. "
            "Add all privileged accounts to Protected Users group (prevents NTLM auth)."
        ),
        "details": [
            "LmCompatibilityLevel: HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa (set to 5)",
            "UseLogonCredential: HKLM\\SYSTEM\\CurrentControlSet\\Control\\"
            "SecurityProviders\\WDigest (set to 0)",
        ],
    })

    return findings
