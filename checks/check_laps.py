"""
checks/check_laps.py - LAPS (Local Administrator Password Solution) Check

Checks:
  1. Legacy LAPS schema presence  (ms-Mcs-AdmPwd attribute in schema)
  2. Windows LAPS schema presence  (msLAPS-Password or msLAPS-EncryptedPassword)
  3. Computers without any LAPS password set (no ms-Mcs-AdmPwd AND no msLAPS-* value)
  4. LAPS coverage percentage      (% of non-DC enabled computers with a LAPS password)

Risk Deductions:
  Critical (-20): No LAPS schema found at all (LAPS not deployed)
  High    (-15): LAPS deployed but < 50% of non-DC computers covered
  Medium  (-8) : LAPS deployed but < 90% of non-DC computers covered
  Low     (-5) : Only legacy LAPS (ms-Mcs-AdmPwd) — not Windows LAPS
"""

CHECK_NAME = "LAPS Deployment"
CHECK_ORDER = 11
CHECK_CATEGORY = ["Privileged Accounts"]

_UAC_ACCOUNTDISABLE    = 0x2
_UAC_SERVER_TRUST      = 0x2000   # DC

_SCHEMA_ATTRS = ["lDAPDisplayName", "distinguishedName"]
_COMP_ATTRS   = [
    "sAMAccountName", "distinguishedName", "userAccountControl",
    "ms-Mcs-AdmPwd", "msLAPS-Password", "msLAPS-EncryptedPassword",
    "msLAPS-PasswordExpirationTime",
]


def _uac(entry, flag):
    try:
        return bool(int(entry.get("userAccountControl")) & flag)
    except Exception:
        return False


def _sam(entry):
    try:
        return str(entry.get("sAMAccountName"))
    except Exception:
        return "?"


def _has_value(entry, attr):
    try:
        v = entry.get(attr)
        return v is not None and str(v).strip() != ""
    except Exception:
        return False


def run_check(connector, verbose=False):
    findings = []
    log = connector.log
    config_dn = "CN=Configuration," + connector.base_dn
    schema_dn = "CN=Schema," + config_dn

    # -----------------------------------------------------------------------
    # 1. Schema detection
    # -----------------------------------------------------------------------
    legacy_laps_schema = connector.ldap_search(
        search_filter="(lDAPDisplayName=ms-Mcs-AdmPwd)",
        attributes=_SCHEMA_ATTRS,
        search_base=schema_dn,
    ) or []

    win_laps_schema = connector.ldap_search(
        search_filter="(|(lDAPDisplayName=msLAPS-Password)(lDAPDisplayName=msLAPS-EncryptedPassword))",
        attributes=_SCHEMA_ATTRS,
        search_base=schema_dn,
    ) or []

    has_legacy_laps = len(legacy_laps_schema) > 0
    has_win_laps    = len(win_laps_schema) > 0
    has_any_laps    = has_legacy_laps or has_win_laps

    log.debug(f"     Legacy LAPS schema (ms-Mcs-AdmPwd)   : {'YES' if has_legacy_laps else 'NO'}")
    log.debug(f"     Windows LAPS schema (msLAPS-*)        : {'YES' if has_win_laps else 'NO'}")

    # -----------------------------------------------------------------------
    # 2. Computer account enumeration
    # -----------------------------------------------------------------------
    # Request LAPS attributes — they won't exist if schema not deployed,
    # which is fine (no error, just missing)
    comp_entries = connector.ldap_search(
        search_filter="(objectClass=computer)",
        attributes=[
            "sAMAccountName", "distinguishedName", "userAccountControl",
            "ms-Mcs-AdmPwd", "msLAPS-Password", "msLAPS-EncryptedPassword",
        ],
    ) or []

    total_non_dc  = 0
    laps_covered  = 0
    no_laps       = []

    for entry in comp_entries:
        if _uac(entry, _UAC_ACCOUNTDISABLE):
            continue
        if _uac(entry, _UAC_SERVER_TRUST):
            continue  # Skip DCs
        total_non_dc += 1
        sam = _sam(entry)

        has_legacy_pwd = _has_value(entry, "ms-Mcs-AdmPwd")
        has_win_pwd    = _has_value(entry, "msLAPS-Password") or _has_value(entry, "msLAPS-EncryptedPassword")

        if has_legacy_pwd or has_win_pwd:
            laps_covered += 1
        else:
            no_laps.append(sam)

    coverage_pct = (laps_covered / total_non_dc * 100) if total_non_dc > 0 else 0

    log.debug(f"     Non-DC computer accounts             : {total_non_dc}")
    log.debug(f"     LAPS-covered computers               : {laps_covered}")
    log.debug(f"     Coverage                             : {coverage_pct:.1f}%")

    # -----------------------------------------------------------------------
    # Build findings
    # -----------------------------------------------------------------------
    if not has_any_laps:
        findings.append({
            "title": "LAPS Not Deployed — No LAPS Schema Found",
            "severity": "critical",
            "deduction": 20,
            "description": (
                "Neither Legacy LAPS (ms-Mcs-AdmPwd) nor Windows LAPS (msLAPS-*) "
                "schema extensions were found in Active Directory. "
                "Without LAPS, local Administrator accounts on domain-joined workstations "
                "and servers likely share the same password, enabling lateral movement "
                "across the entire fleet once a single machine is compromised "
                "(Pass-the-Hash with the local admin hash)."
            ),
            "recommendation": (
                "Deploy Windows LAPS (built into Windows 11 22H2 / Server 2025 and "
                "available as a KB update for earlier versions). "
                "For older systems, deploy Legacy LAPS (Microsoft LAPS 6.x). "
                "Configure LAPS via GPO to set a strong rotation interval (e.g., 30 days). "
                "Restrict read access to LAPS password attributes to privileged accounts only."
            ),
            "details": [
                "ms-Mcs-AdmPwd schema attribute: NOT FOUND",
                "msLAPS-Password schema attribute: NOT FOUND",
                f"Non-DC computers without LAPS: {total_non_dc}",
            ],
        })
        return findings

    # LAPS is deployed — check coverage
    if has_legacy_laps and not has_win_laps:
        findings.append({
            "title": "Only Legacy LAPS (ms-Mcs-AdmPwd) Deployed — Windows LAPS Not Found",
            "severity": "low",
            "deduction": 5,
            "description": (
                "The domain uses Legacy LAPS (Microsoft LAPS 6.x, ms-Mcs-AdmPwd attribute). "
                "Legacy LAPS stores the password in plaintext in Active Directory, "
                "readable by anyone with the delegated right to the attribute. "
                "Windows LAPS (available since April 2023) stores passwords encrypted "
                "and supports more granular access controls and Azure AD integration."
            ),
            "recommendation": (
                "Plan migration to Windows LAPS. "
                "Windows LAPS is available for Windows 11 22H2+, Server 2025, "
                "and via KB5025175 for earlier OS versions. "
                "Both can coexist during migration."
            ),
            "details": ["Legacy LAPS (ms-Mcs-AdmPwd): PRESENT", "Windows LAPS (msLAPS-*): NOT FOUND"],
        })

    if total_non_dc == 0:
        return findings

    if coverage_pct < 50:
        findings.append({
            "title": f"LAPS Coverage Critical: {coverage_pct:.0f}% of Computers Covered",
            "severity": "high",
            "deduction": 15,
            "description": (
                f"Only {laps_covered} of {total_non_dc} enabled non-DC computer accounts "
                f"({coverage_pct:.1f}%) have a LAPS-managed password. "
                "Computers without LAPS likely have identical or predictable local "
                "Administrator passwords, enabling lateral movement across the environment."
            ),
            "recommendation": (
                "Expand LAPS deployment to all non-DC computer accounts. "
                "Use GPO to target all workstation and server OUs. "
                "Verify LAPS agent installation and GPO linkage on all machines."
            ),
            "details": [
                f"Covered: {laps_covered}/{total_non_dc} ({coverage_pct:.1f}%)",
            ] + [f"No LAPS: {n}" for n in no_laps[:50]],
        })
    elif coverage_pct < 90:
        findings.append({
            "title": f"LAPS Coverage Incomplete: {coverage_pct:.0f}% of Computers Covered",
            "severity": "medium",
            "deduction": 8,
            "description": (
                f"{laps_covered} of {total_non_dc} enabled non-DC computer accounts "
                f"({coverage_pct:.1f}%) have a LAPS-managed password. "
                f"{len(no_laps)} computer(s) still lack LAPS coverage."
            ),
            "recommendation": (
                "Investigate uncovered machines — they may be stale, offline, or "
                "missing the LAPS agent. Aim for 100% coverage."
            ),
            "details": [
                f"Covered: {laps_covered}/{total_non_dc} ({coverage_pct:.1f}%)",
            ] + [f"No LAPS: {n}" for n in no_laps[:50]],
        })
    else:
        log.debug(f"     [OK] LAPS coverage: {coverage_pct:.1f}%")

    return findings
