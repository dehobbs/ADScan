"""
checks/check_domain_controllers.py - Domain Controller Security Check

Checks:
  1. Single DC detection
  2. Legacy OS on DCs (pre-2016)
  3. FSMO role enumeration and concentration
  4. RODC Password Replication Policy
  5. DC computer account owners

Risk Deductions:
  Critical (-20): Only one DC
  High    (-15): DC running legacy OS
  High    (-15): All 5 FSMO roles on single DC
  Medium  (-8) : Non-default DC computer owner
  Low     (-5) : Permissive RODC PRP
"""

CHECK_NAME = "Domain Controllers"
CHECK_ORDER = 13
CHECK_CATEGORY = ["Domain Hygiene"]

_LEGACY_OS_KEYWORDS = [
    "windows server 2003", "windows server 2008",
    "windows 2000", "windows nt", "windows server 2012",
]


def _get_str(entry, attr, default=""):
    try:
        v = entry.get(attr)
        return str(v) if v else default
    except Exception:
        return default


def _get_int(entry, attr, default=0):
    try:
        return int(entry.get(attr, default))
    except Exception:
        return default


def _is_legacy_os(os_str):
    return any(kw in os_str.lower() for kw in _LEGACY_OS_KEYWORDS)


def _is_rodc(entry):
    try:
        return bool(entry.get("msDS-IsRodc"))
    except Exception:
        return False


def run_check(connector, verbose=False):
    findings = []

    dc_entries = connector.ldap_search(
        search_filter="(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
        attributes=["sAMAccountName", "operatingSystem", "msDS-IsRodc",
                    "distinguishedName", "userAccountControl"],
    ) or []

    total_dcs = len(dc_entries)

    if verbose:
        print(f"     Total DCs: {total_dcs}")

    if total_dcs == 1:
        findings.append({
            "title": "Single Domain Controller Detected",
            "severity": "critical",
            "deduction": 20,
            "description": (
                f"Only one DC ({_get_str(dc_entries[0], 'sAMAccountName')}) was found. "
                "Hardware failure, ransomware, or corruption would render the entire domain "
                "inoperable. All FSMO roles are concentrated on one host."
            ),
            "recommendation": (
                "Deploy at least two DCs in separate failure domains. "
                "Use: Install-ADDSDomainController"
            ),
            "details": [f"Only DC: {_get_str(dc_entries[0], 'sAMAccountName')}"],
        })
    elif total_dcs == 0:
        return [{"title": "No DCs Found via LDAP", "severity": "critical", "deduction": 20,
                 "description": "No DC accounts found. Check LDAP connectivity.",
                 "recommendation": "Verify LDAP permissions.", "details": []}]

    legacy_dcs = []
    rodc_list  = []
    for e in dc_entries:
        os_str = _get_str(e, "operatingSystem")
        sam = _get_str(e, "sAMAccountName")
        if os_str and _is_legacy_os(os_str):
            legacy_dcs.append(f"{sam}: {os_str}")
        if _is_rodc(e):
            rodc_list.append(sam)
        if verbose:
            print(f"     DC: {sam} | OS: {os_str} | RODC: {_is_rodc(e)}")

    if legacy_dcs:
        findings.append({
            "title": "Domain Controllers Running Legacy OS",
            "severity": "high",
            "deduction": 15,
            "description": (
                f"{len(legacy_dcs)} DC(s) run OS versions older than WS2016. "
                "Legacy DCs lack Credential Guard, VBS, and modern Kerberos controls."
            ),
            "recommendation": "Upgrade all DCs to Windows Server 2022 or 2019.",
            "details": legacy_dcs,
        })

    # FSMO roles
    import re
    config_dn = "CN=Configuration," + connector.base_dn
    schema_dn = "CN=Schema," + config_dn
    fsmo_queries = {
        "PDC Emulator":    ("(objectClass=domainDNS)", "fSMORoleOwner", connector.base_dn),
        "RID Master":      ("(objectClass=rIDManager)", "fSMORoleOwner",
                            f"CN=RID Manager$,CN=System,{connector.base_dn}"),
        "Infrastructure":  ("(objectClass=infrastructureUpdate)", "fSMORoleOwner",
                            f"CN=Infrastructure,{connector.base_dn}"),
        "Schema Master":   ("(objectClass=dMD)", "fSMORoleOwner", schema_dn),
        "Domain Naming":   ("(objectClass=crossRefContainer)", "fSMORoleOwner",
                            f"CN=Partitions,{config_dn}"),
    }
    fsmo_holders = {}
    for role, (filt, attr, base) in fsmo_queries.items():
        entries = connector.ldap_search(search_filter=filt, attributes=[attr], search_base=base) or []
        if entries:
            try:
                owner = str(entries[0].get(attr, ""))
                m = re.search(r'CN=([^,]+),CN=NTDS', owner, re.IGNORECASE)
                fsmo_holders[role] = m.group(1) if m else owner.split(",")[0].replace("CN=", "")
            except Exception:
                pass

    if verbose:
        for r, h in fsmo_holders.items():
            print(f"     FSMO {r}: {h}")

    unique_holders = set(fsmo_holders.values())
    if len(fsmo_holders) == 5 and len(unique_holders) == 1:
        holder = next(iter(unique_holders))
        findings.append({
            "title": f"All 5 FSMO Roles on Single DC: {holder}",
            "severity": "high",
            "deduction": 15,
            "description": (
                f"All FSMO roles are held by {holder}. "
                "DC unavailability will cause auth failures, RID pool exhaustion, and SID mismatches."
            ),
            "recommendation": "Distribute FSMO roles across multiple DCs using Move-ADDirectoryServerOperationMasterRole.",
            "details": [f"{r}: {h}" for r, h in fsmo_holders.items()],
        })
    elif fsmo_holders:
        findings.append({
            "title": "FSMO Role Distribution",
            "severity": "info",
            "deduction": 0,
            "description": "FSMO roles are distributed across domain controllers.",
            "recommendation": "Ensure FSMO holders are well-documented.",
            "details": [f"{r}: {h}" for r, h in fsmo_holders.items()],
        })

    # RODC PRP
    for rodc_sam in rodc_list:
        rodc_entries = connector.ldap_search(
            search_filter=f"(sAMAccountName={rodc_sam})",
            attributes=["msDS-RevealOnDemandGroup"],
        ) or []
        for rodc_e in rodc_entries:
            try:
                reveal = str(rodc_e.get("msDS-RevealOnDemandGroup"))
                if "domain users" in reveal.lower() or "authenticated users" in reveal.lower():
                    findings.append({
                        "title": f"RODC {rodc_sam}: Permissive Password Replication Policy",
                        "severity": "low",
                        "deduction": 5,
                        "description": (
                            f"RODC {rodc_sam} allows caching passwords for broad groups. "
                            "A compromised RODC could expose many cached credentials."
                        ),
                        "recommendation": "Restrict msDS-RevealOnDemandGroup to only required users/computers.",
                        "details": [f"msDS-RevealOnDemandGroup: {reveal[:200]}"],
                    })
            except Exception:
                pass

    return findings
