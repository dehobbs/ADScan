"""
checks/check_gpo.py - Group Policy Object Security Check

Checks:
  1. Disabled GPOs          (gPCFunctionalityVersion = 0 or flags indicate disabled)
  2. Orphaned GPOs          (GPO in CN=Policies has no corresponding SOM link)
  3. Unlinked GPOs          (CN object exists but no gpLink references it)
  4. Empty GPOs             (no user or computer settings defined — both versions = 0)
  5. Excessive GPO count    (> 100 GPOs indicates management sprawl)

LDAP Bases:
  GPO containers: CN=Policies,CN=System,<domain_dn>
  GPO links: via gpLink attribute on OU/domain/site objects

Risk Deductions:
  Medium (-8) : Orphaned or unlinked GPOs (management debt, potential security gap)
  Medium (-8) : Disabled GPOs still in AD (clutter, may indicate outdated configs)
  Low    (-5) : Empty GPOs (processing overhead, policy sprawl)
  Low    (-5) : Excessive GPO count (> 100)
"""

CHECK_NAME = "Group Policy Objects"
CHECK_ORDER = 10

_GPO_ATTRS = [
    "cn", "displayName", "distinguishedName",
    "gPCFunctionalityVersion", "gPCUserExtensionNames",
    "gPCMachineExtensionNames", "flags", "whenCreated", "whenChanged",
]
_CONTAINER_ATTRS = ["gpLink", "distinguishedName", "cn"]


def _get_str(entry, attr, default=""):
    try:
        v = entry[attr].value
        return str(v) if v else default
    except Exception:
        return default


def _get_int(entry, attr, default=0):
    try:
        return int(entry[attr].value)
    except Exception:
        return default


def run_check(connector, verbose=False):
    findings = []

    gpo_base = f"CN=Policies,CN=System,{connector.base_dn}"

    gpo_entries = connector.ldap_search(
        search_filter="(objectClass=groupPolicyContainer)",
        attributes=_GPO_ATTRS,
        search_base=gpo_base,
    ) or []

    if not gpo_entries:
        if verbose:
            print("  [INFO] No GPOs found or LDAP query failed.")
        return findings

    total_gpos = len(gpo_entries)
    if verbose:
        print(f"     Total GPOs found: {total_gpos}")

    # Collect all GPO GUIDs from gpLink attributes across the domain
    # Search for all objects with gpLink (OUs, domain root, sites)
    linked_guids = set()

    linked_containers = connector.ldap_search(
        search_filter="(gpLink=*)",
        attributes=_CONTAINER_ATTRS,
    ) or []

    for container in linked_containers:
        gp_link = _get_str(container, "gpLink")
        # gpLink format: [LDAP://cn={GUID},cn=policies,...;flags][...]
        import re
        guids = re.findall(r'\{([A-Fa-f0-9-]+)\}', gp_link)
        linked_guids.update(g.upper() for g in guids)

    disabled_gpos  = []
    empty_gpos     = []
    unlinked_gpos  = []

    for gpo in gpo_entries:
        name    = _get_str(gpo, "displayName") or _get_str(gpo, "cn") or "?"
        flags   = _get_int(gpo, "flags")
        version = _get_int(gpo, "gPCFunctionalityVersion")
        cn_val  = _get_str(gpo, "cn").upper().strip("{}").upper()

        # Disabled: flags bit 0 (user) + bit 1 (computer) both set = 3 = all disabled
        # flags=1: user disabled, flags=2: computer disabled, flags=3: all disabled
        if flags == 3:
            disabled_gpos.append(f"{name} [{cn_val}] (all settings disabled)")
        elif flags == 1:
            disabled_gpos.append(f"{name} [{cn_val}] (user settings disabled)")
        elif flags == 2:
            disabled_gpos.append(f"{name} [{cn_val}] (computer settings disabled)")

        # Empty: no machine or user extension names AND version is 0
        machine_ext = _get_str(gpo, "gPCMachineExtensionNames")
        user_ext    = _get_str(gpo, "gPCUserExtensionNames")
        if not machine_ext and not user_ext and version == 0:
            empty_gpos.append(f"{name} [{cn_val}]")

        # Unlinked: GUID not in any gpLink
        if cn_val and cn_val not in linked_guids:
            unlinked_gpos.append(f"{name} [{cn_val}]")

    if verbose:
        print(f"     Disabled GPOs : {len(disabled_gpos)}")
        print(f"     Empty GPOs    : {len(empty_gpos)}")
        print(f"     Unlinked GPOs : {len(unlinked_gpos)}")

    if disabled_gpos:
        findings.append({
            "title": f"Disabled Group Policy Objects ({len(disabled_gpos)} found)",
            "severity": "medium",
            "deduction": 8,
            "description": (
                f"{len(disabled_gpos)} GPO(s) have all or some settings disabled. "
                "Fully disabled GPOs still consume SYSVOL space and are processed "
                "by client-side extensions. They often represent outdated or abandoned "
                "policy configurations that were never cleaned up."
            ),
            "recommendation": (
                "Review all disabled GPOs. If the policy is no longer needed, "
                "delete it from both AD and SYSVOL. "
                "Use the Group Policy Management Console (GPMC) > "
                "Group Policy Objects > right-click > Delete."
            ),
            "details": disabled_gpos[:50],
        })

    if unlinked_gpos:
        # Exclude empty GPOs from unlinked count (already caught)
        non_empty_unlinked = [g for g in unlinked_gpos if g not in empty_gpos]
        if non_empty_unlinked:
            findings.append({
                "title": f"Unlinked Group Policy Objects ({len(non_empty_unlinked)} found)",
                "severity": "medium",
                "deduction": 8,
                "description": (
                    f"{len(non_empty_unlinked)} GPO(s) exist in AD but are not linked to "
                    "any OU, domain, or site. Unlinked GPOs are never applied but may "
                    "contain sensitive configuration details visible to authenticated users. "
                    "They also indicate GPO management sprawl."
                ),
                "recommendation": (
                    "Audit all unlinked GPOs. Either link them to the appropriate OU "
                    "or delete them if they are no longer required."
                ),
                "details": non_empty_unlinked[:50],
            })

    if empty_gpos:
        findings.append({
            "title": f"Empty Group Policy Objects ({len(empty_gpos)} found)",
            "severity": "low",
            "deduction": 5,
            "description": (
                f"{len(empty_gpos)} GPO(s) contain no user or computer configuration "
                "settings. Empty GPOs are applied to clients if linked, causing "
                "unnecessary processing overhead at logon/startup with no benefit."
            ),
            "recommendation": (
                "Delete empty GPOs that serve no purpose. "
                "If they are placeholders, document their intended use and configure them."
            ),
            "details": empty_gpos[:50],
        })

    if total_gpos > 100:
        findings.append({
            "title": f"Excessive GPO Count ({total_gpos} GPOs)",
            "severity": "low",
            "deduction": 5,
            "description": (
                f"The domain contains {total_gpos} Group Policy Objects. "
                "A large number of GPOs increases logon time (each linked GPO must be "
                "evaluated), complicates troubleshooting, and increases the risk of "
                "conflicting or redundant settings going unnoticed."
            ),
            "recommendation": (
                "Consolidate GPOs where possible. Use GPMC Modeling to identify "
                "redundant settings. Target < 50 GPOs for well-managed environments. "
                "Consider using AGPM (Advanced Group Policy Management) for lifecycle control."
            ),
            "details": [f"Total GPO count: {total_gpos}", "Recommended: < 100 (ideally < 50)"],
        })

    return findings
