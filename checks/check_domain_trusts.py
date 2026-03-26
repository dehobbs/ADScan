"""
checks/check_domain_trusts.py - Domain Trust Enumeration and Analysis

Enumerates all trustedDomain objects in Active Directory and flags
dangerous trust configurations.

Checks performed:
  1. Bidirectional trusts without SID filtering (SID filter disabled = sidFilteringEnabled=False)
     → Allows SID history injection across trust boundaries
  2. Forest trusts (trustType=2, trustAttributes includes TRUST_ATTRIBUTE_FOREST_TRANSITIVE)
     → Transitive, broad attack surface if SID filtering is relaxed
  3. External trusts (non-forest, cross-domain trusts with external domains)
     → Attack surface depending on trust direction
  4. Trusts with TGT delegation enabled
     → Allows Kerberos TGT forwarding across the trust
  5. MIT (non-Windows) Kerberos realm trusts
  6. Summary of all inbound/outbound/bidirectional trust directions

Trust Attribute Flags (trustAttributes):
  0x00000001  TRUST_ATTRIBUTE_NON_TRANSITIVE
  0x00000002  TRUST_ATTRIBUTE_UPLEVEL_ONLY
  0x00000004  TRUST_ATTRIBUTE_FILTER_SIDS          (SID filtering ENABLED = safer)
  0x00000008  TRUST_ATTRIBUTE_FOREST_TRANSITIVE     (Forest trust)
  0x00000010  TRUST_ATTRIBUTE_CROSS_ORGANIZATION    (Cross-org, SID filtering always on)
  0x00000020  TRUST_ATTRIBUTE_WITHIN_FOREST         (Same forest parent-child)
  0x00000040  TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL     (Treat as external)
  0x00000080  TRUST_ATTRIBUTE_USES_RC4_ENCRYPTION
  0x00000200  TRUST_ATTRIBUTE_CROSS_ORGANIZATION_NO_TGT_DELEGATION
  0x00000800  TRUST_ATTRIBUTE_PAM_TRUST
  0x00000400  TRUST_ATTRIBUTE_ENABLE_TGT_DELEGATION (TGT delegation across trust)

Trust Direction (trustDirection):
  0 = Disabled
  1 = Inbound (this domain trusts the other)
  2 = Outbound (the other domain trusts this one)
  3 = Bidirectional

Trust Type (trustType):
  1 = Downlevel (Windows NT 4.0)
  2 = Uplevel (Active Directory)
  3 = MIT (non-Windows Kerberos realm)
  4 = DCE

Risk Deductions:
  Critical (-20): Bidirectional trust without SID filtering (SID history injection possible)
  High    (-15): Forest trust with SID filtering disabled
  High    (-15): TGT delegation enabled across trust
  Medium  (-8) : External trust (bidirectional)
  Medium  (-8) : Forest trust (any) - informational with guidance
  Low     (-5) : MIT (non-Windows) Kerberos realm trust
"""

CHECK_NAME = "Domain Trusts"
CHECK_ORDER = 7
CHECK_CATEGORY = ["Domain Hygiene"]
CHECK_WEIGHT   = 20   # max deduction at stake for this check module

# trustAttributes bit flags
_TA_NON_TRANSITIVE          = 0x00000001
_TA_UPLEVEL_ONLY            = 0x00000002
_TA_FILTER_SIDS             = 0x00000004   # SID filtering ON (safe)
_TA_FOREST_TRANSITIVE       = 0x00000008   # Forest trust
_TA_CROSS_ORGANIZATION      = 0x00000010   # Always SID-filtered
_TA_WITHIN_FOREST           = 0x00000020   # Same forest
_TA_TREAT_AS_EXTERNAL       = 0x00000040
_TA_USES_RC4                = 0x00000080
_TA_CROSS_ORG_NO_TGT_DELEG  = 0x00000200
_TA_ENABLE_TGT_DELEGATION   = 0x00000400
_TA_PAM_TRUST               = 0x00000800

# trustDirection values
_TD_DISABLED      = 0
_TD_INBOUND       = 1
_TD_OUTBOUND      = 2
_TD_BIDIRECTIONAL = 3

# trustType values
_TT_DOWNLEVEL     = 1
_TT_UPLEVEL       = 2
_TT_MIT           = 3
_TT_DCE           = 4

_TRUST_ATTRS = [
    "cn",
    "distinguishedName",
    "trustPartner",
    "trustDirection",
    "trustType",
    "trustAttributes",
    "flatName",
    "securityIdentifier",
    "whenCreated",
    "whenChanged",
]

_DIR_LABELS = {
    0: "Disabled",
    1: "Inbound  (this domain trusts partner)",
    2: "Outbound (partner trusts this domain)",
    3: "Bidirectional",
}


def _get_str(entry, attr, default=""):
    try:
        v = entry.get(attr)
        return str(v) if v is not None else default
    except Exception:
        return default


def _get_int(entry, attr, default=0):
    try:
        v = entry.get(attr); return int(v) if v is not None else 0
    except Exception:
        return default


def _ta_flag(ta, flag):
    return bool(ta & flag)


def _trust_label(entry):
    partner = _get_str(entry, "trustPartner", "?")
    flat    = _get_str(entry, "flatName")
    direction = _get_int(entry, "trustDirection")
    dir_label = _DIR_LABELS.get(direction, f"Unknown({direction})")
    return f"{partner}" + (f" ({flat})" if flat else "") + f" | Dir: {dir_label}"


def run_check(connector, verbose=False):
    findings = []
    log = connector.log

    trust_entries = connector.ldap_search(
        search_filter="(objectClass=trustedDomain)",
        attributes=_TRUST_ATTRS,
    )

    if not trust_entries:
        log.debug("  [INFO] No domain trusts found (or LDAP query returned no results).")
        return findings

    log.debug("     Total trust relationships found: %d", len(trust_entries))

    bidir_no_filter     = []   # Bidirectional, SID filtering disabled -> critical
    forest_trusts       = []   # Forest trusts (any direction)
    forest_no_filter    = []   # Forest trusts without SID filtering
    external_bidir      = []   # External bidirectional trusts
    tgt_delegation      = []   # TGT delegation enabled
    mit_trusts          = []   # Non-Windows MIT trusts
    rc4_trusts          = []   # Trusts using RC4 (weak encryption)
    all_trusts_summary  = []   # All trusts for informational detail

    for entry in trust_entries:
        partner    = _get_str(entry, "trustPartner", "?")
        ta         = _get_int(entry, "trustAttributes")
        direction  = _get_int(entry, "trustDirection")
        trust_type = _get_int(entry, "trustType")
        label      = _trust_label(entry)

        is_bidirectional    = (direction == _TD_BIDIRECTIONAL)
        is_inbound          = (direction in (_TD_INBOUND, _TD_BIDIRECTIONAL))
        is_forest           = _ta_flag(ta, _TA_FOREST_TRANSITIVE)
        is_within_forest    = _ta_flag(ta, _TA_WITHIN_FOREST)
        is_cross_org        = _ta_flag(ta, _TA_CROSS_ORGANIZATION)
        sid_filtered        = _ta_flag(ta, _TA_FILTER_SIDS) or is_cross_org
        tgt_deleg           = _ta_flag(ta, _TA_ENABLE_TGT_DELEGATION)
        no_tgt_deleg        = _ta_flag(ta, _TA_CROSS_ORG_NO_TGT_DELEG)
        uses_rc4            = _ta_flag(ta, _TA_USES_RC4)
        treat_as_external   = _ta_flag(ta, _TA_TREAT_AS_EXTERNAL)
        is_external         = (not is_forest and not is_within_forest and
                               trust_type in (_TT_UPLEVEL, _TT_DOWNLEVEL))
        is_mit              = (trust_type == _TT_MIT)

        # Build attribute string for verbose/summary
        attrs = []
        if is_forest:           attrs.append("Forest")
        if is_within_forest:    attrs.append("Within-Forest")
        if is_cross_org:        attrs.append("Cross-Org")
        if sid_filtered:        attrs.append("SID-Filtered(ON)")
        else:                   attrs.append("SID-Filtered(OFF)")
        if tgt_deleg:           attrs.append("TGT-Delegation(ON)")
        if uses_rc4:            attrs.append("RC4-Encryption")
        if treat_as_external:   attrs.append("Treat-As-External")

        summary = f"{label} | Attrs: [{', '.join(attrs)}]"
        all_trusts_summary.append(summary)

        log.debug("     %s", summary)

        # Skip within-forest parent-child trusts (normal, expected)
        if is_within_forest:
            continue

        # ------------------------------------------------------------------
        # Critical: Bidirectional without SID filtering
        # ------------------------------------------------------------------
        if is_bidirectional and not sid_filtered and not is_within_forest:
            bidir_no_filter.append(summary)

        # ------------------------------------------------------------------
        # Forest trusts
        # ------------------------------------------------------------------
        if is_forest:
            forest_trusts.append(summary)
            if not sid_filtered:
                forest_no_filter.append(summary)

        # ------------------------------------------------------------------
        # External bidirectional
        # ------------------------------------------------------------------
        if is_external and is_bidirectional:
            external_bidir.append(summary)

        # ------------------------------------------------------------------
        # TGT delegation across trust
        # ------------------------------------------------------------------
        if tgt_deleg and not no_tgt_deleg:
            tgt_delegation.append(summary)

        # ------------------------------------------------------------------
        # MIT (non-Windows) Kerberos realm trusts
        # ------------------------------------------------------------------
        if is_mit:
            mit_trusts.append(summary)

        # ------------------------------------------------------------------
        # RC4 encryption on trusts
        # ------------------------------------------------------------------
        if uses_rc4:
            rc4_trusts.append(summary)

    # -----------------------------------------------------------------------
    # Build findings
    # -----------------------------------------------------------------------

    # Bidirectional without SID filtering (most critical)
    if bidir_no_filter:
        findings.append({
            "title": "Bidirectional Trust(s) Without SID Filtering Enabled",
            "severity": "critical",
            "deduction": 20,
            "description": (
                f"{len(bidir_no_filter)} bidirectional trust(s) do not have SID filtering "
                "(Quarantine) enabled. Without SID filtering, a compromised trusted domain "
                "can inject arbitrary SID history values (including Domain Admins SIDs of "
                "the trusting domain) into Kerberos tickets, enabling complete privilege "
                "escalation across the trust boundary with no additional exploitation needed."
            ),
            "recommendation": (
                "Enable SID filtering (Quarantine) on all cross-domain trusts: \n"
                "  netdom trust <TrustingDomain> /domain:<TrustedDomain> /quarantine:yes\n"
                "For forest trusts: enable SID filtering via Active Directory Domains and Trusts. "
                "Note: Enabling SID filtering may break applications that rely on SID history "
                "for resource access — test thoroughly before enforcing."
            ),
            "details": bidir_no_filter,
        })

    # Forest trusts without SID filtering
    if forest_no_filter:
        findings.append({
            "title": "Forest Trust(s) Without SID Filtering",
            "severity": "high",
            "deduction": 15,
            "description": (
                f"{len(forest_no_filter)} forest trust(s) exist without SID filtering enabled. "
                "Forest trusts with SID filtering disabled allow SID history injection across "
                "entire forests. A compromise of any domain within the trusted forest can "
                "lead to compromise of this forest via SID history abuse."
            ),
            "recommendation": (
                "Enable SID filtering on all forest trusts. "
                "Review whether full forest transitivity is necessary — "
                "consider selective authentication to restrict which principals "
                "can authenticate across the forest trust."
            ),
            "details": forest_no_filter,
        })

    # Forest trusts (all — informational with guidance)
    forest_info_only = [f for f in forest_trusts if f not in forest_no_filter]
    if forest_info_only:
        findings.append({
            "title": "Forest Trust(s) Configured (Review Required)",
            "severity": "medium",
            "deduction": 8,
            "description": (
                f"{len(forest_info_only)} forest trust(s) are configured with SID filtering enabled. "
                "Forest trusts dramatically expand the attack surface of this domain. "
                "A compromise of any domain in a trusted forest, or abuse of "
                "Universal Group membership or ACLs that cross forest boundaries, "
                "can enable privilege escalation into this domain."
            ),
            "recommendation": (
                "Ensure Selective Authentication is enabled on forest trusts to restrict "
                "which users from the trusted forest can authenticate to resources. "
                "Audit cross-forest ACLs and group memberships regularly. "
                "Review whether all forest trusts are genuinely required."
            ),
            "details": forest_info_only,
        })

    # TGT delegation
    if tgt_delegation:
        findings.append({
            "title": "TGT Delegation Enabled Across Trust Boundary",
            "severity": "high",
            "deduction": 15,
            "description": (
                f"{len(tgt_delegation)} trust(s) have TGT delegation enabled "
                "(TRUST_ATTRIBUTE_ENABLE_TGT_DELEGATION). This allows full Kerberos TGTs "
                "to be forwarded across the trust. If any service in the trusted domain "
                "has unconstrained delegation configured, an attacker who compromises it "
                "can harvest cross-domain TGTs including Domain Admin tickets."
            ),
            "recommendation": (
                "Disable TGT delegation across trust boundaries unless explicitly required. "
                "If required, ensure no services in the trusted domain have "
                "unconstrained delegation configured. "
                "Remove TRUST_ATTRIBUTE_ENABLE_TGT_DELEGATION via: "
                "Set-ADObject -Identity <trustDN> -Replace @{trustAttributes=<new_value>}"
            ),
            "details": tgt_delegation,
        })

    # External bidirectional trusts
    if external_bidir:
        findings.append({
            "title": "External Bidirectional Trusts with Non-Forest Domains",
            "severity": "medium",
            "deduction": 8,
            "description": (
                f"{len(external_bidir)} bidirectional external trust(s) exist to domains "
                "outside this forest. External trusts that are bidirectional allow users "
                "from both domains to access resources in the other, expanding the attack "
                "surface. A compromise of the external domain can enable attacks against "
                "this domain depending on resource ACLs and group memberships."
            ),
            "recommendation": (
                "Review whether bidirectional external trusts are required or whether "
                "one-way (outbound only) trusts would suffice. "
                "Ensure SID filtering is enabled. "
                "Audit cross-trust group memberships and resource ACLs."
            ),
            "details": external_bidir,
        })

    # MIT trusts
    if mit_trusts:
        findings.append({
            "title": "Non-Windows MIT Kerberos Realm Trust(s) Found",
            "severity": "low",
            "deduction": 5,
            "description": (
                f"{len(mit_trusts)} MIT (non-Windows) Kerberos realm trust(s) are configured. "
                "These trusts connect Active Directory to non-Windows Kerberos realms "
                "(e.g., Linux/Unix/macOS environments). Misconfiguration of these trusts "
                "can enable cross-realm attacks and weakened encryption requirements."
            ),
            "recommendation": (
                "Verify that all MIT realm trusts are intentional and document their purpose. "
                "Ensure AES encryption types are enforced (not RC4/DES). "
                "Apply the principle of least privilege to cross-realm access."
            ),
            "details": mit_trusts,
        })

    # RC4 on trusts
    if rc4_trusts:
        findings.append({
            "title": "Domain Trust(s) Using RC4 Encryption",
            "severity": "low",
            "deduction": 5,
            "description": (
                f"{len(rc4_trusts)} trust(s) are configured to use RC4 encryption. "
                "RC4 (ARCFOUR_HMAC) is a weak cipher that has been deprecated. "
                "Trust tickets encrypted with RC4 can be cracked more easily than "
                "those using AES128 or AES256."
            ),
            "recommendation": (
                "Remove the TRUST_ATTRIBUTE_USES_RC4_ENCRYPTION flag and ensure "
                "both sides of the trust support AES Kerberos encryption types. "
                "Set msDS-SupportedEncryptionTypes on the trusted domain object "
                "to include AES flags (0x18 or 0x1C)."
            ),
            "details": rc4_trusts,
        })

    # Informational summary of all trusts
    if all_trusts_summary:
        findings.append({
            "title": "Domain Trust Inventory",
            "severity": "info",
            "deduction": 0,
            "description": (
                f"A total of {len(trust_entries)} trust relationship(s) were enumerated. "
                "Review the details below to ensure all trusts are intentional, "
                "documented, and follow the principle of least privilege."
            ),
            "recommendation": (
                "Maintain a trust inventory and review it quarterly. "
                "Decommission any trusts that are no longer required."
            ),
            "details": all_trusts_summary,
        })

    return findings
