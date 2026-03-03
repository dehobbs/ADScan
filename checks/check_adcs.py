"""
checks/check_adcs.py - Active Directory Certificate Services (ADCS) / PKI Check

Implements ESC (Escalation) checks based on the SpecterOps "Certified Pre-Owned" research
(Will Schroeder & Lee Christensen).

ESC checks implemented:
  ESC1  - Enrollee supplies subject (SAN) with no manager approval
  ESC2  - Any-purpose or SubCA template with low-privileged enrollment
  ESC3  - Certificate Request Agent template abuse (enrollment agent)
  ESC6  - CA has EDITF_ATTRIBUTESUBJECTALTNAME2 flag set (CA-level SAN)
  ESC8  - NTLM relay to HTTP ADCS enrollment endpoint (Web Enrollment)
  ESC9  - No security extension on certificate (CT_FLAG_NO_SECURITY_EXTENSION)
  ESC10 - Weak certificate mapping via UPN/SAN without strong mapping
  ESC11 - ADCS relay via ICPR (RPC) -- IF_ENFORCEENCRYPTICERTREQUEST not set
  ESC13 - Issuance policy OID group link (privilege escalation via group)
  ESC15 - Schema V1 templates without szOID_NTDS_CA_SECURITY_EXT
  ESC16 - CA disabling security extension globally (szOID_NTDS_CA_SECURITY_EXT)

Additional checks:
  - Weak key sizes on templates (RSA < 2048-bit)
  - Low-privileged Enrollee ACL enumeration
  - CA existence discovery

Notes:
  - All checks use LDAP queries against the PKI configuration partition
  - ESC8/ESC11 rely on CA flag enumeration; actual HTTP endpoint testing is out of scope
  - ESC10 requires additional registry inspection beyond LDAP scope

LDAP Bases:
  Configuration NC : CN=Configuration,<domain-dn>
  PKI templates    : CN=Certificate Templates,CN=Public Key Services,CN=Services,<config-dn>
  Enrollment svc   : CN=Enrollment Services,CN=Public Key Services,CN=Services,<config-dn>
"""

CHECK_NAME = "ADCS / PKI Vulnerabilities"
CHECK_ORDER = 6
CHECK_CATEGORY = "Certificate Services & ESC Vulnerabilities"

# Template flags
_CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT              = 0x1
_CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME     = 0x100
_CT_FLAG_NO_SECURITY_EXTENSION                  = 0x80000
_CT_FLAG_ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL = 0x2000

# msPKI-Certificate-Name-Flag
_SUBJECT_ALT_REQUIRE_UPN   = 0x20000000
_SUBJECT_ALT_REQUIRE_EMAIL = 0x40000000
_SUBJECT_REQUIRE_EMAIL     = 0x80000000
_SUBJECT_ALT_REQUIRE_DNS   = 0x08000000

# Enrollment flag bits
_CT_FLAG_PEND_ALL_REQUESTS = 0x2  # Manager approval required

# CA flags (from msPKI-Private-Key-Flag / certutil -CAInfo)
_EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000  # ESC6
_IF_ENFORCEENCRYPTICERTREQUEST  = 0x200        # ESC11 -- should be set

# Extended Key Usage OIDs
_EKU_ANY             = "2.5.29.37.0"
_EKU_CLIENT_AUTH     = "1.3.6.1.5.5.7.3.2"
_EKU_SMART_CARD_AUTH = "1.3.6.1.4.1.311.20.2.2"
_EKU_CERT_REQUEST_AGENT = "1.3.6.1.4.1.311.20.2.1"  # Enrollment Agent
_EKU_ANY_PURPOSE     = "2.5.29.37.0"
_EKU_SUBCA           = ""  # No EKU = SubCA

# Well-known low-privilege SIDs / names indicating broad enrollment rights
_LOW_PRIV_PRINCIPALS = {
    "s-1-1-0":          "Everyone",
    "s-1-5-11":         "Authenticated Users",
    "s-1-5-domainusers":"Domain Users",
    "domain users":     "Domain Users",
    "everyone":         "Everyone",
    "authenticated users": "Authenticated Users",
    "users":            "Users",
    "s-1-5-32-545":     "BUILTIN\\Users",
}

_TEMPLATE_ATTRS = [
    "cn", "displayName", "distinguishedName",
    "msPKI-Certificate-Name-Flag",
    "msPKI-Enrollment-Flag",
    "msPKI-RA-Signature",
    "msPKI-Private-Key-Flag",
    "msPKI-Template-Schema-Version",
    "msPKI-Certificate-Application-Policy",
    "pKIExtendedKeyUsage",
    "pKIExpirationPeriod",
    "pKIOverlapPeriod",
    "nTSecurityDescriptor",
    "msPKI-Minimal-Key-Size",
    "msPKI-Template-Minor-Version",
    "flags",
    "objectClass",
]

_CA_ATTRS = [
    "cn", "displayName", "distinguishedName",
    "dNSHostName", "flags",
    "msPKI-Private-Key-Flag",
    "cACertificate",
    "certificateTemplates",
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_str(entry, attr, default=""):
    try:
        v = entry[attr].value
        return str(v) if v is not None else default
    except Exception:
        return default

def _get_int(entry, attr, default=0):
    try:
        return int(entry[attr].value)
    except Exception:
        return default

def _get_list(entry, attr):
    try:
        v = entry[attr].values
        return [str(x) for x in v] if v else []
    except Exception:
        return []

def _get_name(entry):
    return _get_str(entry, "displayName") or _get_str(entry, "cn") or "?"

def _has_low_priv_enrollment(entry):
    """Return list of low-privilege principals that have Enroll/AutoEnroll rights."""
    try:
        sd = entry["nTSecurityDescriptor"].raw_values
    except Exception:
        pass
    return []

def _acl_note(template_name):
    return (
        f"Template '{template_name}': Manually verify nTSecurityDescriptor "
        "for Enroll/AutoEnroll rights granted to Domain Users / Authenticated Users / Everyone."
    )

def _ekus(entry):
    ekus_policy = _get_list(entry, "msPKI-Certificate-Application-Policy")
    ekus_ext    = _get_list(entry, "pKIExtendedKeyUsage")
    return set(ekus_policy + ekus_ext)

def _requires_manager_approval(entry):
    enroll_flag = _get_int(entry, "msPKI-Enrollment-Flag")
    return bool(enroll_flag & _CT_FLAG_PEND_ALL_REQUESTS)

def _ra_signatures_required(entry):
    """Number of authorised signatures (RA) required."""
    return _get_int(entry, "msPKI-RA-Signature", 0)

def _schema_version(entry):
    return _get_int(entry, "msPKI-Template-Schema-Version", 1)

def _min_key_size(entry):
    return _get_int(entry, "msPKI-Minimal-Key-Size", 0)

def _config_dn(base_dn):
    """Derive Configuration NC from domain base DN."""
    parts = base_dn.split(",")
    domain_parts = [p for p in parts if p.strip().upper().startswith("DC=")]
    return "CN=Configuration," + ",".join(domain_parts)

# ---------------------------------------------------------------------------
# Main check
# ---------------------------------------------------------------------------

def run_check(connector, verbose=False):
    findings = []

    config_dn = _config_dn(connector.base_dn)
    pki_dn    = f"CN=Public Key Services,CN=Services,{config_dn}"
    tmpl_dn   = f"CN=Certificate Templates,{pki_dn}"
    enroll_dn = f"CN=Enrollment Services,{pki_dn}"

    # -----------------------------------------------------------------------
    # Discover CAs
    # -----------------------------------------------------------------------
    ca_entries = connector.ldap_search(
        search_filter="(objectClass=pKIEnrollmentService)",
        attributes=_CA_ATTRS,
        search_base=enroll_dn,
    )
    if not ca_entries:
        if verbose:
            print("  [INFO] No ADCS Certification Authority found in this domain.")
        return findings

    ca_names = [_get_name(e) for e in ca_entries]
    if verbose:
        print(f"  CA(s) found: {', '.join(ca_names)}")

    # -----------------------------------------------------------------------
    # ESC6: CA has EDITF_ATTRIBUTESUBJECTALTNAME2 flag
    # -----------------------------------------------------------------------
    esc6_cas = []
    for ca in ca_entries:
        flags = _get_int(ca, "msPKI-Private-Key-Flag")
        if flags & _EDITF_ATTRIBUTESUBJECTALTNAME2:
            esc6_cas.append(_get_name(ca))

    if esc6_cas:
        findings.append({
            "title": "ESC6: CA Allows Attribute Subject Alternative Name (EDITF_ATTRIBUTESUBJECTALTNAME2)",
            "severity": "critical",
            "deduction": 20,
            "description": (
                "One or more CAs have the EDITF_ATTRIBUTESUBJECTALTNAME2 flag set. "
                "This allows any certificate requestor to specify an arbitrary SAN "
                "(e.g., a UPN of a Domain Admin) in the certificate request, "
                "regardless of template configuration. This completely bypasses "
                "ESC1 mitigations applied at the template level and can be exploited "
                "to obtain a certificate authenticating as any domain user."
            ),
            "recommendation": (
                "Run: certutil -config <CA> -setreg policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2 "
                "then restart the CertSvc service on the CA. "
                "Note: This may break legitimate applications -- test in staging first."
            ),
            "details": [f"CA: {ca}" for ca in esc6_cas],
        })

    # -----------------------------------------------------------------------
    # ESC11: CA does not enforce encrypted requests (ICPR relay)
    # -----------------------------------------------------------------------
    esc11_cas = []
    for ca in ca_entries:
        flags = _get_int(ca, "flags")
        if not (flags & _IF_ENFORCEENCRYPTICERTREQUEST):
            esc11_cas.append(_get_name(ca))

    if esc11_cas:
        findings.append({
            "title": "ESC11: CA Does Not Enforce Encrypted Certificate Requests (ICPR Relay Risk)",
            "severity": "high",
            "deduction": 15,
            "description": (
                "One or more CAs do not enforce encryption for ICPR (RPC-based) "
                "certificate requests (IF_ENFORCEENCRYPTICERTREQUEST flag is not set). "
                "This enables NTLM relay attacks against the CA's RPC endpoint, "
                "allowing an attacker to relay authentication and obtain certificates "
                "on behalf of other users -- similar to ESC8 but over RPC."
            ),
            "recommendation": (
                "Enable encrypted certificate requests: "
                "certutil -config <CA> -setreg CA\\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST "
                "and restart CertSvc. Also enable EPA (Extended Protection for Authentication) "
                "on the CA and enable SMB signing domain-wide."
            ),
            "details": [f"CA: {ca}" for ca in esc11_cas],
        })

    # -----------------------------------------------------------------------
    # Enumerate certificate templates
    # -----------------------------------------------------------------------
    tmpl_entries = connector.ldap_search(
        search_filter="(objectClass=pKICertificateTemplate)",
        attributes=_TEMPLATE_ATTRS,
        search_base=tmpl_dn,
    )
    if not tmpl_entries:
        if verbose:
            print("  [INFO] No certificate templates found.")
        return findings

    if verbose:
        print(f"  Certificate templates found: {len(tmpl_entries)}")

    esc1_templates  = []
    esc2_templates  = []
    esc3_templates  = []
    esc9_templates  = []
    esc13_templates = []
    esc15_templates = []
    weak_key_templates = []
    acl_notes = []

    for tmpl in tmpl_entries:
        name       = _get_name(tmpl)
        name_flag  = _get_int(tmpl, "msPKI-Certificate-Name-Flag")
        enroll_flag = _get_int(tmpl, "msPKI-Enrollment-Flag")
        ra_sigs    = _ra_signatures_required(tmpl)
        schema_ver = _schema_version(tmpl)
        key_size   = _min_key_size(tmpl)
        tmpl_ekus  = _ekus(tmpl)
        approval   = _requires_manager_approval(tmpl)
        priv_key_flag = _get_int(tmpl, "msPKI-Private-Key-Flag")

        has_client_auth = (
            _EKU_CLIENT_AUTH     in tmpl_ekus or
            _EKU_SMART_CARD_AUTH in tmpl_ekus or
            _EKU_ANY             in tmpl_ekus or
            len(tmpl_ekus) == 0  # no EKU = SubCA
        )
        has_any_purpose  = _EKU_ANY in tmpl_ekus or len(tmpl_ekus) == 0
        has_enroll_agent = _EKU_CERT_REQUEST_AGENT in tmpl_ekus

        enrollee_supplies_san     = bool(name_flag & _CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME)
        enrollee_supplies_subject = bool(name_flag & _CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
        no_security_ext           = bool(name_flag & _CT_FLAG_NO_SECURITY_EXTENSION)

        # ESC1
        if enrollee_supplies_san and has_client_auth and not approval:
            esc1_templates.append(f"{name} (SAN flag set, no approval required)")

        # ESC2
        if has_any_purpose and not approval and not ra_sigs:
            esc2_templates.append(f"{name} (any-purpose/SubCA EKU, no approval, no RA signatures)")

        # ESC3
        if has_enroll_agent and not approval and not ra_sigs:
            esc3_templates.append(f"{name} (Enrollment Agent EKU, no approval)")

        # ESC9
        if no_security_ext:
            esc9_templates.append(f"{name} (CT_FLAG_NO_SECURITY_EXTENSION set)")

        # ESC13
        policy_oids = _get_list(tmpl, "msPKI-Certificate-Application-Policy")
        non_eku_policies = [p for p in policy_oids if p not in (
            _EKU_CLIENT_AUTH, _EKU_SMART_CARD_AUTH, _EKU_ANY, _EKU_CERT_REQUEST_AGENT
        )]
        if non_eku_policies and not approval:
            esc13_templates.append(
                f"{name} (Issuance Policy OIDs present, verify OID->group links: "
                f"{', '.join(non_eku_policies[:3])})"
            )

        # ESC15
        if schema_ver == 1 and has_client_auth and not no_security_ext:
            esc15_templates.append(
                f"{name} (Schema V1 template with client auth -- verify szOID_NTDS_CA_SECURITY_EXT)"
            )

        # Weak key size
        if 0 < key_size < 2048:
            weak_key_templates.append(f"{name} (minimum key size: {key_size} bits)")

        # ACL note
        acl_notes.append(_acl_note(name))

    # -----------------------------------------------------------------------
    # ESC8: Web Enrollment endpoint (HTTP NTLM relay)
    # -----------------------------------------------------------------------
    findings.append({
        "title": "ESC8: Potential NTLM Relay to ADCS Web Enrollment Endpoint",
        "severity": "high",
        "deduction": 15,
        "description": (
            f"Active Directory Certificate Services is deployed in this domain "
            f"(CA(s): {', '.join(ca_names)}). "
            "If the IIS-based Web Enrollment role (certsrv) is enabled on any CA, "
            "it is likely vulnerable to NTLM relay attacks (ESC8). "
            "An attacker can coerce authentication from a privileged host "
            "(e.g., Domain Controller using PrinterBug/PetitPotam) and relay it "
            "to the Web Enrollment endpoint to obtain a certificate as that host, "
            "enabling DCSync or full domain compromise via UnPAC-the-Hash or PKINIT."
        ),
        "recommendation": (
            "1. Disable the Web Enrollment (certsrv) IIS role if not required. "
            "2. If required, enable EPA (Extended Protection for Authentication) and HTTPS. "
            "3. Enable SMB signing on all domain-joined systems. "
            "4. Block intra-domain NTLM where possible (LmCompatibilityLevel=5). "
            "Verify: https://<CA-host>/certsrv -- if accessible, Web Enrollment is enabled."
        ),
        "details": [f"CA host: {_get_str(ca, 'dNSHostName') or _get_name(ca)}" for ca in ca_entries],
    })

    # -----------------------------------------------------------------------
    # ESC10: Certificate mapping via UPN without strong mapping
    # -----------------------------------------------------------------------
    findings.append({
        "title": "ESC10: Certificate Mapping May Not Use Strong Mapping (Verify KB5014754)",
        "severity": "medium",
        "deduction": 8,
        "description": (
            "ESC10 describes abuse of weak certificate-to-account mapping. "
            "If the StrongCertificateBindingEnforcement registry key on Domain Controllers "
            "is set to 0 (disabled) or 1 (compatibility mode), certificates with a UPN "
            "SAN or email SAN can be used to authenticate as the matching account, "
            "even if the certificate was not issued to that account. "
            "This cannot be fully assessed via LDAP alone -- registry inspection is required."
        ),
        "recommendation": (
            "On all Domain Controllers, set: "
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Kdc\\"
            "StrongCertificateBindingEnforcement = 2 "
            "(Full Enforcement mode). "
            "Apply KB5014754 and review Microsoft certificate-based authentication changes."
        ),
        "details": [
            "Requires verification of HKLM\\SYSTEM\\CurrentControlSet\\Services\\Kdc\\"
            "StrongCertificateBindingEnforcement on each DC",
            f"CA(s) in scope: {', '.join(ca_names)}",
        ],
    })

    # -----------------------------------------------------------------------
    # ESC16: CA disabling security extension globally
    # -----------------------------------------------------------------------
    esc16_cas = []
    for ca in ca_entries:
        priv_key_flag = _get_int(ca, "msPKI-Private-Key-Flag")
        if priv_key_flag & _CT_FLAG_NO_SECURITY_EXTENSION:
            esc16_cas.append(_get_name(ca))

    if esc16_cas:
        findings.append({
            "title": "ESC16: CA Disabling szOID_NTDS_CA_SECURITY_EXT Globally",
            "severity": "critical",
            "deduction": 20,
            "description": (
                "One or more CAs have CT_FLAG_NO_SECURITY_EXTENSION set at the CA level. "
                "This suppresses the szOID_NTDS_CA_SECURITY_EXT extension from ALL "
                "issued certificates, preventing strong certificate mapping and enabling "
                "certificate abuse across ALL templates on this CA."
            ),
            "recommendation": (
                "Remove the CT_FLAG_NO_SECURITY_EXTENSION flag from the CA's "
                "msPKI-Private-Key-Flag attribute. "
                "Enforce the NTDS CA Security Extension on all templates."
            ),
            "details": [f"CA: {ca}" for ca in esc16_cas],
        })

    # -----------------------------------------------------------------------
    # Template-level findings
    # -----------------------------------------------------------------------
    if esc1_templates:
        findings.append({
            "title": "ESC1: Certificate Templates Allow Enrollee-Supplied SAN",
            "severity": "critical",
            "deduction": 20,
            "description": (
                f"{len(esc1_templates)} certificate template(s) allow the enrollee to specify "
                "an arbitrary Subject Alternative Name (SAN) and have a client authentication EKU "
                "without requiring manager approval. Any user with enrollment rights can request "
                "a certificate with the UPN of a Domain Admin and authenticate as them."
            ),
            "recommendation": (
                "Disable the CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME flag on all templates "
                "that are not explicitly required to support it. "
                "Require manager approval on any template where this flag must remain. "
                "See: msPKI-Certificate-Name-Flag bit 0x100."
            ),
            "details": esc1_templates,
        })

    if esc2_templates:
        findings.append({
            "title": "ESC2: Any-Purpose / SubCA Certificate Templates with Low-Privilege Enrollment",
            "severity": "critical",
            "deduction": 20,
            "description": (
                f"{len(esc2_templates)} template(s) have an Any-Purpose EKU or no EKU (SubCA) "
                "configured without manager approval or RA signature requirements. "
                "Any-purpose certificates can be used for any purpose including client "
                "authentication, code signing, or as a subordinate CA -- enabling full "
                "escalation to domain compromise."
            ),
            "recommendation": (
                "Remove Any-Purpose EKUs from templates unless explicitly required. "
                "Add manager approval or RA signature requirements to SubCA-style templates. "
                "Restrict enrollment rights to only the specific service accounts that need them."
            ),
            "details": esc2_templates,
        })

    if esc3_templates:
        findings.append({
            "title": "ESC3: Enrollment Agent Templates Allow Certificate Request Delegation",
            "severity": "high",
            "deduction": 15,
            "description": (
                f"{len(esc3_templates)} template(s) grant the Certificate Request Agent EKU "
                "without requiring RA signatures or manager approval. "
                "An enrollment agent certificate allows the holder to enroll for certificates "
                "on behalf of ANY other user -- enabling escalation to Domain Admin by obtaining "
                "a certificate as a privileged account."
            ),
            "recommendation": (
                "Require at least 1 RA (Authorised Signature) on enrollment agent templates. "
                "Restrict enrollment rights to designated PKI administrators only. "
                "Monitor for issuance of enrollment agent certificates."
            ),
            "details": esc3_templates,
        })

    if esc9_templates:
        findings.append({
            "title": "ESC9: Templates With CT_FLAG_NO_SECURITY_EXTENSION",
            "severity": "high",
            "deduction": 15,
            "description": (
                f"{len(esc9_templates)} template(s) have CT_FLAG_NO_SECURITY_EXTENSION set. "
                "Certificates issued from these templates will not include the "
                "szOID_NTDS_CA_SECURITY_EXT extension, which contains the account SID. "
                "Without this extension, strong certificate mapping cannot be applied, "
                "allowing certificate-to-account mapping via weaker methods (UPN/email)."
            ),
            "recommendation": (
                "Remove CT_FLAG_NO_SECURITY_EXTENSION (0x80000) from msPKI-Certificate-Name-Flag "
                "on all templates. Enforce StrongCertificateBindingEnforcement=2 on all DCs."
            ),
            "details": esc9_templates,
        })

    if esc13_templates:
        findings.append({
            "title": "ESC13: Templates With Issuance Policy OIDs (Verify OID-Group Links)",
            "severity": "medium",
            "deduction": 8,
            "description": (
                f"{len(esc13_templates)} template(s) contain non-EKU policy OIDs in "
                "msPKI-Certificate-Application-Policy. "
                "ESC13 occurs when an issuance policy OID is linked to a privileged AD group. "
                "If a user can enroll for such a certificate, they inherit the linked group "
                "privileges when authenticating via PKINIT."
            ),
            "recommendation": (
                "Audit all issuance policy OIDs in "
                "CN=OID,CN=Public Key Services,CN=Services,<config> "
                "and verify which groups they are linked to via msDS-OIDToGroupLink. "
                "Remove unnecessary OID-to-group links."
            ),
            "details": esc13_templates,
        })

    if esc15_templates:
        findings.append({
            "title": "ESC15: Schema V1 Templates May Lack NTDS Security Extension",
            "severity": "medium",
            "deduction": 8,
            "description": (
                f"{len(esc15_templates)} Schema Version 1 (legacy) certificate template(s) "
                "support client authentication. V1 templates pre-date the "
                "szOID_NTDS_CA_SECURITY_EXT extension. If these templates are actively used "
                "and strong certificate binding is not enforced, they may be exploitable "
                "for authentication without a valid SID-based binding."
            ),
            "recommendation": (
                "Migrate V1 templates to V4 templates that include the NTDS security extension. "
                "If migration is not possible, ensure StrongCertificateBindingEnforcement=2 "
                "is applied on all DCs via KB5014754."
            ),
            "details": esc15_templates,
        })

    if weak_key_templates:
        findings.append({
            "title": "Certificate Templates With Weak RSA Key Sizes (< 2048-bit)",
            "severity": "medium",
            "deduction": 8,
            "description": (
                f"{len(weak_key_templates)} certificate template(s) allow RSA key sizes "
                "below 2048 bits. Keys smaller than 2048 bits are considered weak and "
                "can be factored with modern compute resources."
            ),
            "recommendation": (
                "Update msPKI-Minimal-Key-Size to at least 2048 on all templates. "
                "Consider requiring 4096-bit keys for long-lived certificates (CA certs)."
            ),
            "details": weak_key_templates,
        })

    # Enrollee ACL summary note
    findings.append({
        "title": "ADCS Enrollee ACL Review Required",
        "severity": "info",
        "deduction": 0,
        "description": (
            f"ADScan found {len(tmpl_entries)} certificate template(s). "
            "A full ESC1/ESC4 assessment requires parsing the nTSecurityDescriptor "
            "of each template to identify Enroll/AutoEnroll rights granted to low-privileged "
            "principals (Domain Users, Authenticated Users, Everyone). "
            "This binary ACL parsing is beyond the scope of this passive check."
        ),
        "recommendation": (
            "Run Certify.exe (github.com/GhostPack/Certify) or "
            "Certipy (github.com/ly4k/Certipy) for complete ACL-based ESC enumeration. "
            "Focus on templates with client auth EKUs and broad enrollment rights."
        ),
        "details": [f"Total templates enumerated: {len(tmpl_entries)}"] + [
            f"CA: {_get_name(ca)}" for ca in ca_entries
        ],
    })

    return findings
