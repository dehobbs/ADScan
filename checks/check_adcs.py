"""
checks/check_adcs.py - ADCS / PKI Vulnerability Check

Combines LDAP-based ESC checks with optional Certipy-based deep enumeration
into a single unified check.

Execution order:
  1. LDAP checks  -- always run; enumerate CAs, templates, and flag ESC1-16 via
                     direct LDAP queries against the PKI Configuration NC.
  2. Certipy check -- run only when Certipy is installed and connector credentials
                     are available; performs a full certipy-ad find -vulnerable pass
                     and merges results with the LDAP findings.

ESC checks implemented via LDAP:
  ESC1  - Enrollee supplies SAN with no manager approval
  ESC2  - Any-purpose or SubCA template with low-privileged enrollment
  ESC3  - Certificate Request Agent template abuse
  ESC6  - CA has EDITF_ATTRIBUTESUBJECTALTNAME2 flag set
  ESC8  - NTLM relay to HTTP ADCS enrollment endpoint (Web Enrollment)
  ESC9  - No security extension on certificate (CT_FLAG_NO_SECURITY_EXTENSION)
  ESC10 - Weak certificate mapping via UPN/SAN without strong mapping
  ESC11 - ADCS relay via ICPR -- IF_ENFORCEENCRYPTICERTREQUEST not set
  ESC13 - Issuance policy OID group link
  ESC15 - Schema V1 templates without szOID_NTDS_CA_SECURITY_EXT
  ESC16 - CA disabling security extension globally
  Weak key sizes, Low-privilege Enrollee ACL notes

Additional ESC checks via Certipy (when available):
  ESC4  - Template write-access misconfiguration (ACL)
  ESC7  - CA ACL abuse (ManageCA / ManageCertificates)
  Full re-confirmation of ESC1-3, 6, 8-11, 13, 15-16 with ACL context

Prerequisites for Certipy section:
  uv tool install certipy-ad (or python adscan.py --setup-tools)
  Connector must expose: username, password, domain, dc_host

Artifact saved to:
  Reports/Artifacts/adscan_certipy_<domain>_<timestamp>.json
"""
import glob
import json
import os
import subprocess  # nosec B404 - subprocess is required to invoke certipy-ad
import logging

from lib.tools import ensure_tool

_log = logging.getLogger(__name__)

CHECK_NAME     = "ADCS / PKI Vulnerabilities"
CHECK_ORDER    = 6
CHECK_CATEGORY = ["ADCS / PKI Vulnerabilities"]
CHECK_WEIGHT   = 20   # max deduction at stake for this check module

# ---------------------------------------------------------------------------
# Template / CA flag constants (LDAP checks)
# ---------------------------------------------------------------------------
_CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT          = 0x1
_CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME = 0x100
_CT_FLAG_NO_SECURITY_EXTENSION              = 0x80000

_SUBJECT_ALT_REQUIRE_UPN   = 0x20000000
_SUBJECT_ALT_REQUIRE_EMAIL = 0x40000000
_SUBJECT_REQUIRE_EMAIL     = 0x80000000
_SUBJECT_ALT_REQUIRE_DNS   = 0x08000000

_CT_FLAG_PEND_ALL_REQUESTS        = 0x2
_EDITF_ATTRIBUTESUBJECTALTNAME2   = 0x00040000
_IF_ENFORCEENCRYPTICERTREQUEST    = 0x200

_EKU_ANY              = "2.5.29.37.0"
_EKU_CLIENT_AUTH      = "1.3.6.1.5.5.7.3.2"
_EKU_SMART_CARD_AUTH  = "1.3.6.1.4.1.311.20.2.2"
_EKU_CERT_REQUEST_AGENT = "1.3.6.1.4.1.311.20.2.1"
_EKU_ANY_PURPOSE      = "2.5.29.37.0"
_EKU_SUBCA            = ""

_LOW_PRIV_PRINCIPALS = {
    "s-1-1-0":        "Everyone",
    "s-1-5-11":       "Authenticated Users",
    "s-1-5-domainusers": "Domain Users",
    "domain users":   "Domain Users",
    "everyone":       "Everyone",
    "authenticated users": "Authenticated Users",
    "users":          "Users",
    "s-1-5-32-545":   "BUILTIN\\Users",
}

_TEMPLATE_ATTRS = [
    "cn", "displayName", "distinguishedName",
    "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag",
    "msPKI-RA-Signature", "msPKI-Private-Key-Flag",
    "msPKI-Template-Schema-Version", "msPKI-Certificate-Application-Policy",
    "pKIExtendedKeyUsage", "pKIExpirationPeriod", "pKIOverlapPeriod",
    "nTSecurityDescriptor", "msPKI-Minimal-Key-Size",
    "flags", "objectClass",
]

_CA_ATTRS = [
    "cn", "displayName", "distinguishedName", "dNSHostName",
    "flags", "msPKI-Private-Key-Flag", "cACertificate", "certificateTemplates",
]

# CA flags: bit 0x200 = CA_FLAG_IGNORE_ENROLLMENT_AUTH_DATA (EPA disabled for Web Enrollment)
_CA_FLAG_EPA_DISABLED = 0x200

# ---------------------------------------------------------------------------
# Certipy severity / description / recommendation maps
# ---------------------------------------------------------------------------
_ESC_MAP = {
    "ESC1":  ("critical", 20),
    "ESC2":  ("critical", 20),
    "ESC3":  ("high",     15),
    "ESC4":  ("critical", 20),
    "ESC6":  ("critical", 20),
    "ESC7":  ("high",     15),
    "ESC8":  ("high",     15),
    "ESC9":  ("high",     15),
    "ESC10": ("medium",    8),
    "ESC11": ("high",     15),
    "ESC13": ("medium",    8),
    "ESC15": ("medium",    8),
    "ESC16": ("critical", 20),
}

_ESC_DESCRIPTIONS = {
    "ESC1":  "Enrollee can supply a Subject Alternative Name (SAN) with no manager approval and client auth EKU.",
    "ESC2":  "Any-purpose or SubCA template with low-privilege enrollment and no approval/RA requirements.",
    "ESC3":  "Enrollment Agent template grants certificate request delegation without RA signatures.",
    "ESC4":  "Low-privileged principal has write access to a certificate template (template misconfiguration).",
    "ESC6":  "CA has EDITF_ATTRIBUTESUBJECTALTNAME2 set, allowing arbitrary SAN in any request.",
    "ESC7":  "Low-privileged principal has ManageCA or ManageCertificates rights on the CA.",
    "ESC8":  "NTLM relay to ADCS HTTP Web Enrollment endpoint (certsrv) is possible.",
    "ESC9":  "Template has CT_FLAG_NO_SECURITY_EXTENSION set, preventing strong certificate mapping.",
    "ESC10": "Weak certificate-to-account mapping (StrongCertificateBindingEnforcement not enforced).",
    "ESC11": "CA does not enforce encrypted ICPR requests (IF_ENFORCEENCRYPTICERTREQUEST not set).",
    "ESC13": "Issuance policy OID is linked to a privileged AD group via msDS-OIDToGroupLink.",
    "ESC15": "Schema V1 template with client auth EKU may lack the NTDS CA Security Extension.",
    "ESC16": "CA disables szOID_NTDS_CA_SECURITY_EXT globally via msPKI-Private-Key-Flag.",
}

_ESC_RECOMMENDATIONS = {
    "ESC1":  "Disable CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME on the template, or require manager approval.",
    "ESC2":  "Remove Any-Purpose EKU; add manager approval or RA signature requirements.",
    "ESC3":  "Require at least 1 RA (Authorised Signature) on enrollment agent templates.",
    "ESC4":  "Remove write/FullControl ACEs granted to low-privileged principals on the template.",
    "ESC6":  "Run: certutil -config <CA> -setreg policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2, then restart CertSvc.",
    "ESC7":  "Remove ManageCA and ManageCertificates from low-privileged accounts in the CA ACL.",
    "ESC8":  "Disable certsrv IIS role if unused; enable EPA and HTTPS if required; enable SMB signing.",
    "ESC9":  "Remove CT_FLAG_NO_SECURITY_EXTENSION (0x80000) from msPKI-Certificate-Name-Flag on the template.",
    "ESC10": "Set HKLM\\SYSTEM\\CurrentControlSet\\Services\\Kdc\\StrongCertificateBindingEnforcement=2 on all DCs.",
    "ESC11": "Run: certutil -config <CA> -setreg CA\\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST, then restart CertSvc.",
    "ESC13": "Audit and remove unnecessary OID-to-group links via msDS-OIDToGroupLink.",
    "ESC15": "Migrate V1 templates to V4; enforce StrongCertificateBindingEnforcement=2 via KB5014754.",
    "ESC16": "Remove CT_FLAG_NO_SECURITY_EXTENSION flag from the CA msPKI-Private-Key-Flag attribute.",
}

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------
def _get_str(entry, attr, default=""):
    try:
        v = entry.get(attr)
        return str(v) if v is not None else default
    except Exception as exc:
        _log.debug(f"_get_str({attr!r}): {exc}")
        return default

def _get_int(entry, attr, default=0):
    try:
        v = entry.get(attr)
        return int(v) if v is not None else default
    except Exception as exc:
        _log.debug(f"_get_int({attr!r}): {exc}")
        return default

def _get_list(entry, attr):
    try:
        v = entry.get(attr)
        if v is None:
            return []
        if isinstance(v, list):
            return [str(x) for x in v]
        return [str(v)]
    except Exception as exc:
        _log.debug(f"_get_list({attr!r}): {exc}")
        return []

def _get_name(entry):
    return _get_str(entry, "displayName") or _get_str(entry, "cn") or "?"

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
    return _get_int(entry, "msPKI-RA-Signature", 0)

def _schema_version(entry):
    return _get_int(entry, "msPKI-Template-Schema-Version", 1)

def _min_key_size(entry):
    return _get_int(entry, "msPKI-Minimal-Key-Size", 0)

def _config_dn(base_dn):
    parts = base_dn.split(",")
    domain_parts = [p for p in parts if p.strip().upper().startswith("DC=")]
    return "CN=Configuration," + ",".join(domain_parts)

# ---------------------------------------------------------------------------
# Certipy helpers
# ---------------------------------------------------------------------------
def _resolve_certipy():
    """Return the absolute path to certipy-ad, auto-installing via uv if needed."""
    return ensure_tool("certipy")

def _get_credential_info(connector):
    username = getattr(connector, "username", None)
    password = getattr(connector, "password", None)
    domain   = getattr(connector, "domain",   None)
    dc_ip    = (
        getattr(connector, "dc_host", None)
        or getattr(connector, "dc_ip",   None)
        or getattr(connector, "server",  None)
    )
    if not domain and hasattr(connector, "base_dn"):
        parts     = connector.base_dn.split(",")
        dc_parts  = [p.split("=")[1] for p in parts if p.strip().upper().startswith("DC=")]
        domain    = ".".join(dc_parts)
    return {"username": username, "password": password, "domain": domain, "dc_ip": dc_ip}

# SSL-related error signatures that indicate LDAPS is broken on the DC.
_LDAPS_ERROR_PATTERNS = (
    # SSL/TLS negotiation failures
    "ssl wrapping error",
    "ssl: wrong version number",
    "ssl: unsupported protocol",
    "ssl handshake",
    "handshake failure",
    "ssleoferror",
    "certificate verify failed",
    "tlsv1 alert",
    "tlsv1.3 alert",
    # TCP-level errors that manifest on port 636 when LDAPS is unconfigured
    "connection reset by peer",
    "[errno 104]",   # ECONNRESET
    "[errno 111]",   # ECONNREFUSED (port 636 closed)
    "[errno 110]",   # ETIMEDOUT (port 636 filtered)
    # Certipy-specific error messages
    "error: socket",
    "got error: socket",
    "ldaps connection",
    "port 636",
)

def _is_ldaps_error(stdout, stderr):
    """Return True if certipy output suggests an LDAPS/TLS failure."""
    combined = (stdout + stderr).lower()
    return any(pat in combined for pat in _LDAPS_ERROR_PATTERNS)

def _run_certipy(creds, exe_path="certipy-ad", cwd=None, scheme=None):
    """Invoke certipy-ad find. scheme may be None (default LDAPS) or 'ldap'."""
    upn = f"{creds['username']}@{creds['domain']}"
    cmd = [
        exe_path,
        "find",
        "-u",      upn,
        "-p",      creds["password"],
        "-dc-ip",  creds["dc_ip"],
        "-enabled",
        "-vulnerable",
    ]
    if scheme:
        cmd += ["-ldap-scheme", scheme]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120, cwd=cwd)  # nosec B603 - cmd is a fully validated list, no shell interpolation
    return result.returncode, result.stdout, result.stderr

def _parse_certipy_json(json_path):
    findings = []
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # ---------------------------------------------------------------------------
    # Certipy JSON structure (confirmed from Certipy source, get_output_for_text_and_json):
    #
    #   "Certificate Authorities": {
    #       "0": { "CA Name": "corp-CA", "DNS Name": "...", "[!] Vulnerabilities": {...} },
    #       "1": { ... }
    #   },
    #   "Certificate Templates": {
    #       "0": { "Template Name": "VulnTemplate", "[!] Vulnerabilities": {...} },
    #       ...
    #   }
    #
    # Keys are integer-string indices; the display name is a field INSIDE the entry.
    # We also handle legacy list format for forward-compatibility.
    # ---------------------------------------------------------------------------

    def _iter_ca_entries(section):
        """Yield (ca_name, entry_dict) for Certipy CA output."""
        if isinstance(section, dict):
            for entry in section.values():
                if isinstance(entry, dict):
                    name = entry.get("CA Name") or entry.get("Name") or entry.get("cn") or "Unknown CA"
                    yield str(name), entry
        elif isinstance(section, list):
            for entry in section:
                if isinstance(entry, dict):
                    name = entry.get("CA Name") or entry.get("Name") or entry.get("cn") or "Unknown CA"
                    yield str(name), entry

    def _iter_tmpl_entries(section):
        """Yield (template_name, entry_dict) for Certipy template output."""
        if isinstance(section, dict):
            for entry in section.values():
                if isinstance(entry, dict):
                    name = entry.get("Template Name") or entry.get("Name") or entry.get("cn") or "Unknown Template"
                    yield str(name), entry
        elif isinstance(section, list):
            for entry in section:
                if isinstance(entry, dict):
                    name = entry.get("Template Name") or entry.get("Name") or entry.get("cn") or "Unknown Template"
                    yield str(name), entry

    # CA-level findings
    cas      = data.get("Certificate Authorities", {})
    ca_names = []
    ca_vulns = {}
    for ca_name, ca_data in _iter_ca_entries(cas):
        ca_names.append(ca_name)
        for esc, reason in ca_data.get("[!] Vulnerabilities", {}).items():
            esc_key = esc.split(":")[0].strip().upper()
            ca_vulns.setdefault(esc_key, []).append(f"CA '{ca_name}': {reason}")

    for esc_key, details in ca_vulns.items():
        severity, deduction = _ESC_MAP.get(esc_key, ("medium", 8))
        findings.append({
            "title":          f"{esc_key}: {_ESC_DESCRIPTIONS.get(esc_key, 'CA-level vulnerability')} [CA]",
            "severity":       severity,
            "deduction":      deduction,
            "description":    _ESC_DESCRIPTIONS.get(esc_key, f"{esc_key} detected on one or more CAs."),
            "recommendation": _ESC_RECOMMENDATIONS.get(esc_key, f"Remediate {esc_key} on the affected CA."),
            "details":        details,
        })

    # Template-level findings
    templates  = data.get("Certificate Templates", {})
    tmpl_vulns = {}
    for tmpl_name, tmpl_data in _iter_tmpl_entries(templates):
        for esc, reason in tmpl_data.get("[!] Vulnerabilities", {}).items():
            esc_key = esc.split(":")[0].strip().upper()
            tmpl_vulns.setdefault(esc_key, []).append(f"Template '{tmpl_name}': {reason}")

    for esc_key, details in tmpl_vulns.items():
        severity, deduction = _ESC_MAP.get(esc_key, ("medium", 8))
        findings.append({
            "title":          f"{esc_key}: {_ESC_DESCRIPTIONS.get(esc_key, 'Template-level vulnerability')}",
            "severity":       severity,
            "deduction":      deduction,
            "description":    _ESC_DESCRIPTIONS.get(esc_key, f"{esc_key} detected on one or more certificate templates."),
            "recommendation": _ESC_RECOMMENDATIONS.get(esc_key, f"Remediate {esc_key} on the affected template."),
            "details":        details,
        })

    # Summary finding
    if ca_names:
        findings.append({
            "title":     "ADCS Certification Authorities Discovered (Certipy)",
            "severity":  "info",
            "deduction": 0,
            "description": (
                f"Certipy discovered {len(ca_names)} Certification "
                "Authority/Authorities in this domain. "
                "Review the full Certipy JSON artifact for complete CA configuration details."
            ),
            "recommendation": (
                "Review CA configurations for unnecessary roles (Web Enrollment, NDES), "
                "weak templates, and overly permissive ACLs. "
                "Run Certipy without -vulnerable to enumerate all templates."
            ),
            "details": [f"CA: {n}" for n in ca_names],
        })

    return findings
# ---------------------------------------------------------------------------
# LDAP-based ADCS checks (formerly check_adcs.py)
# ---------------------------------------------------------------------------
def _run_ldap_checks(connector, verbose=False):
    """Run all LDAP-based ESC checks against the PKI Configuration NC."""
    findings  = []
    log = connector.log
    config_dn = _config_dn(connector.base_dn)
    pki_dn    = f"CN=Public Key Services,CN=Services,{config_dn}"
    tmpl_dn   = f"CN=Certificate Templates,{pki_dn}"
    enroll_dn = f"CN=Enrollment Services,{pki_dn}"

    # -------------------------------------------------------------------
    # Discover CAs
    # -------------------------------------------------------------------
    ca_entries = connector.ldap_search(
        search_filter="(objectClass=pKIEnrollmentService)",
        attributes=_CA_ATTRS,
        search_base=enroll_dn,
    )
    if not ca_entries:
        log.debug("  [INFO] No ADCS Certification Authority found in this domain.")
        return findings
    ca_names = [_get_name(e) for e in ca_entries]
    log.debug("  CA(s) found: %s", ', '.join(ca_names))

    # -------------------------------------------------------------------
    # ESC6: CA has EDITF_ATTRIBUTESUBJECTALTNAME2 flag
    # -------------------------------------------------------------------
    esc6_cas = []
    for ca in ca_entries:
        flags = _get_int(ca, "msPKI-Private-Key-Flag")
        if flags & _EDITF_ATTRIBUTESUBJECTALTNAME2:
            esc6_cas.append(_get_name(ca))
    if esc6_cas:
        findings.append({
            "title": "ESC6: CA Allows Attribute Subject Alternative Name (EDITF_ATTRIBUTESUBJECTALTNAME2)",
            "severity":  "critical",
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

    # -------------------------------------------------------------------
    # ESC11: CA does not enforce encrypted requests (ICPR relay)
    # -------------------------------------------------------------------
    esc11_cas = []
    for ca in ca_entries:
        flags = _get_int(ca, "flags")
        if not (flags & _IF_ENFORCEENCRYPTICERTREQUEST):
            esc11_cas.append(_get_name(ca))
    if esc11_cas:
        findings.append({
            "title": "ESC11: CA Does Not Enforce Encrypted Certificate Requests (ICPR Relay Risk)",
            "severity":  "high",
            "deduction": 15,
            "description": (
                "One or more CAs do not enforce encryption for ICPR (RPC-based) "
                "certificate requests (IF_ENFORCEENCRYPTICERTREQUEST flag is not set). "
                "This enables NTLM relay attacks against the CA RPC endpoint."
            ),
            "recommendation": (
                "Enable encrypted certificate requests: "
                "certutil -config <CA> -setreg CA\\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST "
                "and restart CertSvc. Also enable EPA on the CA and SMB signing domain-wide."
            ),
            "details": [f"CA: {ca}" for ca in esc11_cas],
        })

    # -------------------------------------------------------------------
    # Enumerate certificate templates
    # -------------------------------------------------------------------
    tmpl_entries = connector.ldap_search(
        search_filter="(objectClass=pKICertificateTemplate)",
        attributes=_TEMPLATE_ATTRS,
        search_base=tmpl_dn,
    )
    if not tmpl_entries:
        log.debug("  [INFO] No certificate templates found.")
        return findings
    log.debug("  Certificate templates found: %d", len(tmpl_entries))

    esc1_templates  = []
    esc2_templates  = []
    esc3_templates  = []
    esc9_templates  = []
    esc13_templates = []
    esc15_templates = []
    weak_key_templates = []

    for tmpl in tmpl_entries:
        name        = _get_name(tmpl)
        name_flag   = _get_int(tmpl, "msPKI-Certificate-Name-Flag")
        enroll_flag = _get_int(tmpl, "msPKI-Enrollment-Flag")
        ra_sigs     = _ra_signatures_required(tmpl)
        schema_ver  = _schema_version(tmpl)
        key_size    = _min_key_size(tmpl)
        tmpl_ekus   = _ekus(tmpl)
        approval    = _requires_manager_approval(tmpl)

        has_client_auth = (
            _EKU_CLIENT_AUTH     in tmpl_ekus
            or _EKU_SMART_CARD_AUTH in tmpl_ekus
            or _EKU_ANY          in tmpl_ekus
            or len(tmpl_ekus) == 0
        )
        has_any_purpose   = _EKU_ANY in tmpl_ekus or len(tmpl_ekus) == 0
        has_enroll_agent  = _EKU_CERT_REQUEST_AGENT in tmpl_ekus

        enrollee_supplies_san     = bool(name_flag & _CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME)
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

    # -------------------------------------------------------------------
    # ESC8: Web Enrollment endpoint (HTTP NTLM relay)
    # Fires only for CAs where EPA cannot be confirmed as enforced.
    # The CA "flags" attribute bit 0x200 (CA_FLAG_IGNORE_ENROLLMENT_AUTH_DATA)
    # indicates EPA is NOT enforced.  If the attribute is absent (None/0) we
    # cannot confirm protection and conservatively flag the CA.
    # -------------------------------------------------------------------
    cas_without_epa = [
        ca for ca in ca_entries
        if (int(_get_str(ca, "flags") or 0) & _CA_FLAG_EPA_DISABLED) or
           not _get_str(ca, "flags")
    ]
    if cas_without_epa:
        findings.append({
            "title": "ESC8: Potential NTLM Relay to ADCS Web Enrollment Endpoint",
            "severity":  "high",
            "deduction": 15,
            "description": (
                f"Active Directory Certificate Services is deployed in this domain "
                f"(CA(s): {', '.join(ca_names)}). "
                "If the IIS-based Web Enrollment role (certsrv) is enabled on any CA, "
                "it is likely vulnerable to NTLM relay attacks (ESC8). "
                "An attacker can coerce authentication from a privileged host and relay "
                "it to the Web Enrollment endpoint to obtain a certificate as that host, "
                "enabling DCSync or full domain compromise via UnPAC-the-Hash or PKINIT."
            ),
            "recommendation": (
                "1. Disable the Web Enrollment (certsrv) IIS role if not required. "
                "2. If required, enable EPA (Extended Protection for Authentication) and HTTPS. "
                "3. Enable SMB signing on all domain-joined systems. "
                "4. Block intra-domain NTLM where possible (LmCompatibilityLevel=5). "
                "Verify: https://<CA-host>/certsrv -- if accessible, Web Enrollment is enabled."
            ),
            "details": [f"CA host: {_get_str(ca, 'dNSHostName') or _get_name(ca)}" for ca in cas_without_epa],
        })

    # -------------------------------------------------------------------
    # ESC10: Certificate mapping via UPN without strong mapping
    # -------------------------------------------------------------------
    findings.append({
        "title": "ESC10: Certificate Mapping May Not Use Strong Mapping (Verify KB5014754)",
        "severity":  "medium",
        "deduction": 8,
        "description": (
            "ESC10 describes abuse of weak certificate-to-account mapping. "
            "If StrongCertificateBindingEnforcement on Domain Controllers "
            "is set to 0 (disabled) or 1 (compatibility mode), certificates with a UPN "
            "SAN or email SAN can be used to authenticate as the matching account. "
            "This cannot be fully assessed via LDAP alone -- registry inspection is required."
        ),
        "recommendation": (
            "On all Domain Controllers, set: "
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Kdc\\"
            "StrongCertificateBindingEnforcement = 2 "
            "(Full Enforcement mode). Apply KB5014754."
        ),
        "details": [
            "Requires verification of HKLM\\SYSTEM\\CurrentControlSet\\Services\\Kdc\\"
            "StrongCertificateBindingEnforcement on each DC",
            f"CA(s) in scope: {', '.join(ca_names)}",
        ],
    })

    # -------------------------------------------------------------------
    # ESC16: CA disabling security extension globally
    # -------------------------------------------------------------------
    esc16_cas = []
    for ca in ca_entries:
        priv_key_flag = _get_int(ca, "msPKI-Private-Key-Flag")
        if priv_key_flag & _CT_FLAG_NO_SECURITY_EXTENSION:
            esc16_cas.append(_get_name(ca))
    if esc16_cas:
        findings.append({
            "title": "ESC16: CA Disabling szOID_NTDS_CA_SECURITY_EXT Globally",
            "severity":  "critical",
            "deduction": 20,
            "description": (
                "One or more CAs have CT_FLAG_NO_SECURITY_EXTENSION set at the CA level. "
                "This suppresses the szOID_NTDS_CA_SECURITY_EXT extension from ALL "
                "issued certificates, preventing strong certificate mapping and enabling "
                "certificate abuse across ALL templates on this CA."
            ),
            "recommendation": (
                "Remove the CT_FLAG_NO_SECURITY_EXTENSION flag from the CA "
                "msPKI-Private-Key-Flag attribute. "
                "Enforce the NTDS CA Security Extension on all templates."
            ),
            "details": [f"CA: {ca}" for ca in esc16_cas],
        })

    # -------------------------------------------------------------------
    # Template-level findings
    # -------------------------------------------------------------------
    if esc1_templates:
        findings.append({
            "title": "ESC1: Certificate Templates Allow Enrollee-Supplied SAN",
            "severity":  "critical",
            "deduction": 20,
            "description": (
                f"{len(esc1_templates)} certificate template(s) allow the enrollee to specify "
                "an arbitrary Subject Alternative Name (SAN) and have a client authentication EKU "
                "without requiring manager approval. Any user with enrollment rights can request "
                "a certificate with the UPN of a Domain Admin and authenticate as them."
            ),
            "recommendation": (
                "Disable CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME on all templates "
                "where it is not required. Require manager approval on any template "
                "where this flag must remain. See: msPKI-Certificate-Name-Flag bit 0x100."
            ),
            "details": esc1_templates,
        })

    if esc2_templates:
        findings.append({
            "title": "ESC2: Any-Purpose / SubCA Certificate Templates with Low-Privilege Enrollment",
            "severity":  "critical",
            "deduction": 20,
            "description": (
                f"{len(esc2_templates)} template(s) have an Any-Purpose EKU or no EKU (SubCA) "
                "configured without manager approval or RA signature requirements. "
                "Any-purpose certificates can be used for any purpose including client "
                "authentication, code signing, or as a subordinate CA."
            ),
            "recommendation": (
                "Remove Any-Purpose EKUs from templates unless explicitly required. "
                "Add manager approval or RA signature requirements to SubCA-style templates. "
                "Restrict enrollment rights to specific service accounts."
            ),
            "details": esc2_templates,
        })

    if esc3_templates:
        findings.append({
            "title": "ESC3: Enrollment Agent Templates Allow Certificate Request Delegation",
            "severity":  "high",
            "deduction": 15,
            "description": (
                f"{len(esc3_templates)} template(s) grant the Certificate Request Agent EKU "
                "without requiring RA signatures or manager approval. "
                "An enrollment agent certificate allows the holder to enroll for certificates "
                "on behalf of ANY other user."
            ),
            "recommendation": (
                "Require at least 1 RA (Authorised Signature) on enrollment agent templates. "
                "Restrict enrollment rights to designated PKI administrators only."
            ),
            "details": esc3_templates,
        })

    if esc9_templates:
        findings.append({
            "title": "ESC9: Templates With CT_FLAG_NO_SECURITY_EXTENSION",
            "severity":  "high",
            "deduction": 15,
            "description": (
                f"{len(esc9_templates)} template(s) have CT_FLAG_NO_SECURITY_EXTENSION set. "
                "Certificates issued from these templates will not include the "
                "szOID_NTDS_CA_SECURITY_EXT extension, which contains the account SID. "
                "Without this extension, strong certificate mapping cannot be applied."
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
            "severity":  "medium",
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
            "severity":  "medium",
            "deduction": 8,
            "description": (
                f"{len(esc15_templates)} Schema Version 1 (legacy) certificate template(s) "
                "support client authentication. V1 templates pre-date the "
                "szOID_NTDS_CA_SECURITY_EXT extension. If strong certificate binding "
                "is not enforced, they may be exploitable."
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
            "severity":  "medium",
            "deduction": 8,
            "description": (
                f"{len(weak_key_templates)} certificate template(s) allow RSA key sizes "
                "below 2048 bits. Keys smaller than 2048 bits are considered weak."
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
        "severity":  "info",
        "deduction": 0,
        "description": (
            f"ADScan found {len(tmpl_entries)} certificate template(s). "
            "A full ESC1/ESC4 assessment requires parsing the nTSecurityDescriptor "
            "of each template to identify Enroll/AutoEnroll rights granted to low-privileged "
            "principals (Domain Users, Authenticated Users, Everyone). "
            "This binary ACL parsing is beyond the scope of the passive LDAP check."
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

# ---------------------------------------------------------------------------
# Certipy-based ADCS check (formerly check_adcs_certipy.py)
# ---------------------------------------------------------------------------
def _run_certipy_check(connector, verbose=False):
    """Run Certipy-based ADCS enumeration and return findings list.
    Returns an empty list if Certipy is unavailable or credentials are missing.
    """
    findings = []
    log = connector.log

    # -- Check Certipy is available ---------------------------------------
    certipy_exe = _resolve_certipy()
    if certipy_exe is None:
        findings.append({
            "title":     "Certipy Not Installed - Deep ADCS Check Skipped",
            "severity":  "info",
            "deduction": 0,
            "description": (
                "Certipy (certipy-ad) is not installed or not available on PATH. "
                "The Certipy-based ADCS deep-enumeration check cannot run. "
                "Install with: uv tool install certipy-ad"
            ),
            "recommendation": (
                "Install Certipy: uv tool install certipy-ad "
                "(or run: python adscan.py --setup-tools). "
                "Then re-run ADScan for full ACL-based ESC enumeration (ESC4, ESC7, etc.)."
            ),
            "details": [],
        })
        return findings

    # -- Extract credentials ----------------------------------------------
    try:
        creds   = _get_credential_info(connector)
        missing = [k for k, v in creds.items() if not v]
        if missing:
            raise ValueError(f"Missing credential fields: {', '.join(missing)}")
    except Exception as e:
        findings.append({
            "title":     "Certipy ADCS Check - Missing Credentials",
            "severity":  "info",
            "deduction": 0,
            "description": (
                f"Could not extract required credentials from the connector: {e}. "
                "Certipy requires username, password, domain, and DC IP."
            ),
            "recommendation": (
                "Ensure the ADScan connector exposes: username, password, domain, dc_host."
            ),
            "details": [str(e)],
        })
        return findings

    log.debug("  [Certipy] Running as %s@%s against DC %s", creds['username'], creds['domain'], creds['dc_ip'])

    # -- Build artifact output path ---------------------------------------
    artifacts_dir  = os.path.abspath(getattr(connector, "artifacts_dir",
                                              os.path.join("Reports", "Artifacts")))
    os.makedirs(artifacts_dir, exist_ok=True)

    try:
        returncode, stdout, stderr = _run_certipy(creds, exe_path=certipy_exe, cwd=artifacts_dir)

        # ----------------------------------------------------------------
        # LDAPS → LDAP fallback
        # If Certipy failed with an SSL/TLS error (e.g. LDAPS not configured
        # on the DC) automatically retry using plain LDAP (port 389).
        # ----------------------------------------------------------------
        ldap_fallback_used = False
        # Trigger LDAPS→LDAP fallback whenever SSL error patterns appear in output,
        # regardless of return code — Certipy may return 0 even on SSL failure.
        if _is_ldaps_error(stdout, stderr):
            log.debug("  [Certipy] LDAPS connection failed — retrying with plain LDAP (-scheme ldap)...")
            returncode, stdout, stderr = _run_certipy(
                creds, exe_path=certipy_exe, cwd=artifacts_dir, scheme="ldap"
            )
            ldap_fallback_used = True

        # Log the subprocess call to the debug log (if enabled)
        dbg = getattr(connector, "debug_log", None)
        if dbg:
            upn = f"{creds['username']}@{creds['domain']}"
            scheme_note = " (LDAP fallback)" if ldap_fallback_used else ""
            dbg.log_subprocess(
                cmd=["certipy-ad", "find", "-u", upn, "-p", "<redacted>",
                     "-dc-ip", creds["dc_ip"],
                     "-enabled", "-vulnerable"]
                    + (["-ldap-scheme", "ldap"] if ldap_fallback_used else []),
                cwd=str(artifacts_dir) if artifacts_dir else None,
                returncode=returncode,
                stdout=stdout,
                stderr=stderr,
            )
        if ldap_fallback_used:
            log.debug("  [Certipy] Running via plain LDAP (LDAPS unavailable on DC)")
        if stdout:
            log.debug("  [Certipy stdout]\n%s", stdout[:2000])
        if stderr:
            log.debug("  [Certipy stderr]\n%s", stderr[:1000])

        if returncode != 0:
            findings.append({
                "title":     "Certipy Execution Failed",
                "severity":  "info",
                "deduction": 0,
                "description": (
                    f"Certipy exited with return code {returncode}"
                    + (" (tried LDAPS then plain LDAP fallback)." if ldap_fallback_used
                       else ". Check that credentials are valid and the DC is reachable.")
                ),
                "recommendation": (
                    f"Run manually: certipy-ad find -u {creds['username']}@{creds['domain']} "
                    f"-p <password> -dc-ip {creds['dc_ip']} -scheme ldap -json -vulnerable"
                    if ldap_fallback_used else
                    f"Run manually: certipy-ad find -u {creds['username']}@{creds['domain']} "
                    f"-p <password> -dc-ip {creds['dc_ip']} -json -vulnerable"
                ),
                "details": [
                    "LDAPS failed (SSL error) — plain LDAP fallback also failed." if ldap_fallback_used
                    else f"Return code: {returncode}",
                    f"stderr: {stderr[:500]}" if stderr else "no stderr",
                ],
            })
            return findings

        # Detect which output file Certipy actually wrote
        # Certipy writes output named after the domain (e.g. <domain>_Certipy.json).
        # Find the most recently modified JSON file in the artifacts directory.
        _found = glob.glob(os.path.join(artifacts_dir, "*.json"))
        actual_json = max(_found, key=os.path.getmtime) if _found else None

        if actual_json is None:
            findings.append({
                "title":     "Certipy JSON Output Not Found",
                "severity":  "info",
                "deduction": 0,
                "description": (
                    "Certipy ran successfully but did not produce a JSON output file. "
                    f"Searched in: {artifacts_dir}"
                    + (" (ran via plain LDAP fallback)" if ldap_fallback_used else "")
                ),
                "recommendation": (
                    "Ensure Certipy version >= 4.0 is installed (certipy-ad). "
                    "Run certipy-ad manually with -json -output to verify output naming."
                ),
                "details": [f"stdout: {stdout[:500]}"],
            })
            return findings

        scheme_label = "LDAP (fallback)" if ldap_fallback_used else "LDAPS"
        log.debug("  [Certipy] Artifact saved (%s): %s", scheme_label, actual_json)

        parsed = _parse_certipy_json(actual_json)
        if parsed:
            findings.extend(parsed)
        else:
            findings.append({
                "title":     "Certipy ADCS Scan - No Vulnerable Findings",
                "severity":  "info",
                "deduction": 0,
                "description": (
                    "Certipy completed successfully and found no vulnerable "
                    "certificate templates or CA misconfigurations."
                    + (" (ran via plain LDAP fallback)" if ldap_fallback_used else "")
                ),
                "recommendation": (
                    "Continue to monitor ADCS configuration. Re-run periodically "
                    "or after any PKI changes."
                ),
                "details": [f"Artifact: {actual_json}"],
            })
    except subprocess.TimeoutExpired:
        findings.append({
            "title":     "Certipy Timed Out",
            "severity":  "info",
            "deduction": 0,
            "description": (
                "Certipy did not complete within the 120-second timeout. "
                "This may indicate network connectivity issues or a slow DC."
            ),
            "recommendation": "Check network connectivity to the DC and retry.",
            "details": [f"DC: {creds['dc_ip']}"],
        })
    except Exception as e:
        findings.append({
            "title":     "Certipy ADCS Check - Unexpected Error",
            "severity":  "info",
            "deduction": 0,
            "description": f"An unexpected error occurred while running Certipy: {e}",
            "recommendation": "Review ADScan logs and run Certipy manually to diagnose.",
            "details": [str(e)],
        })

    return findings

# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------
def run_check(connector, verbose=False):
    """Run combined LDAP + Certipy ADCS checks.

    Phase 1: LDAP-based checks (always executed).
    Phase 2: Certipy-based checks (executed when Certipy is installed
             and connector credentials are available).

    Findings from both phases are merged and returned as a single list.
    Duplicate ESC findings (same title) are de-duplicated, preferring the
    Certipy result which includes ACL context not available via LDAP.
    """
    # Phase 1 - LDAP
    try:
        ldap_findings = _run_ldap_checks(connector, verbose=verbose)
    except Exception as exc:
        ldap_findings = [{
            "title":     "ADCS LDAP Check Failed",
            "severity":  "info",
            "deduction": 0,
            "description": f"The LDAP-based ADCS check raised an exception: {exc}",
            "recommendation": "Check LDAP connectivity and base_dn configuration.",
            "details": [str(exc)],
        }]

    # Phase 2 - Certipy
    try:
        certipy_findings = _run_certipy_check(connector, verbose=verbose)
    except Exception as exc:
        certipy_findings = [{
            "title":     "ADCS Certipy Check Failed",
            "severity":  "info",
            "deduction": 0,
            "description": f"The Certipy-based ADCS check raised an exception: {exc}",
            "recommendation": "Check Certipy installation and connector credentials.",
            "details": [str(exc)],
        }]

    # ---------------------------------------------------------------------------
    # Merge LDAP and Certipy findings.
    #
    # The deduplication key is the ESC prefix at the start of the title
    # (e.g. "ESC1", "ESC6") so that differently-worded titles from LDAP and
    # Certipy for the same finding are treated as duplicates.
    # Certipy wins for any ESC it reports (richer ACL context).
    # LDAP-only findings with no ESC key (weak keys, ACL notes, ESC8/10 notes)
    # are always kept because Certipy's -vulnerable flag may skip them.
    # ---------------------------------------------------------------------------

    import re as _re
    _ESC_PREFIX_RE = _re.compile(r'^(ESC\d+)\b', _re.IGNORECASE)

    def _esc_key(title):
        """Extract the ESC prefix from a finding title, e.g. 'ESC1' from 'ESC1: ...'."""
        m = _ESC_PREFIX_RE.match(title.strip())
        return m.group(1).upper() if m else None

    # Build set of ESC keys that Certipy reported
    certipy_esc_keys = {k for f in certipy_findings for k in [_esc_key(f["title"])] if k}

    # Keep LDAP findings whose ESC key is NOT covered by Certipy
    # (or that have no ESC key at all — those are LDAP-only checks)
    merged = [
        f for f in ldap_findings
        if _esc_key(f["title"]) not in certipy_esc_keys
    ]
    merged.extend(certipy_findings)

    return merged
