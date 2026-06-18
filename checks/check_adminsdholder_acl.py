CHECK_NAME = "AdminSDHolder ACL"
CHECK_ORDER = 63
CHECK_CATEGORY = ["Privileged Accounts"]
CHECK_WEIGHT   = 20   # max deduction at stake for this check module

# Well-known RIDs of privileged groups that are EXPECTED to hold rights on
# AdminSDHolder. These groups use domain-relative (S-1-5-21-<domain>-<RID>)
# or BUILTIN (S-1-5-32-<RID>) SIDs, so they are matched by RID -- recognition
# does NOT depend on resolving the SID to a name. Well-known group RIDs are
# all < 1000; user/custom objects get RIDs >= 1000, so matching the trailing
# RID against this set never collides with a real account.
EXPECTED_RIDS = {
    512: "Domain Admins",
    516: "Domain Controllers",
    518: "Schema Admins",
    519: "Enterprise Admins",
    544: "Administrators",  # BUILTIN\\Administrators (S-1-5-32-544)
}

# Well-known SIDs / CN patterns for privileged principals that are EXPECTED to
# hold *write* access on AdminSDHolder. Low-privilege principals such as
# Everyone (S-1-1-0) and Authenticated Users (S-1-5-11) are deliberately NOT
# listed: they should only ever have read access, so write access for them is a
# genuine finding that must be reported (their normal read access is filtered
# out by DANGEROUS_MASK below, not by this allowlist).
EXPECTED_PRIVILEGED = {
    # Well-known SIDs
    "S-1-5-18",        # SYSTEM
    "S-1-5-32-544",    # BUILTIN\\Administrators
    "S-1-3-0",         # Creator Owner
    # CN patterns (matched case-insensitively in the trustee name)
    "domain admins",
    "enterprise admins",
    "administrators",
    "system",
    "creator owner",
    "self",
    "exchange windows permissions",  # Exchange-managed, may be expected
}

# ACE right bits that represent dangerous WRITE access (Win32 / ADS_RIGHTS).
# NOTE: 0x00020000 is READ_CONTROL (a *read* right) and must NOT appear here --
# treating it as WriteDACL caused every principal with normal read access
# (e.g. Authenticated Users) to be falsely flagged.
WRITE_RIGHTS = {
    0x00000020: "WriteProperty",  # ADS_RIGHT_DS_WRITE_PROP
    0x00040000: "WriteDACL",      # WRITE_DAC
    0x00080000: "WriteOwner",     # WRITE_OWNER
    0x10000000: "GenericAll",     # GENERIC_ALL
    0x40000000: "GenericWrite",   # GENERIC_WRITE
}

# Bit mask for any write-like access
DANGEROUS_MASK = (
    0x00000020 |  # WriteProperty (ADS_RIGHT_DS_WRITE_PROP)
    0x00040000 |  # WriteDACL     (WRITE_DAC)
    0x00080000 |  # WriteOwner    (WRITE_OWNER)
    0x40000000 |  # GenericWrite  (GENERIC_WRITE)
    0x10000000    # GenericAll    (GENERIC_ALL)
)


def _rid_of(sid):
    """Return the trailing RID of a SID string as an int, or None.

    e.g. 'S-1-5-21-...-512' -> 512, 'S-1-5-32-544' -> 544. Returns None for
    empty input or anything without an integer final component.
    """
    if not sid:
        return None
    tail = str(sid).rsplit("-", 1)[-1]
    try:
        return int(tail)
    except ValueError:
        return None


def _is_expected(trustee_name, trustee_sid):
    """Return True if the trustee is an expected privileged principal."""
    # RID-based match first: recognizes Domain Admins / Enterprise Admins /
    # Schema Admins / Domain Controllers / Administrators even when the SID
    # could not be resolved to a name (their domain-relative SIDs are not in
    # the absolute-SID allowlist below, so name resolution would otherwise be
    # the only thing keeping them out of the findings).
    if _rid_of(trustee_sid) in EXPECTED_RIDS:
        return True
    if trustee_sid:
        for s in EXPECTED_PRIVILEGED:
            if trustee_sid.startswith(s):
                return True
    if trustee_name:
        name_lower = trustee_name.lower()
        for pattern in EXPECTED_PRIVILEGED:
            if pattern in name_lower:
                return True
    return False


def run_check(connector, verbose=False):
    findings = []

    try:
        # Retrieve the AdminSDHolder object with its nTSecurityDescriptor
        admin_sdholder_dn = "CN=AdminSDHolder,CN=System," + connector.base_dn

        results = connector.ldap_search(
            search_filter="(objectClass=*)",
            search_base=admin_sdholder_dn,
            attributes=["nTSecurityDescriptor", "cn"],
            controls=[("1.2.840.113556.1.4.801", True, b"\x30\x03\x02\x01\x07")],  # SD control
        )

        if not results:
            findings.append({
                "title": "AdminSDHolder ACL: Object not found",
                "severity": "info",
                "deduction": 0,
                "description": (
                    "The CN=AdminSDHolder,CN=System object could not be retrieved. "
                    "This may indicate insufficient permissions or a non-standard domain configuration."
                ),
                "recommendation": "Run the check with a Domain Admin account to read the security descriptor.",
                "details": [],
            })
            return findings

        suspicious_aces = []

        for entry in results:
            raw_sd = entry.get("nTSecurityDescriptor")

            if not raw_sd:
                continue

            # Try to parse with impacket
            try:
                from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR, ACCESS_ALLOWED_ACE
                from impacket.ldap.ldaptypes import ACE as ImpacketACE

                if isinstance(raw_sd, str):
                    import base64
                    raw_sd = base64.b64decode(raw_sd)
                elif isinstance(raw_sd, list):
                    raw_sd = bytes(raw_sd)

                sd = SR_SECURITY_DESCRIPTOR()
                sd.fromString(raw_sd)

                if sd["Dacl"]:
                    for ace in sd["Dacl"].aces:
                        ace_type = ace["AceType"]
                        # Only look at Allow ACEs (type 0x00)
                        if ace_type != 0x00:
                            continue

                        mask = ace["Ace"]["Mask"]["Mask"]
                        sid_obj = ace["Ace"]["Sid"]
                        # Use the canonical S-1-5-... form. str(sid_obj) returns
                        # the hex of the binary SID, which neither resolve_sid nor
                        # _is_expected can match -- causing every principal
                        # (Domain Admins, SYSTEM, etc.) to be flagged.
                        try:
                            trustee_sid = sid_obj.formatCanonical()
                        except Exception:
                            trustee_sid = str(sid_obj)
                        trustee_name = trustee_sid  # fallback

                        # Try to resolve SID to name via connector
                        try:
                            resolved = connector.resolve_sid(trustee_sid)
                            if resolved:
                                trustee_name = resolved
                        except Exception:  # SID resolution is best-effort; fall back to raw SID
                            pass

                        if _is_expected(trustee_name, trustee_sid):
                            continue

                        # Check if the ACE grants dangerous rights
                        if mask & DANGEROUS_MASK:
                            right_names = []
                            for bit, name in WRITE_RIGHTS.items():
                                if mask & bit:
                                    right_names.append(name)
                            suspicious_aces.append(
                                f"{trustee_name} ({trustee_sid}) — rights: {', '.join(right_names) or hex(mask)}"
                            )

            except ImportError:
                # impacket not available — report as informational
                findings.append({
                    "title": "AdminSDHolder ACL: impacket not available for DACL parsing",
                    "severity": "info",
                    "deduction": 0,
                    "description": (
                        "The AdminSDHolder ACL check requires impacket to parse the binary "
                        "nTSecurityDescriptor. Install impacket: pip install impacket"
                    ),
                    "recommendation": "Install impacket and re-run the scan.",
                    "details": [],
                })
                return findings
            except Exception as parse_err:
                findings.append({
                    "title": "AdminSDHolder ACL: Failed to parse security descriptor",
                    "severity": "info",
                    "deduction": 0,
                    "description": f"Security descriptor parsing failed: {parse_err}",
                    "recommendation": "Verify domain admin privileges and impacket version.",
                    "details": [str(parse_err)],
                })
                return findings

        if suspicious_aces:
            findings.append({
                "title": f"AdminSDHolder ACL: {len(suspicious_aces)} unexpected principal(s) with write access",
                "severity": "critical",
                "deduction": 20,
                "description": (
                    "Non-privileged principals have write-level permissions on CN=AdminSDHolder. "
                    "SDProp runs every 60 minutes and copies the AdminSDHolder DACL to ALL protected "
                    "accounts (Domain Admins, Enterprise Admins, etc.). Any principal with write "
                    "access to AdminSDHolder effectively has persistent write access to every "
                    "privileged account in the domain — this is a domain persistence technique."
                ),
                "recommendation": (
                    "Immediately remove unexpected ACEs from CN=AdminSDHolder. "
                    "Use: dsacls 'CN=AdminSDHolder,CN=System,DC=...' to view and remove entries. "
                    "Or use PowerShell: "
                    "(Get-Acl 'AD:CN=AdminSDHolder,CN=System,DC=...').Access | "
                    "Where-Object {$_.IdentityReference -notmatch 'Admins|SYSTEM|Administrators'}"
                ),
                "details": suspicious_aces,
            })
        else:
            findings.append({
                "title": "AdminSDHolder ACL: No unexpected write permissions found",
                "severity": "info",
                "deduction": 0,
                "description": (
                    "The CN=AdminSDHolder DACL contains only expected privileged principals. "
                    "No non-privileged accounts have write-level access."
                ),
                "recommendation": "Periodically review the AdminSDHolder ACL as part of AD hardening.",
                "details": [],
            })

    except Exception as e:
        findings.append({
            "title": "AdminSDHolder ACL: Check encountered an error",
            "severity": "info",
            "deduction": 0,
            "description": f"The check could not complete: {e}",
            "recommendation": "Verify domain admin privileges and LDAP connectivity.",
            "details": [str(e)],
        })

    return findings
