CHECK_NAME = "AdminSDHolder ACL"
CHECK_ORDER = 63
CHECK_CATEGORY = ["Privileged Accounts"]
CHECK_WEIGHT   = 20   # max deduction at stake for this check module

# Well-known SIDs / CN patterns for privileged principals (these are EXPECTED in the AdminSDHolder DACL)
EXPECTED_PRIVILEGED = {
    # Well-known SIDs
    "S-1-5-18",        # SYSTEM
    "S-1-5-32-544",    # BUILTIN\\Administrators
    "S-1-3-0",         # Creator Owner
    "S-1-1-0",         # Everyone (usually read-only)
    "S-1-5-11",        # Authenticated Users (usually read-only)
    # CN patterns (matched case-insensitively in the trustee name)
    "domain admins",
    "enterprise admins",
    "administrators",
    "system",
    "creator owner",
    "self",
    "exchange windows permissions",  # Exchange-managed, may be expected
}

# ACE flags that indicate write / dangerous permissions
# These are the ldap3 / impacket ACE right masks
WRITE_RIGHTS = {
    0x00020000: "WriteDACL",
    0x00040000: "WriteOwner",
    0x00000020: "WriteProperty (all)",
    0x00000028: "WriteProperty",
    0x000F01FF: "GenericAll / FullControl",
    0x10000000: "GenericAll",
    0x00040000: "WriteOwner",
}

# Bit mask for any write-like access
DANGEROUS_MASK = (
    0x00020000 |  # WriteDACL
    0x00040000 |  # WriteOwner
    0x00000020 |  # WriteProperty
    0x10000000    # GenericAll
)


def _is_expected(trustee_name, trustee_sid):
    """Return True if the trustee is an expected privileged principal."""
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
