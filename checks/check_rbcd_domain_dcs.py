"""
checks/check_rbcd_domain_dcs.py - Resource-Based Constrained Delegation (RBCD) Check

Detects dangerous RBCD configuration on high-value targets: the domain NC head
and all Domain Controller computer objects.

RBCD is controlled by the msDS-AllowedToActOnBehalfOfOtherIdentity attribute,
which holds a binary security descriptor (DACL). Any principal listed in that
DACL can use S4U2Proxy to impersonate ANY user (including Domain Admins) to
services on the target object.

On a Domain Controller this is equivalent to Domain Admin access via Kerberos
without knowing any password — a critical persistence and privilege escalation
path abused by tools such as Rubeus and Impacket.

LDAP attributes queried:
  msDS-AllowedToActOnBehalfOfOtherIdentity  -- binary security descriptor
  sAMAccountName, distinguishedName, dNSHostName  -- for DC identification

Risk Deductions:
  Critical (-20): any unexpected principal with S4U2Proxy rights on the
                  domain NC head or a DC computer object.
"""
CHECK_NAME = "RBCD on Domain Object / DCs"
CHECK_ORDER = 72
CHECK_CATEGORY = ["Kerberos"]

# msDS-AllowedToActOnBehalfOfOtherIdentity contains a binary security descriptor
# whose DACL lists principals that are allowed to perform S4U2Proxy against this object.
# If set on the domain NC head or a DC computer account, the permitted principals
# effectively have Domain Admin-level access via S4U2Proxy.


def _parse_rbcd_sd(raw_sd):
    """
    Parse the msDS-AllowedToActOnBehalfOfOtherIdentity binary security descriptor
    and return a list of trustee SIDs/names.
    Returns list of SID strings, or empty list on failure.
    """
    trustees = []
    if not raw_sd:
        return trustees

    try:
        from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
        import base64

        if isinstance(raw_sd, str):
            data = base64.b64decode(raw_sd)
        elif isinstance(raw_sd, (list, bytearray)):
            data = bytes(raw_sd)
        else:
            data = raw_sd

        sd = SR_SECURITY_DESCRIPTOR()
        sd.fromString(data)

        if sd["Dacl"]:
            for ace in sd["Dacl"].aces:
                ace_type = ace["AceType"]
                if ace_type == 0x00:  # ACCESS_ALLOWED_ACE
                    try:
                        sid_obj = ace["Ace"]["Sid"]
                        trustees.append(str(sid_obj))
                    except Exception:  # ACE SID extraction failed; skip this trustee
                        pass
    except ImportError:
        trustees.append("<impacket not available — install with: pip install impacket>")
    except Exception as e:
        trustees.append(f"<parse error: {e}>")

    return trustees


def _resolve_sid(connector, sid_str):
    """Try to resolve a SID to an account name."""
    try:
        resolved = connector.resolve_sid(sid_str)
        if resolved:
            return resolved
    except Exception:  # SID resolution failed; return raw SID string
        return sid_str
    return sid_str


# Well-known safe SIDs that may legitimately appear in RBCD (system accounts)
SAFE_SIDS = {
    "S-1-5-18",    # SYSTEM
    "S-1-5-10",    # SELF
}


def run_check(connector, verbose=False):
    findings = []
    log = connector._log

    try:
        # ------------------------------------------------------------------ #
        # 1. Check the domain NC head object itself                           #
        # ------------------------------------------------------------------ #
        domain_results = connector.ldap_search(
            search_filter="(objectClass=domain)",
            search_base=connector.base_dn,
            attributes=["distinguishedName", "msDS-AllowedToActOnBehalfOfOtherIdentity"],
        )

        domain_rbcd_trustees = []
        if domain_results:
            for entry in domain_results:
                attrs = entry.get("attributes", {}) if isinstance(entry, dict) else {}
                raw_sd = attrs.get("msDS-AllowedToActOnBehalfOfOtherIdentity")
                if raw_sd:
                    sids = _parse_rbcd_sd(raw_sd)
                    for sid in sids:
                        if sid not in SAFE_SIDS:
                            resolved = _resolve_sid(connector, sid)
                            domain_rbcd_trustees.append(
                                f"Domain NC head: {connector.base_dn} | Trustee: {resolved} ({sid})"
                            )

        # ------------------------------------------------------------------ #
        # 2. Check all DC computer objects                                    #
        # ------------------------------------------------------------------ #
        dc_results = connector.ldap_search(
            search_filter=(
                "(&(objectClass=computer)"
                "(userAccountControl:1.2.840.113556.1.4.803:=8192)"
                "(msDS-AllowedToActOnBehalfOfOtherIdentity=*))"
            ),
            attributes=[
                "sAMAccountName",
                "distinguishedName",
                "dNSHostName",
                "msDS-AllowedToActOnBehalfOfOtherIdentity",
            ],
        )

        dc_rbcd_trustees = []
        if dc_results:
            for entry in dc_results:
                attrs = entry.get("attributes", {}) if isinstance(entry, dict) else {}
                sam = attrs.get("sAMAccountName", "unknown")
                dn = attrs.get("distinguishedName", "")
                dns = attrs.get("dNSHostName", "")
                raw_sd = attrs.get("msDS-AllowedToActOnBehalfOfOtherIdentity")

                if raw_sd:
                    sids = _parse_rbcd_sd(raw_sd)
                    for sid in sids:
                        if sid not in SAFE_SIDS:
                            resolved = _resolve_sid(connector, sid)
                            dc_rbcd_trustees.append(
                                f"DC: {sam} ({dns}) | Trustee: {resolved} ({sid}) | DN: {dn}"
                            )

        # ------------------------------------------------------------------ #
        # 3. Build findings                                                   #
        # ------------------------------------------------------------------ #
        all_hits = domain_rbcd_trustees + dc_rbcd_trustees

        if all_hits:
            target_desc = []
            if domain_rbcd_trustees:
                target_desc.append(f"domain NC head ({len(domain_rbcd_trustees)} trustee(s))")
            if dc_rbcd_trustees:
                target_desc.append(f"DC computer accounts ({len(dc_rbcd_trustees)} trustee(s))")

            findings.append({
                "title": (
                    f"RBCD on Domain Object / DCs: {len(all_hits)} principal(s) with "
                    "S4U2Proxy rights on " + " and ".join(target_desc)
                ),
                "severity": "critical",
                "deduction": 20,
                "description": (
                    "msDS-AllowedToActOnBehalfOfOtherIdentity is set on the domain NC head or "
                    "one or more Domain Controller computer objects. This attribute controls "
                    "Resource-Based Constrained Delegation (RBCD). Principals listed in this "
                    "attribute can use S4U2Proxy to impersonate ANY user (including Domain Admins) "
                    "to services on the target object.\n\n"
                    "On a DC this grants the ability to obtain a service ticket as any domain user "
                    "to the DC — effectively granting Domain Admin access via Kerberos without "
                    "knowing any password. This is a critical persistence and privilege escalation "
                    "path used in attacks like 'RBCD abuse' (implemented in Rubeus, impacket, etc.)."
                ),
                "recommendation": (
                    "1. Immediately investigate each listed principal and verify legitimacy.\n"
                    "2. Remove any unexpected RBCD entries:\n"
                    "   Set-ADComputer <DC_name> -Clear msDS-AllowedToActOnBehalfOfOtherIdentity\n"
                    "   Set-ADObject <domain_NC_DN> -Clear msDS-AllowedToActOnBehalfOfOtherIdentity\n"
                    "3. Monitor this attribute for changes using AD audit logging (Event ID 5136).\n"
                    "4. Restrict write access to msDS-AllowedToActOnBehalfOfOtherIdentity on all "
                    "DC and domain NC objects."
                ),
                "details": all_hits,
            })

        else:
            findings.append({
                "title": "RBCD on Domain Object / DCs: No unexpected RBCD entries found",
                "severity": "info",
                "deduction": 0,
                "description": (
                    "msDS-AllowedToActOnBehalfOfOtherIdentity is not set on the domain NC head "
                    "or any Domain Controller computer accounts. This is the expected secure state."
                ),
                "recommendation": (
                    "Monitor this attribute for unexpected changes via AD audit logging (Event ID 5136). "
                    "Restrict write access to this attribute on all DC objects."
                ),
                "details": [],
            })

    except Exception as e:
        findings.append({
            "title": "RBCD on Domain Object / DCs: Check encountered an error",
            "severity": "info",
            "deduction": 0,
            "description": f"The check could not complete: {e}",
            "recommendation": "Verify LDAP connectivity and permissions.",
            "details": [str(e)],
        })

    return findings
