CHECK_NAME = "Pre-Windows 2000 Compatible Access"
CHECK_ORDER = 68
CHECK_CATEGORY = ["Domain Hygiene"]

# Well-known SIDs for Everyone and Anonymous Logon
SID_EVERYONE             = "S-1-1-0"
SID_ANONYMOUS_LOGON      = "S-1-5-7"
SID_AUTHENTICATED_USERS  = "S-1-5-11"

PRE_WIN2K_GROUP_CN = "Pre-Windows 2000 Compatible Access"


def _classify_dn(dn):
    """Classify a member DN as dangerous, authenticated, or other.

    Returns one of: 'dangerous', 'authenticated', 'other'.
    """
    lower = dn.lower()
    if "s-1-1-0" in lower or "everyone" in lower:
        return "dangerous"
    if "s-1-5-7" in lower or "anonymous" in lower:
        return "dangerous"
    if "s-1-5-11" in lower or "authenticated users" in lower:
        return "authenticated"
    return "other"


def _label(dn):
    """Return a human-readable label for a well-known principal DN."""
    lower = dn.lower()
    if "s-1-1-0" in lower or "everyone" in lower:
        return f"Everyone ({dn})"
    if "s-1-5-7" in lower or "anonymous" in lower:
        return f"Anonymous Logon ({dn})"
    if "s-1-5-11" in lower or "authenticated users" in lower:
        return f"Authenticated Users ({dn})"
    return dn


def run_check(connector, verbose=False):
    findings = []

    try:
        # Step 1: locate the group and get its DN
        group_results = connector.ldap_search(
            search_filter=f"(&(objectClass=group)(cn={PRE_WIN2K_GROUP_CN}))",
            search_base="CN=Builtin," + connector.base_dn,
            attributes=["distinguishedName"],
        )
        if not group_results:
            # Fallback: search from the domain root
            group_results = connector.ldap_search(
                search_filter=f"(&(objectClass=group)(cn={PRE_WIN2K_GROUP_CN}))",
                attributes=["distinguishedName"],
            )

        if not group_results:
            findings.append({
                "title": "Pre-Windows 2000 Compatible Access: Group not found",
                "severity": "info",
                "deduction": 0,
                "description": (
                    "The 'Pre-Windows 2000 Compatible Access' group could not be found. "
                    "This may indicate a non-standard configuration or insufficient search permissions."
                ),
                "recommendation": "Manually verify: Get-ADGroup 'Pre-Windows 2000 Compatible Access'",
                "details": [],
            })
            return findings

        group_dn = group_results[0].get("distinguishedName")

        # Step 2: reverse memberOf lookup — avoids range-control paging issues
        # that occur when reading the 'member' attribute directly on large groups.
        member_results = connector.ldap_search(
            search_filter=f"(memberOf={group_dn})",
            attributes=["distinguishedName", "sAMAccountName"],
        )

        dangerous_members    = []
        authenticated_members = []
        other_members        = []

        for entry in member_results:
            dn = entry.get("distinguishedName") or entry.get("dn", "")
            classification = _classify_dn(dn)
            if classification == "dangerous":
                dangerous_members.append(_label(dn))
            elif classification == "authenticated":
                authenticated_members.append(_label(dn))
            else:
                sam = entry.get("sAMAccountName") or ""
                other_members.append(f"{sam} ({dn})" if sam else dn)

        if dangerous_members:
            findings.append({
                "title": (
                    "Pre-Windows 2000 Compatible Access: "
                    "Everyone/Anonymous Logon are members — unauthenticated enumeration enabled"
                ),
                "severity": "critical",
                "deduction": 20,
                "description": (
                    "The 'Pre-Windows 2000 Compatible Access' group contains 'Everyone' or "
                    "'Anonymous Logon'. This group grants read access to virtually all user, "
                    "group, and computer objects in the domain via SAMR and LSARPC interfaces. "
                    "With 'Everyone' or 'Anonymous Logon' as members, an unauthenticated attacker "
                    "on the network can enumerate all domain accounts, groups, and sensitive "
                    "information without any credentials. This is used by tools like enum4linux, "
                    "rpcclient, and Metasploit's auxiliary modules."
                ),
                "recommendation": (
                    "1. Remove Everyone and Anonymous Logon from this group immediately:\n"
                    "   Remove-ADGroupMember -Identity 'Pre-Windows 2000 Compatible Access' "
                    "-Members 'S-1-1-0','S-1-5-7'\n"
                    "2. If legacy systems require this access, restrict by IP using firewall rules.\n"
                    "3. Disable null session access on all DCs:\n"
                    "   Set RestrictAnonymous = 2 and RestrictAnonymousSAM = 1 in:\n"
                    "   HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa"
                ),
                "details": (
                    dangerous_members
                    + authenticated_members
                    + ([f"Also a member: {m}" for m in other_members[:20]] if other_members else [])
                ),
            })

        elif authenticated_members:
            findings.append({
                "title": (
                    "Pre-Windows 2000 Compatible Access: "
                    "Authenticated Users is a member — broad domain enumeration enabled"
                ),
                "severity": "medium",
                "deduction": 8,
                "description": (
                    "The 'Pre-Windows 2000 Compatible Access' group has members (listed in the "
                    "details below). This group grants broad SAMR/LSARPC read access to virtually "
                    "all user, group, and computer objects in the domain — including account names, "
                    "group memberships, and SID values. The presence of 'Authenticated Users' means "
                    "any valid domain credential is sufficient to perform this enumeration. Any "
                    "additional accounts or groups listed in the details inherit the same read access "
                    "and should be reviewed to confirm they are required for legacy application "
                    "compatibility. Membership in this group is frequently exploited during "
                    "post-compromise reconnaissance to rapidly map the AD environment."
                ),
                "recommendation": (
                    "Remove Authenticated Users from this group if legacy compatibility is not required:\n"
                    "Remove-ADGroupMember -Identity 'Pre-Windows 2000 Compatible Access' "
                    "-Members 'S-1-5-11'"
                ),
                "details": authenticated_members + other_members[:50],
            })

        elif other_members:
            findings.append({
                "title": f"Pre-Windows 2000 Compatible Access: {len(other_members)} member(s) found",
                "severity": "low",
                "deduction": 3,
                "description": (
                    "The 'Pre-Windows 2000 Compatible Access' group has members. "
                    "Review to ensure all memberships are required for legacy application compatibility."
                ),
                "recommendation": (
                    "Review group membership and remove any accounts not required for legacy "
                    "pre-Windows 2000 compatibility."
                ),
                "details": other_members[:50],
            })

        else:
            findings.append({
                "title": "Pre-Windows 2000 Compatible Access: Group is empty — no issues",
                "severity": "info",
                "deduction": 0,
                "description": (
                    "The 'Pre-Windows 2000 Compatible Access' group has no members. "
                    "Unauthenticated SAMR/LSARPC enumeration is not enabled via this group."
                ),
                "recommendation": "No action required. Continue to monitor this group.",
                "details": [],
            })

    except Exception as e:
        findings.append({
            "title": "Pre-Windows 2000 Compatible Access: Check encountered an error",
            "severity": "info",
            "deduction": 0,
            "description": f"The check could not complete: {e}",
            "recommendation": "Verify LDAP connectivity and permissions.",
            "details": [str(e)],
        })

    return findings
