CHECK_NAME = "Pre-Windows 2000 Compatible Access"
CHECK_ORDER = 68
CHECK_CATEGORY = ["Domain Hygiene"]

# Well-known SIDs for Everyone and Anonymous Logon
SID_EVERYONE        = "S-1-1-0"
SID_ANONYMOUS_LOGON = "S-1-5-7"
SID_AUTHENTICATED_USERS = "S-1-5-11"

# The Pre-Windows 2000 Compatible Access group SID (BUILTIN)
# S-1-5-32-554
PRE_WIN2K_GROUP_SID = "S-1-5-32-554"
PRE_WIN2K_GROUP_CN  = "Pre-Windows 2000 Compatible Access"


def run_check(connector, verbose=False):
    findings = []

    try:
        # Query the Pre-Windows 2000 Compatible Access group
        results = connector.ldap_search(
            search_filter=(
                "(|(cn=Pre-Windows 2000 Compatible Access)"
                "(objectSid=\x01\x02\x00\x00\x00\x00\x00\x05\x20\x00\x00\x00\x2a\x02\x00\x00))"
            ),
            search_base="CN=Builtin," + connector.base_dn,
            attributes=["cn", "member", "distinguishedName"],
        )

        if not results:
            # Try a broader search
            results = connector.ldap_search(
                search_filter="(&(objectClass=group)(cn=Pre-Windows 2000 Compatible Access))",
                attributes=["cn", "member", "distinguishedName"],
            )

        if not results:
            findings.append({
                "title": "Pre-Windows 2000 Compatible Access: Group not found",
                "severity": "info",
                "deduction": 0,
                "description": (
                    "The 'Pre-Windows 2000 Compatible Access' group could not be found. "
                    "This may indicate a non-standard configuration or insufficient search permissions."
                ),
                "recommendation": "Manually verify the group exists: Get-ADGroup 'Pre-Windows 2000 Compatible Access'",
                "details": [],
            })
            return findings

        dangerous_members = []    # Everyone or Anonymous Logon
        authenticated_members = []  # Authenticated Users (less dangerous but notable)
        other_members = []

        for entry in results:
            attrs = entry.get("attributes", {}) if isinstance(entry, dict) else {}
            members = attrs.get("member") or []
            if isinstance(members, str):
                members = [members]

            for member_dn in members:
                member_dn_lower = member_dn.lower()

                # Check for Everyone (S-1-1-0 appears as CN=S-1-1-0 in ForeignSecurityPrincipals)
                if "s-1-1-0" in member_dn_lower or "everyone" in member_dn_lower:
                    dangerous_members.append(f"Everyone ({member_dn})")

                # Check for Anonymous Logon (S-1-5-7)
                elif "s-1-5-7" in member_dn_lower or "anonymous" in member_dn_lower:
                    dangerous_members.append(f"Anonymous Logon ({member_dn})")

                # Check for Authenticated Users (S-1-5-11) — still grants broad access
                elif "s-1-5-11" in member_dn_lower or "authenticated users" in member_dn_lower:
                    authenticated_members.append(f"Authenticated Users ({member_dn})")

                else:
                    other_members.append(member_dn)

        if dangerous_members:
            findings.append({
                "title": (
                    f"Pre-Windows 2000 Compatible Access: "
                    f"Everyone/Anonymous Logon are members — unauthenticated enumeration enabled"
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
                "details": dangerous_members + ([f"Other members: {m}" for m in other_members[:20]] if other_members else []),
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
                    "The 'Pre-Windows 2000 Compatible Access' group contains 'Authenticated Users'. "
                    "This grants any authenticated domain account (including low-privilege users) "
                    "broad SAMR/LSARPC read access to enumerate domain objects. "
                    "While this requires valid credentials, it significantly lowers the bar for "
                    "post-compromise reconnaissance."
                ),
                "recommendation": (
                    "Remove Authenticated Users from this group if legacy compatibility is not required. "
                    "Remove-ADGroupMember -Identity 'Pre-Windows 2000 Compatible Access' "
                    "-Members 'S-1-5-11'"
                ),
                "details": authenticated_members,
            })

        else:
            # Check if the group has other unexpected members
            if other_members:
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
