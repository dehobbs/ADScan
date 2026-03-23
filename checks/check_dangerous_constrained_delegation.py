CHECK_NAME = "Dangerous Constrained Delegation Targets"
CHECK_ORDER = 69
CHECK_CATEGORY = ["Kerberos"]

# High-value service classes that, if combined with DC targets, represent full compromise
HIGH_VALUE_SERVICE_CLASSES = {
    "ldap",    # DCSync, LDAP enumeration
    "cifs",    # File system access — lateral movement
    "host",    # General DC host access
    "gc",      # Global Catalog
    "krbtgt",  # Kerberos TGT — full domain compromise
    "rpc",     # Remote Procedure Call
    "rpcss",   # RPC subsystem
    "http",    # Web services on DC
    "wsman",   # WinRM — remote management
    "termsrv", # RDP
    "dns",     # DNS management on DC
    "time",    # Time service (Kerberos sensitive)
    "w32time",
}


def _parse_spn_service_class(spn):
    """Extract the service class from an SPN (the part before the first /)."""
    if not spn or "/" not in spn:
        return spn.lower() if spn else ""
    return spn.split("/")[0].lower()


def _parse_spn_host(spn):
    """Extract the hostname from an SPN."""
    if not spn or "/" not in spn:
        return ""
    parts = spn.split("/", 1)
    if len(parts) < 2:
        return ""
    host_part = parts[1].split(":")[0]   # strip port if present
    host_part = host_part.split("/")[0]   # strip instance if present
    return host_part.lower()


def run_check(connector, verbose=False):
    findings = []

    try:
        # Step 1: Get all DC hostnames
        dc_results = connector.ldap_search(
            search_filter=(
                "(&(objectClass=computer)"
                "(userAccountControl:1.2.840.113556.1.4.803:=8192))"   # SERVER_TRUST_ACCOUNT
            ),
            attributes=["dNSHostName", "sAMAccountName", "cn"],
        )

        dc_hostnames = set()
        if dc_results:
            for entry in dc_results:
                dns = entry.get("dNSHostName", "")
                sam = entry.get("sAMAccountName", "").rstrip("$").lower()
                cn = entry.get("cn", "").lower()
                if dns:
                    dc_hostnames.add(dns.lower())
                    dc_hostnames.add(dns.split(".")[0].lower())  # short hostname
                if sam:
                    dc_hostnames.add(sam)
                if cn:
                    dc_hostnames.add(cn)

        # Step 2: Find all accounts with constrained delegation (msDS-AllowedToDelegateTo)
        deleg_results = connector.ldap_search(
            search_filter="(msDS-AllowedToDelegateTo=*)",
            attributes=[
                "sAMAccountName",
                "distinguishedName",
                "msDS-AllowedToDelegateTo",
                "userAccountControl",
                "adminCount",
            ],
        )

        if not deleg_results:
            findings.append({
                "title": "Dangerous Constrained Delegation: No constrained delegation configured",
                "severity": "info",
                "deduction": 0,
                "description": "No accounts with msDS-AllowedToDelegateTo are configured in the domain.",
                "recommendation": "No action required.",
                "details": [],
            })
            return findings

        critical_hits = []   # delegation TO a DC with a high-value service class
        high_hits = []       # delegation TO a DC (any service class)
        medium_hits = []     # delegation to high-value service class on non-DC

        for entry in deleg_results:
            sam = entry.get("sAMAccountName", "unknown")
            dn = entry.get("distinguishedName", "")
            delegate_to = entry.get("msDS-AllowedToDelegateTo") or []
            if isinstance(delegate_to, str):
                delegate_to = [delegate_to]
            uac = int(entry.get("userAccountControl", 0) or 0)
            admin_count = int(entry.get("adminCount", 0) or 0)
            is_dc = bool(uac & 0x2000)

            for spn in delegate_to:
                svc_class = _parse_spn_service_class(spn)
                target_host = _parse_spn_host(spn)
                targets_dc = target_host in dc_hostnames if dc_hostnames else False
                is_dangerous_svc = svc_class in HIGH_VALUE_SERVICE_CLASSES

                label = f"{sam} -> {spn}"
                if admin_count:
                    label = f"[ADMIN] {label}"
                if is_dc:
                    label = f"[DC] {label}"
                label += f" | DN: {dn}"

                if targets_dc and is_dangerous_svc:
                    critical_hits.append(label)
                elif targets_dc:
                    high_hits.append(label)
                elif is_dangerous_svc:
                    medium_hits.append(label)

        if critical_hits:
            findings.append({
                "title": (
                    f"Dangerous Constrained Delegation: {len(critical_hits)} account(s) "
                    "delegating to high-value services on Domain Controllers"
                ),
                "severity": "critical",
                "deduction": 20,
                "description": (
                    "Accounts are configured with constrained delegation targeting high-value "
                    "service classes (ldap/, cifs/, host/, gc/, krbtgt/) on Domain Controllers. "
                    "An attacker who compromises one of these accounts can impersonate any user "
                    "(including Domain Admins) to those services on the DC via S4U2Proxy, "
                    "effectively achieving domain compromise. This is a classic escalation path."
                ),
                "recommendation": (
                    "1. Remove or restrict dangerous constrained delegation configurations.\n"
                    "2. If delegation is required, use Resource-Based Constrained Delegation (RBCD) "
                    "on the target only — not unconstrained or sensitive-class constrained delegation.\n"
                    "3. Enable the 'Account is sensitive and cannot be delegated' flag on all "
                    "privileged accounts.\n"
                    "4. Review: Get-ADObject -Filter {msDS-AllowedToDelegateTo -like '*'} "
                    "-Properties msDS-AllowedToDelegateTo"
                ),
                "details": critical_hits,
            })

        if high_hits:
            findings.append({
                "title": (
                    f"Constrained Delegation Targets DCs: {len(high_hits)} account(s)"
                ),
                "severity": "high",
                "deduction": 10,
                "description": (
                    "Accounts have constrained delegation configured with Domain Controller "
                    "hostnames as targets (non-critical service classes). This still grants "
                    "significant trust — an attacker can potentially move laterally to DCs "
                    "by compromising the delegating account."
                ),
                "recommendation": (
                    "Review whether delegation to DC targets is required. "
                    "If not, remove the delegation entries. "
                    "Ensure the 'sensitive and cannot be delegated' flag is set on DA accounts."
                ),
                "details": high_hits,
            })

        if medium_hits:
            findings.append({
                "title": (
                    f"Constrained Delegation to High-Value Services: {len(medium_hits)} account(s)"
                ),
                "severity": "medium",
                "deduction": 5,
                "description": (
                    "Accounts are delegating to high-value service classes (ldap/, cifs/, host/ etc.) "
                    "on non-DC hosts. Depending on what those hosts are, this may still represent "
                    "a significant escalation path."
                ),
                "recommendation": (
                    "Review all constrained delegation targets and ensure they are required "
                    "for legitimate business purposes. Restrict where possible."
                ),
                "details": medium_hits[:50],
            })

        if not critical_hits and not high_hits and not medium_hits:
            findings.append({
                "title": "Dangerous Constrained Delegation: No high-risk targets found",
                "severity": "info",
                "deduction": 0,
                "description": (
                    "Constrained delegation is configured but no accounts are targeting "
                    "high-value service classes on Domain Controllers."
                ),
                "recommendation": "Periodically review constrained delegation configurations.",
                "details": [],
            })

    except Exception as e:
        findings.append({
            "title": "Dangerous Constrained Delegation: Check encountered an error",
            "severity": "info",
            "deduction": 0,
            "description": f"The check could not complete: {e}",
            "recommendation": "Verify LDAP connectivity and permissions.",
            "details": [str(e)],
        })

    return findings
