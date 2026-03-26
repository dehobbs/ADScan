"""
checks/check_constrained_delegation.py - Constrained Delegation Check

Constrained Kerberos Delegation (KCD) restricts delegation to specific services.
Two variants exist:

  1. Standard KCD (requires Kerberos):
     userAccountControl flag TRUSTED_TO_AUTH_FOR_DELEGATION (0x1000000) +
     msDS-AllowedToDelegateTo attribute lists target SPNs.

  2. Protocol Transition (any protocol):
     Same as above with the TRUSTED_TO_AUTH_FOR_DELEGATION (T2A4D) flag set.
     This allows impersonating ANY user (including sensitive/protected accounts)
     without needing a Kerberos service ticket from the user first — highest risk.

Risk Scoring:
  - Accounts with T2A4D (protocol transition) -> high (-15 pts)
  - Accounts with KCD to high-value SPNs (cifs, ldap, host to DCs) -> high (-15 pts)
  - Standard KCD (no high-value targets) -> info (0 pts)
"""
import logging

_log = logging.getLogger(__name__)


CHECK_NAME = "Constrained Delegation"
CHECK_ORDER = 3
CHECK_CATEGORY = ["Kerberos"]
CHECK_WEIGHT   = 20   # max deduction at stake for this check module

# userAccountControl flags
_UAC_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000  # Protocol Transition / S4U2Self
_UAC_ACCOUNTDISABLE                  = 0x2

# High-value service types that are particularly dangerous to delegate to
_HIGH_VALUE_SERVICES = {
    "cifs", "ldap", "ldaps", "host", "http",
    "mssql", "MSSQLSvc", "wsman", "rpcss",
}

# Extended set used for DC-targeting analysis (includes DC-specific service classes)
_DC_HIGH_VALUE_SERVICES = {
    "ldap", "cifs", "host", "gc", "krbtgt",
    "rpc", "rpcss", "http", "wsman", "termsrv",
    "dns", "time", "w32time",
}


def _spn_host(spn):
    """Extract the target hostname from an SPN."""
    if not spn or "/" not in spn:
        return ""
    host_part = spn.split("/", 1)[1].split(":")[0].split("/")[0]
    return host_part.lower()


_ATTRS = [
    "sAMAccountName",
    "distinguishedName",
    "userAccountControl",
    "msDS-AllowedToDelegateTo",
    "objectClass",
    "description",
    "adminCount",
]


def _uac_flag(entry, flag):
    try:
        return bool(int(entry.get("userAccountControl")) & flag)
    except Exception as exc:
        _log.debug(f"_uac_flag: unexpected error: {exc}")
        return False


def _is_disabled(entry):
    return _uac_flag(entry, _UAC_ACCOUNTDISABLE)


def _get_delegate_to(entry):
    """Return list of allowed-to-delegate-to SPN strings."""
    try:
        val = entry.get("msDS-AllowedToDelegateTo")
        return list(val) if val else []
    except Exception as exc:
        _log.debug(f"_get_delegate_to: unexpected error: {exc}")
        return []


def _spn_service(spn):
    """Extract service type from SPN."""
    return spn.split("/")[0].lower() if "/" in spn else spn.lower()


def run_check(connector, verbose=False):
    """Identify accounts with Constrained Delegation configured."""
    findings = []
    log = connector.log

    entries = connector.ldap_search(
        search_filter=(
            "(&"
            "(|(objectClass=user)(objectClass=computer))"
            "(msDS-AllowedToDelegateTo=*)"
            ")"
        ),
        attributes=_ATTRS,
    )

    log.debug(f"  Accounts with msDS-AllowedToDelegateTo set: {len(entries) if entries else 0}")

    t2a4d_accounts = []
    high_value_accounts = []
    all_kcd_accounts = []
    high_value_sams = set()

    for entry in entries:
        sam = ""
        try:
            sam = str(entry.get("sAMAccountName"))
        except Exception:
            pass

        disabled_suffix = " [DISABLED]" if _is_disabled(entry) else ""
        delegate_to = _get_delegate_to(entry)
        has_t2a4d = _uac_flag(entry, _UAC_TRUSTED_TO_AUTH_FOR_DELEGATION)
        account_info = f"{sam}{disabled_suffix}"
        all_kcd_accounts.append(account_info)

        if has_t2a4d:
            t2a4d_accounts.append(account_info)
            log.debug(f"  [T2A4D] {sam}")
        else:
            risky_spns = [
                spn for spn in delegate_to
                if _spn_service(spn) in _HIGH_VALUE_SERVICES
            ]
            if risky_spns:
                high_value_accounts.append(f"{account_info} -> {', '.join(risky_spns[:3])}")
                high_value_sams.add(account_info)
                log.debug(f"  [HIGH-VALUE KCD] {sam}")

    if t2a4d_accounts:
        findings.append({
            "title": "Accounts with Constrained Delegation + Protocol Transition (S4U2Self)",
            "severity": "high",
            "deduction": 15,
            "description": (
                f"{len(t2a4d_accounts)} account(s) have the TRUSTED_TO_AUTH_FOR_DELEGATION "
                "(T2A4D) flag set, enabling Protocol Transition. This allows the service to "
                "impersonate ANY domain user to the listed target services without requiring "
                "a Kerberos ticket from that user first (S4U2Self / S4U2Proxy abuse). "
                "An attacker who compromises these accounts can obtain service tickets "
                "as any user including Domain Admins."
            ),
            "recommendation": (
                "Audit whether Protocol Transition is genuinely required. "
                "If the application supports Kerberos, switch to standard KCD "
                "without the T2A4D flag. "
                "Ensure that sensitive accounts (DA, EA, Schema Admins) are flagged "
                "as 'Account is sensitive and cannot be delegated'."
            ),
            "details": t2a4d_accounts,
        })

    if high_value_accounts:
        findings.append({
            "title": "Constrained Delegation Targeting High-Value Services",
            "severity": "high",
            "deduction": 15,
            "description": (
                f"{len(high_value_accounts)} account(s) are configured with Constrained "
                "Delegation targeting high-value services (CIFS, LDAP, HOST, HTTP, etc.). "
                "If any of these accounts is compromised, an attacker can use S4U2Proxy "
                "to access those services as any user who has previously authenticated, "
                "potentially leading to lateral movement or privilege escalation."
            ),
            "recommendation": (
                "Review whether delegation to these services is genuinely required. "
                "Minimise the scope of allowed SPNs. Prefer RBCD (Resource-Based "
                "Constrained Delegation) which is controlled by the target resource, "
                "not the source account. Protect these accounts with privileged access "
                "workstations and strong authentication."
            ),
            "details": high_value_accounts,
        })

    t2a4d_set = set(t2a4d_accounts)
    remaining = [
        a for a in all_kcd_accounts
        if a not in t2a4d_set and a not in high_value_sams
    ]
    if remaining and not t2a4d_accounts and not high_value_accounts:
        findings.append({
            "title": "Accounts with Constrained Delegation Configured",
            "severity": "info",
            "deduction": 0,
            "description": (
                f"{len(remaining)} account(s) have standard Constrained Delegation "
                "configured. While not immediately critical, these accounts should "
                "be periodically reviewed to ensure delegation targets remain appropriate."
            ),
            "recommendation": (
                "Maintain an inventory of all delegation-enabled accounts. "
                "Apply the principle of least privilege when assigning delegation targets. "
                "Consider migrating to Resource-Based Constrained Delegation where possible."
            ),
            "details": remaining,
        })

    try:
        dc_results = connector.ldap_search(
            search_filter=(
                "(&(objectClass=computer)"
                "(userAccountControl:1.2.840.113556.1.4.803:=8192))"
            ),
            attributes=["dNSHostName", "sAMAccountName", "cn"],
        )

        dc_hostnames = set()
        if dc_results:
            for dc in dc_results:
                dns = dc.get("dNSHostName", "")
                sam = dc.get("sAMAccountName", "").rstrip("$").lower()
                cn = dc.get("cn", "").lower()
                if dns:
                    dc_hostnames.add(dns.lower())
                    dc_hostnames.add(dns.split(".")[0].lower())
                if sam:
                    dc_hostnames.add(sam)
                if cn:
                    dc_hostnames.add(cn)

        if dc_hostnames and entries:
            critical_dc_hits = []
            high_dc_hits = []
            medium_hits = []

            for entry in entries:
                sam = ""
                try:
                    sam = str(entry.get("sAMAccountName"))
                except Exception:
                    pass

                disabled_suffix = " [DISABLED]" if _is_disabled(entry) else ""
                admin_count = int(entry.get("adminCount", 0) or 0)
                delegate_to = _get_delegate_to(entry)

                for spn in delegate_to:
                    svc_class = _spn_service(spn)
                    target_host = _spn_host(spn)
                    targets_dc = target_host in dc_hostnames
                    is_dangerous_svc = svc_class in _DC_HIGH_VALUE_SERVICES
                    label = f"{sam}{disabled_suffix} -> {spn}"
                    if admin_count:
                        label = f"[ADMIN] {label}"

                    if targets_dc and is_dangerous_svc:
                        critical_dc_hits.append(label)
                    elif targets_dc:
                        high_dc_hits.append(label)
                    elif is_dangerous_svc:
                        medium_hits.append(label)

            if critical_dc_hits:
                findings.append({
                    "title": (
                        f"Dangerous Constrained Delegation: {len(critical_dc_hits)} account(s) "
                        "delegating to high-value services on Domain Controllers"
                    ),
                    "severity": "critical",
                    "deduction": 20,
                    "description": (
                        "Accounts are configured with constrained delegation targeting "
                        "high-value service classes (ldap/, cifs/, host/, gc/, krbtgt/) "
                        "on Domain Controllers. An attacker who compromises one of these "
                        "accounts can impersonate any user (including Domain Admins) to "
                        "those services on the DC via S4U2Proxy, effectively achieving "
                        "domain compromise."
                    ),
                    "recommendation": (
                        "Remove or restrict dangerous constrained delegation configurations. "
                        "Use Resource-Based Constrained Delegation (RBCD) on the target only. "
                        "Enable 'Account is sensitive and cannot be delegated' on all "
                        "privileged accounts."
                    ),
                    "details": critical_dc_hits,
                })

            if high_dc_hits:
                findings.append({
                    "title": (
                        f"Constrained Delegation Targets DCs: {len(high_dc_hits)} account(s)"
                    ),
                    "severity": "high",
                    "deduction": 10,
                    "description": (
                        "Accounts have constrained delegation configured with Domain Controller "
                        "hostnames as targets (non-critical service classes). An attacker who "
                        "compromises a delegating account can still move laterally to DCs."
                    ),
                    "recommendation": (
                        "Review whether delegation to DC targets is required. "
                        "If not, remove the delegation entries. "
                        "Ensure the 'sensitive and cannot be delegated' flag is set on "
                        "all privileged accounts."
                    ),
                    "details": high_dc_hits,
                })

            if medium_hits:
                findings.append({
                    "title": (
                        f"Constrained Delegation to High-Value Services: {len(medium_hits)} account(s)"
                    ),
                    "severity": "medium",
                    "deduction": 5,
                    "description": (
                        "Accounts are delegating to high-value service classes (ldap/, cifs/, "
                        "host/ etc.) on non-DC hosts. Depending on what those hosts are, this "
                        "may still represent a significant escalation path."
                    ),
                    "recommendation": (
                        "Review all constrained delegation targets and ensure they are required "
                        "for legitimate business purposes. Restrict where possible."
                    ),
                    "details": medium_hits[:50],
                })

    except Exception as exc:
        log.debug(f"  [WARN] DC-targeting delegation analysis failed: {exc}")

    return findings
