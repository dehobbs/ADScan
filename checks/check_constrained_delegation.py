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
  - Any constrained delegation misconfiguration -> medium (-8 pts)
"""

CHECK_NAME = "Constrained Delegation"
CHECK_ORDER = 3
CHECK_CATEGORY = ["Kerberos"]

# userAccountControl flags
_UAC_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000  # Protocol Transition / S4U2Self
_UAC_ACCOUNTDISABLE                  = 0x2

# High-value service types that are particularly dangerous to delegate to
_HIGH_VALUE_SERVICES = {
    "cifs", "ldap", "ldaps", "host", "http",
    "mssql", "MSSQLSvc", "wsman", "rpcss",
}

_ATTRS = [
    "sAMAccountName",
    "distinguishedName",
    "userAccountControl",
    "msDS-AllowedToDelegateTo",
    "objectClass",
    "description",
]


def _uac_flag(entry, flag):
    try:
        return bool(int(entry.get("userAccountControl")) & flag)
    except Exception:
        return False


def _is_disabled(entry):
    return _uac_flag(entry, _UAC_ACCOUNTDISABLE)


def _get_delegate_to(entry):
    """Return list of allowed-to-delegate-to SPN strings."""
    try:
        val = entry.get("msDS-AllowedToDelegateTo")
        return list(val) if val else []
    except Exception:
        return []


def _spn_service(spn):
    """Extract service type from SPN (e.g. 'cifs/dc01.corp.local' -> 'cifs')."""
    return spn.split("/")[0].lower() if "/" in spn else spn.lower()


def run_check(connector, verbose=False):
    """Identify accounts with Constrained Delegation configured."""
    findings = []
    log = connector.log

    # Query accounts with msDS-AllowedToDelegateTo set (KCD)
    entries = connector.ldap_search(
        search_filter=(
            "(&"
            "(|(objectClass=user)(objectClass=computer))"
            "(msDS-AllowedToDelegateTo=*)"
            ")"
        ),
        attributes=_ATTRS,
    )

    log.debug(f"     Accounts with msDS-AllowedToDelegateTo set: {len(entries) if entries else 0}")

    t2a4d_accounts = []      # Protocol Transition accounts
    high_value_accounts = [] # Delegating to high-value SPNs
    all_kcd_accounts = []    # Any KCD account

    for entry in entries:
        sam = ""
        try:
            sam = str(entry.get("sAMAccountName"))
        except Exception:  # sAMAccountName may be absent; sam stays as empty string
            pass

        disabled_suffix = " [DISABLED]" if _is_disabled(entry) else ""
        delegate_to = _get_delegate_to(entry)
        has_t2a4d = _uac_flag(entry, _UAC_TRUSTED_TO_AUTH_FOR_DELEGATION)

        account_info = f"{sam}{disabled_suffix}"
        all_kcd_accounts.append(account_info)

        if has_t2a4d:
            t2a4d_accounts.append(account_info)
            log.debug(f"     [T2A4D] {sam} -> {', '.join(delegate_to[:5])}")
        else:
            # Check if any delegated SPN is high-value
            risky_spns = [
                spn for spn in delegate_to
                if _spn_service(spn) in _HIGH_VALUE_SERVICES
            ]
            if risky_spns:
                high_value_accounts.append(f"{account_info} -> {', '.join(risky_spns[:3])}")
                log.debug(f"     [HIGH-VALUE KCD] {sam} -> {', '.join(risky_spns)}")

    # ----------------------------------------------------------------
    # Protocol Transition (S4U2Self capable) accounts
    # ----------------------------------------------------------------
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

    # ----------------------------------------------------------------
    # KCD to high-value services
    # ----------------------------------------------------------------
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

    # ----------------------------------------------------------------
    # Informational: any KCD not already flagged
    # ----------------------------------------------------------------
    remaining = [a for a in all_kcd_accounts
                 if a not in t2a4d_accounts
                 and not any(a.split(" ->")[0] in hv for hv in high_value_accounts)]

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

    return findings
