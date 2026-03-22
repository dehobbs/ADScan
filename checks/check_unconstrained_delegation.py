"""
checks/check_unconstrained_delegation.py - Unconstrained Delegation Check

Unconstrained Kerberos delegation allows a service account or computer account
to impersonate any user who authenticates to it, forwarding their full TGT to
any service. This represents one of the most critical Kerberos misconfigurations.

LDAP Filter:
  Accounts with userAccountControl flag ADS_UF_TRUSTED_FOR_DELEGATION (0x80000)
  set, excluding Domain Controllers (which legitimately use this flag).

Risk:
  - Non-DC account with unconstrained delegation -> high  (-20 pts per group)
  - Computer account with unconstrained delegation -> high (-20 pts)
  - User account with unconstrained delegation    -> critical (-25 pts)
"""

CHECK_NAME = "Unconstrained Delegation"
CHECK_ORDER = 2
CHECK_CATEGORY = ["Kerberos"]

# userAccountControl flags
_UAC_TRUSTED_FOR_DELEGATION = 0x80000   # Unconstrained delegation
_UAC_SERVER_TRUST_ACCOUNT   = 0x2000    # Domain Controller computer account
_UAC_WORKSTATION_TRUST      = 0x1000    # Regular computer account
_UAC_ACCOUNTDISABLE         = 0x2       # Account disabled

_ATTRS = [
    "sAMAccountName",
    "distinguishedName",
    "userAccountControl",
    "objectClass",
    "servicePrincipalName",
    "description",
    "whenCreated",
    "lastLogonTimestamp",
]


def _uac_flag(entry, flag):
    """Return True if the given UAC flag is set on the entry."""
    try:
        uac = int(entry.get("userAccountControl"))
        return bool(uac & flag)
    except Exception:
        return False


def _is_domain_controller(entry):
    """Return True if the account appears to be a Domain Controller."""
    return _uac_flag(entry, _UAC_SERVER_TRUST_ACCOUNT)


def _is_user_account(entry):
    """Return True if this is a regular user account (not computer)."""
    try:
        obj_classes = [c.lower() for c in entry.get("objectClass")]
        return "user" in obj_classes and "computer" not in obj_classes
    except Exception:
        return False


def _is_disabled(entry):
    return _uac_flag(entry, _UAC_ACCOUNTDISABLE)


def run_check(connector, verbose=False):
    """Search for accounts with unconstrained delegation enabled."""
    findings = []

    # Query all accounts (users + computers) with unconstrained delegation bit set
    # Use a bitwise AND filter: userAccountControl with 0x80000
    entries = connector.ldap_search(
        search_filter=(
            "(&"
            "(|(objectClass=user)(objectClass=computer))"
            "(userAccountControl:1.2.840.113556.1.4.803:=524288)"  # 0x80000
            ")"
        ),
        attributes=_ATTRS,
    )

    if not entries:
        if verbose:
            print("  [INFO] No accounts with unconstrained delegation found (or LDAP unavailable).")
        return findings

    user_accounts = []
    computer_accounts = []
    dc_accounts = []

    for entry in entries:
        sam = ""
        try:
            sam = str(entry.get("sAMAccountName"))
        except Exception:  # sAMAccountName may be absent; sam stays as empty string
            pass

        if _is_domain_controller(entry):
            dc_accounts.append(sam)
            continue  # DCs legitimately have this flag

        disabled_suffix = " [DISABLED]" if _is_disabled(entry) else ""

        if _is_user_account(entry):
            user_accounts.append(sam + disabled_suffix)
        else:
            computer_accounts.append(sam + disabled_suffix)

    if verbose:
        print(f"     Domain Controllers (expected, skipped): {len(dc_accounts)}")
        print(f"     User accounts with unconstrained delegation: {len(user_accounts)}")
        print(f"     Computer accounts with unconstrained delegation: {len(computer_accounts)}")

    # ----------------------------------------------------------------
    # User accounts with unconstrained delegation (most severe)
    # ----------------------------------------------------------------
    if user_accounts:
        findings.append({
            "title": "User Accounts with Unconstrained Delegation",
            "severity": "critical",
            "deduction": 25,
            "description": (
                f"{len(user_accounts)} user account(s) have Unconstrained Kerberos Delegation "
                "enabled. When any user authenticates to a service running under such an account, "
                "their full Kerberos TGT is forwarded and cached. An attacker who compromises "
                "one of these accounts can extract all cached TGTs and impersonate any user "
                "including Domain Admins — a technique known as 'TGT Harvesting'."
            ),
            "recommendation": (
                "Replace Unconstrained Delegation with Constrained Delegation (KCD) or "
                "Resource-Based Constrained Delegation (RBCD) for all service accounts. "
                "Mark sensitive accounts (Domain Admins, etc.) with the "
                "'Account is sensitive and cannot be delegated' flag."
            ),
            "details": user_accounts,
        })

    # ----------------------------------------------------------------
    # Computer accounts with unconstrained delegation
    # ----------------------------------------------------------------
    if computer_accounts:
        findings.append({
            "title": "Computer Accounts with Unconstrained Delegation",
            "severity": "high",
            "deduction": 20,
            "description": (
                f"{len(computer_accounts)} computer account(s) (non-DC) have Unconstrained "
                "Kerberos Delegation enabled. If an attacker gains control of any of these "
                "machines, they can coerce a Domain Controller into authenticating to them "
                "(e.g., using PrinterBug / SpoolSample), then extract and abuse the DC's TGT "
                "to perform a full domain compromise (DCSync)."
            ),
            "recommendation": (
                "Migrate these computer accounts to Constrained or Resource-Based Constrained "
                "Delegation. If delegation is not required, disable it entirely by removing "
                "the TRUSTED_FOR_DELEGATION flag from the userAccountControl attribute."
            ),
            "details": computer_accounts,
        })

    return findings
