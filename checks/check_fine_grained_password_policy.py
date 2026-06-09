"""
checks/check_fine_grained_password_policy.py - Fine-Grained Password Policy (PSO) Check

The Default Domain Password Policy (evaluated by check_password_policy.py) governs
every account that is NOT covered by a Fine-Grained Password Policy. FGPPs — stored
as Password Settings Objects (PSOs) of objectClass `msDS-PasswordSettings` under
`CN=Password Settings Container,CN=System,<domain>` — override the default policy
for the specific users and groups they are linked to (via msDS-PSOAppliesTo), with
the lowest msDS-PasswordSettingsPrecedence winning when several apply.

PSOs are a common blind spot: an organisation can have a hardened default domain
policy yet a PSO that quietly exempts service accounts or VIPs from lockout, length,
or complexity. A weak PSO linked to a privileged group is especially dangerous.

This check enumerates every PSO and evaluates it against the same thresholds the
default-policy check uses. A PSO that is weaker than recommended raises a finding;
a PSO linked to a privileged principal escalates the description emphasis.

Risk Criteria (per PSO, worst weakness drives the finding severity):
  - Lockout threshold = 0 (no lockout)        -> critical (-20 pts)
  - Reversible encryption enabled             -> critical (-20 pts)
  - Minimum password length < 15             -> high     (-15 pts)
  - Password complexity disabled              -> high     (-15 pts)
  - Maximum password age = never expires      -> high     (-15 pts)
  - Maximum password age > 365 days           -> medium   (-8 pts)
  - Minimum password age = 0                  -> medium   (-8 pts)
  - Lockout threshold > 10                    -> medium   (-8 pts)
  - Lockout observation window < 30 minutes   -> low      (-5 pts)
"""

CHECK_NAME     = "Fine-Grained Password Policies (PSO)"
CHECK_ORDER    = 2
CHECK_CATEGORY = ["Account Hygiene"]
CHECK_WEIGHT   = 15   # max deduction at stake for this check module

# pwdProperties is a domain-policy bitmask; PSOs use dedicated boolean attributes
# instead, so no flag constants are needed here.

# msDS-PasswordSettings attributes to retrieve for each PSO
_PSO_ATTRS = [
    "cn",
    "name",
    "distinguishedName",
    "msDS-PasswordSettingsPrecedence",
    "msDS-MinimumPasswordLength",
    "msDS-PasswordComplexityEnabled",
    "msDS-PasswordHistoryLength",
    "msDS-MinimumPasswordAge",
    "msDS-MaximumPasswordAge",
    "msDS-LockoutThreshold",
    "msDS-LockoutObservationWindow",
    "msDS-LockoutDuration",
    "msDS-PasswordReversibleEncryptionEnabled",
    "msDS-PSOAppliesTo",
]

# Privileged principal CNs — a PSO linked to any of these is higher risk
_PRIVILEGED_PRINCIPALS = {
    "domain admins", "enterprise admins", "schema admins", "administrators",
    "account operators", "backup operators", "server operators", "print operators",
    "dnsadmins", "group policy creator owners", "administrator", "krbtgt",
}

# Severity ranking for picking the worst weakness in a PSO
_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_SEV_DEDUCTION = {"critical": 20, "high": 15, "medium": 8, "low": 5, "info": 0}

# A maxPwdAge this large (in days) is the FGPP "never expires" sentinel
# (msDS-MaximumPasswordAge stored as the Int64 minimum, 0x8000000000000000).
_NEVER_EXPIRES_DAYS = 36_500   # ~100 years


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _to_int(val, default=None):
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


def _as_bool(val):
    """Normalise an ldap3 boolean attribute (bool / 'TRUE' / 1) to a Python bool."""
    if isinstance(val, bool):
        return val
    if val is None:
        return False
    return str(val).strip().lower() in ("true", "1", "yes")


def _filetime_to_days(val):
    """Convert an LDAP FileTime interval (negative 100-ns units) to whole days.

    Returns None if the value is missing/unparseable, 0 if the raw value is 0.
    """
    n = _to_int(val)
    if n is None:
        return None
    if n == 0:
        return 0
    return int(abs(n) / (10_000_000 * 86_400))


def _filetime_to_minutes(val):
    """Convert an LDAP FileTime interval (negative 100-ns units) to whole minutes."""
    n = _to_int(val)
    if n is None:
        return None
    if n == 0:
        return 0
    return int(abs(n) / (10_000_000 * 60))


def _as_list(val):
    if val is None:
        return []
    return val if isinstance(val, list) else [val]


def _cn_from_dn(dn):
    """Extract the leading CN value from a distinguishedName for display."""
    try:
        first = str(dn).split(",", 1)[0]
        if "=" in first:
            return first.split("=", 1)[1]
        return first
    except Exception:
        return str(dn)


def _worst_severity(weaknesses):
    """Return the highest-ranked severity among a list of (severity, text) tuples."""
    worst = "info"
    for sev, _ in weaknesses:
        if _SEV_RANK.get(sev, 0) > _SEV_RANK.get(worst, 0):
            worst = sev
    return worst


# ---------------------------------------------------------------------------
# Pure evaluation logic (no LDAP) — kept separate so it is unit-testable
# ---------------------------------------------------------------------------

def evaluate_pso(pso):
    """Evaluate a single PSO attribute dict.

    Returns a list of (severity, description) tuples for each weak setting found.
    An empty list means the PSO meets all recommended thresholds.
    """
    weaknesses = []

    min_len  = _to_int(pso.get("msDS-MinimumPasswordLength"))
    complex_ = _as_bool(pso.get("msDS-PasswordComplexityEnabled"))
    reversible = _as_bool(pso.get("msDS-PasswordReversibleEncryptionEnabled"))
    lockout_threshold = _to_int(pso.get("msDS-LockoutThreshold"))
    max_age_days = _filetime_to_days(pso.get("msDS-MaximumPasswordAge"))
    min_age_days = _filetime_to_days(pso.get("msDS-MinimumPasswordAge"))
    lockout_window_mins = _filetime_to_minutes(pso.get("msDS-LockoutObservationWindow"))

    # Lockout threshold (most critical)
    if lockout_threshold == 0:
        weaknesses.append((
            "critical",
            "Account lockout disabled (msDS-LockoutThreshold = 0) — permits unlimited "
            "password-spray / brute-force attempts against linked accounts.",
        ))
    elif lockout_threshold is not None and lockout_threshold > 10:
        weaknesses.append((
            "medium",
            f"Lockout threshold is high ({lockout_threshold}) — still permits "
            "password spraying before accounts lock.",
        ))

    # Reversible encryption
    if reversible:
        weaknesses.append((
            "critical",
            "Reversible password encryption enabled "
            "(msDS-PasswordReversibleEncryptionEnabled = TRUE) — functionally equivalent "
            "to storing plaintext passwords for linked accounts.",
        ))

    # Minimum length
    if min_len is not None and min_len < 15:
        weaknesses.append((
            "high",
            f"Minimum password length is {min_len} (recommended >= 15).",
        ))

    # Complexity
    if not complex_:
        weaknesses.append((
            "high",
            "Password complexity disabled (msDS-PasswordComplexityEnabled = FALSE).",
        ))

    # Maximum password age
    if max_age_days is not None and (max_age_days == 0 or max_age_days >= _NEVER_EXPIRES_DAYS):
        weaknesses.append((
            "high",
            "Passwords never expire (msDS-MaximumPasswordAge = never).",
        ))
    elif max_age_days is not None and max_age_days > 365:
        weaknesses.append((
            "medium",
            f"Maximum password age is {max_age_days} days (recommended <= 365).",
        ))

    # Minimum password age
    if min_age_days == 0:
        weaknesses.append((
            "medium",
            "Minimum password age is 0 — renders password history ineffective "
            "(users can cycle through history in one session).",
        ))

    # Lockout observation window
    if lockout_threshold not in (0, None) and lockout_window_mins is not None and lockout_window_mins < 30:
        weaknesses.append((
            "low",
            f"Lockout observation window is {lockout_window_mins} minutes "
            "(recommended >= 30) — allows rapid-burst password attempts.",
        ))

    return weaknesses


# ---------------------------------------------------------------------------
# Main check
# ---------------------------------------------------------------------------

def run_check(connector, verbose=False):
    findings = []
    log = connector.log

    try:
        psos = connector.ldap_search(
            search_filter="(objectClass=msDS-PasswordSettings)",
            attributes=_PSO_ATTRS,
        ) or []

        log.debug("     Fine-Grained Password Policies found: %d", len(psos))

        if not psos:
            findings.append({
                "title": "No Fine-Grained Password Policies Defined",
                "severity": "info",
                "deduction": 0,
                "description": (
                    "No Fine-Grained Password Policies (PSOs) were found in this domain. "
                    "All accounts are therefore governed by the Default Domain Password "
                    "Policy (see the Domain Password Policy finding). This is not a "
                    "vulnerability — it is reported for completeness so the absence of "
                    "PSO-based exemptions is documented."
                ),
                "recommendation": (
                    "If stricter requirements are needed for privileged accounts, consider "
                    "introducing a PSO that enforces a longer minimum length and lower "
                    "lockout threshold for Tier-0 groups."
                ),
                "details": [],
            })
            return findings

        weak_count = 0
        for pso in psos:
            name = pso.get("cn") or pso.get("name") or _cn_from_dn(pso.get("distinguishedName"))
            precedence = _to_int(pso.get("msDS-PasswordSettingsPrecedence"))
            applies_to = [_cn_from_dn(d) for d in _as_list(pso.get("msDS-PSOAppliesTo"))]
            applies_priv = [a for a in applies_to if a.lower() in _PRIVILEGED_PRINCIPALS]

            weaknesses = evaluate_pso(pso)
            if not weaknesses:
                log.debug("     [OK] PSO '%s' meets recommended thresholds", name)
                continue

            weak_count += 1
            severity = _worst_severity(weaknesses)
            deduction = _SEV_DEDUCTION.get(severity, 0)

            priv_note = ""
            if applies_priv:
                # A weak PSO linked to a privileged principal is materially worse;
                # ensure it never scores below high.
                if _SEV_RANK[severity] < _SEV_RANK["high"]:
                    severity = "high"
                    deduction = _SEV_DEDUCTION["high"]
                priv_note = (
                    f" This PSO is linked to PRIVILEGED principal(s): "
                    f"{', '.join(applies_priv)}, so the weak setting(s) directly relax "
                    "password requirements for high-value accounts."
                )

            applies_str = ", ".join(applies_to) if applies_to else "(not linked to any principal)"
            detail_lines = [f"- {text}" for _, text in weaknesses]
            detail_lines.append(f"Precedence: {precedence if precedence is not None else 'unknown'}")
            detail_lines.append(f"Applies to: {applies_str}")

            findings.append({
                "title": f"Weak Fine-Grained Password Policy: {name}",
                "severity": severity,
                "deduction": deduction,
                "description": (
                    f"The Fine-Grained Password Policy (PSO) '{name}' overrides the Default "
                    "Domain Password Policy for the principals it is linked to, and contains "
                    f"{len(weaknesses)} setting(s) weaker than recommended.{priv_note} "
                    "PSOs are a frequent blind spot: a hardened default policy can be silently "
                    "undermined by a permissive PSO."
                ),
                "recommendation": (
                    "Review and harden this PSO to match (or exceed) the Default Domain "
                    "Password Policy: enforce a lockout threshold of 5-10, a minimum length "
                    "of 15+, complexity enabled, and disable reversible encryption. Confirm "
                    "the linked principals genuinely require a separate policy; remove the PSO "
                    "if it exists only to exempt accounts from domain-wide requirements."
                ),
                "details": detail_lines,
            })

        if weak_count == 0:
            findings.append({
                "title": "Fine-Grained Password Policies: No Issues Found",
                "severity": "info",
                "deduction": 0,
                "description": (
                    f"All {len(psos)} Fine-Grained Password Policy (PSO) object(s) meet the "
                    "recommended thresholds for length, complexity, lockout, and expiry."
                ),
                "recommendation": (
                    "Continue to review PSO membership and settings periodically, especially "
                    "any PSO linked to privileged groups."
                ),
                "details": [],
            })

    except Exception as e:
        findings.append({
            "title": "Fine-Grained Password Policies: Check Encountered an Error",
            "severity": "info",
            "deduction": 0,
            "description": f"The check could not complete: {e}",
            "recommendation": "Verify LDAP connectivity and read access to the Password Settings Container.",
            "details": [str(e)],
        })

    return findings
