"""
checks/check_password_policy.py - Domain Password Policy Check

Evaluates the Default Domain Password Policy for weak settings that could
facilitate brute-force or password-spray attacks.

Risk Criteria:
  - Minimum password length < 8        -> high   (-15 pts)
  - Minimum password length < 12       -> medium  (-8 pts)
  - Password complexity disabled       -> high   (-15 pts)
  - Max password age > 365 days        -> medium  (-8 pts)
  - Max password age = 0 (never expire)-> high   (-15 pts)
  - Lockout threshold = 0 (no lockout) -> critical (-20 pts)
  - Lockout threshold > 10             -> medium  (-8 pts)
  - Lockout observation window < 30min -> low     (-5 pts)
"""

CHECK_NAME = "Domain Password Policy"
CHECK_ORDER = 1
CHECK_CATEGORY = ["Account Hygiene"]
CHECK_WEIGHT   = 20   # max deduction at stake for this check module

# LDAP attributes for the Default Domain Policy (stored on domainDNS object)
_POLICY_ATTRS = [
    "minPwdLength",
    "pwdHistoryLength",
    "pwdProperties",
    "maxPwdAge",
    "minPwdAge",
    "lockoutThreshold",
    "lockoutObservationWindow",
    "lockoutDuration",
    "distinguishedName",
]

# pwdProperties flags
_FLAG_COMPLEXITY = 0x1
_FLAG_REVERSIBLE  = 0x10


def _filetime_to_days(filetime_val):
    """Convert a negative LDAP FileTime (100-ns intervals) to days."""
    try:
        val = int(filetime_val)
        if val == 0:
            return 0  # never expires
        # Negative value = relative time in 100ns intervals
        days = abs(val) / (10_000_000 * 86_400)
        return int(days)
    except (TypeError, ValueError):
        return None


def _filetime_to_minutes(filetime_val):
    """Convert a negative LDAP FileTime to minutes."""
    try:
        val = int(filetime_val)
        if val == 0:
            return 0
        minutes = abs(val) / (10_000_000 * 60)
        return int(minutes)
    except (TypeError, ValueError):
        return None


def run_check(connector, verbose=False):
    """Query and evaluate the Default Domain Password Policy."""
    findings = []
    log = connector.log

    entries = connector.ldap_search(
        search_filter="(objectClass=domainDNS)",
        attributes=_POLICY_ATTRS,
    )

    if not entries:
        log.warning("  [WARN] Could not retrieve domain password policy via LDAP.")
        return findings

    entry = entries[0]

    def _get(attr, default=None):
        try:
            return entry.get(attr)
        except Exception:
            return default

    min_pwd_len           = _get("minPwdLength", 0)
    pwd_history           = _get("pwdHistoryLength", 0)
    pwd_props             = _get("pwdProperties", 0)
    max_pwd_age_raw       = _get("maxPwdAge", -1)
    lockout_threshold     = _get("lockoutThreshold", 0)
    lockout_window_raw    = _get("lockoutObservationWindow", -1800000000)
    lockout_duration_raw  = _get("lockoutDuration", -1800000000)

    max_pwd_age_days    = _filetime_to_days(max_pwd_age_raw)
    lockout_window_mins = _filetime_to_minutes(lockout_window_raw)

    complexity_enabled = bool(int(pwd_props or 0) & _FLAG_COMPLEXITY)
    reversible_enabled = bool(int(pwd_props or 0) & _FLAG_REVERSIBLE)

    log.debug("     Min Password Length  : %s", min_pwd_len)
    log.debug("     Password History     : %s", pwd_history)
    log.debug("     Complexity Enabled   : %s", complexity_enabled)
    log.debug("     Reversible Encryption: %s", reversible_enabled)
    log.debug("     Max Password Age     : %s days (0=never expires)", max_pwd_age_days)
    log.debug("     Lockout Threshold    : %s attempts", lockout_threshold)
    log.debug("     Lockout Window       : %s minutes", lockout_window_mins)

    # ----------------------------------------------------------------
    # Lockout threshold (most critical)
    # ----------------------------------------------------------------
    if lockout_threshold == 0:
        findings.append({
            "title": "Account Lockout Disabled",
            "severity": "critical",
            "deduction": 20,
            "description": (
                "The domain has no account lockout policy configured (lockout threshold = 0). "
                "This allows unlimited authentication attempts against any account, making "
                "password spraying and brute-force attacks trivially easy."
            ),
            "recommendation": (
                "Configure an account lockout threshold of 5-10 invalid attempts. "
                "Use Fine-Grained Password Policies (PSOs) if different thresholds "
                "are needed for different account tiers."
            ),
            "details": ["lockoutThreshold = 0 (no lockout policy applied)"],
        })
    elif lockout_threshold > 10:
        findings.append({
            "title": "Account Lockout Threshold Too High",
            "severity": "medium",
            "deduction": 8,
            "description": (
                f"The account lockout threshold is set to {lockout_threshold} invalid attempts. "
                "A high threshold still permits password-spray attacks before accounts lock."
            ),
            "recommendation": (
                "Reduce the lockout threshold to 5-10 invalid attempts. "
                "Pair this with a reasonable observation window (15-30 minutes)."
            ),
            "details": [f"lockoutThreshold = {lockout_threshold}"],
        })

    # ----------------------------------------------------------------
    # Lockout observation window
    # ----------------------------------------------------------------
    if lockout_threshold != 0 and lockout_window_mins is not None and lockout_window_mins < 30:
        findings.append({
            "title": "Lockout Observation Window Too Short",
            "severity": "low",
            "deduction": 5,
            "description": (
                f"The lockout observation window is {lockout_window_mins} minutes. "
                "A short window allows attackers to attempt passwords in rapid bursts "
                "without triggering a lockout."
            ),
            "recommendation": (
                "Set the lockout observation window to at least 30 minutes."
            ),
            "details": [f"lockoutObservationWindow = {lockout_window_mins} minutes"],
        })

    # ----------------------------------------------------------------
    # Minimum password length
    # ----------------------------------------------------------------
    if min_pwd_len is not None:
        if min_pwd_len < 8:
            findings.append({
                "title": "Minimum Password Length Too Short (< 8)",
                "severity": "high",
                "deduction": 15,
                "description": (
                    f"The minimum password length is set to {min_pwd_len} characters. "
                    "Very short passwords are extremely vulnerable to brute-force attacks, "
                    "especially against offline NTLM hash cracking."
                ),
                "recommendation": (
                    "Set the minimum password length to at least 12 characters. "
                    "Microsoft recommends 14+ characters for privileged accounts."
                ),
                "details": [f"minPwdLength = {min_pwd_len}"],
            })
        elif min_pwd_len < 12:
            findings.append({
                "title": "Minimum Password Length Below Recommended (< 12)",
                "severity": "medium",
                "deduction": 8,
                "description": (
                    f"The minimum password length is {min_pwd_len} characters. "
                    "NIST SP 800-63B and Microsoft best practices recommend at least "
                    "12 characters to resist offline cracking."
                ),
                "recommendation": (
                    "Increase the minimum password length to 12 or more characters."
                ),
                "details": [f"minPwdLength = {min_pwd_len}"],
            })

    # ----------------------------------------------------------------
    # Password complexity
    # ----------------------------------------------------------------
    if not complexity_enabled:
        findings.append({
            "title": "Password Complexity Disabled",
            "severity": "high",
            "deduction": 15,
            "description": (
                "Password complexity requirements are disabled on the domain. "
                "Without complexity enforcement, users may set dictionary words or "
                "simple patterns as passwords, dramatically increasing attack surface."
            ),
            "recommendation": (
                "Enable password complexity requirements (pwdProperties flag 0x1). "
                "Complexity requires passwords to contain characters from at least "
                "3 of the following: uppercase, lowercase, digits, special characters."
            ),
            "details": [f"pwdProperties = {pwd_props} (complexity bit not set)"],
        })

    # ----------------------------------------------------------------
    # Password expiry
    # ----------------------------------------------------------------
    if max_pwd_age_days == 0:
        findings.append({
            "title": "Passwords Never Expire",
            "severity": "high",
            "deduction": 15,
            "description": (
                "The maximum password age is set to 0, meaning domain passwords never "
                "expire. If an account is compromised, the attacker retains access "
                "indefinitely unless an administrator manually resets the password."
            ),
            "recommendation": (
                "Configure a maximum password age of 90-365 days. "
                "Consider adopting NIST guidance: pair long passphrases with "
                "breach-detection rather than forced periodic rotation."
            ),
            "details": ["maxPwdAge = 0 (passwords never expire)"],
        })
    elif max_pwd_age_days is not None and max_pwd_age_days > 365:
        findings.append({
            "title": "Maximum Password Age Exceeds 365 Days",
            "severity": "medium",
            "deduction": 8,
            "description": (
                f"Passwords may remain valid for up to {max_pwd_age_days} days. "
                "Stale passwords increase the window of exposure if credentials are "
                "compromised."
            ),
            "recommendation": (
                "Reduce the maximum password age to 90-365 days."
            ),
            "details": [f"maxPwdAge = {max_pwd_age_days} days"],
        })

    # ----------------------------------------------------------------
    # Reversible encryption
    # ----------------------------------------------------------------
    if reversible_enabled:
        findings.append({
            "title": "Reversible Password Encryption Enabled",
            "severity": "critical",
            "deduction": 20,
            "description": (
                "The domain is configured to store passwords using reversible encryption. "
                "This is functionally equivalent to storing plaintext passwords in the "
                "Active Directory database and represents a severe security risk."
            ),
            "recommendation": (
                "Disable reversible encryption immediately "
                "(clear the 0x10 bit in pwdProperties). "
                "All users must change their passwords after this change takes effect."
            ),
            "details": [f"pwdProperties = {pwd_props} (reversible encryption bit is set)"],
        })

    return findings
