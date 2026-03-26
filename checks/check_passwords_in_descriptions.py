CHECK_NAME     = "Passwords in Descriptions"
CHECK_ORDER    = 61
CHECK_CATEGORY = ["Account Hygiene"]
CHECK_WEIGHT   = 0    # info-only check, no deduction possible

import re

# Keywords that strongly suggest a credential is stored in the description field
CREDENTIAL_KEYWORDS = [
    "password", "passwd", "pwd", "pass ", "p@ss",
    "secret", "cred", "credential",
    "login", "logon",
    "temp123", "welcome", "changeme", "letmein", "admin123", "default",
]

# Patterns that look like passwords (e.g. "Pw: abc123", "pass=abc", etc.)
CREDENTIAL_PATTERNS = [
    re.compile(r'(?i)(password|passwd|pwd|pass)\s*[=:\-]\s*\S+'),
    re.compile(r'(?i)(cred(ential)?|secret|login)\s*[=:\-]\s*\S+'),
    re.compile(r'(?i)temp\s*(pass|pw|password)'),
]

# Pattern to match the actual credential value after a keyword=value separator
# Used by _redact_desc to replace the value with [[REDACTED]]
_REDACT_PATTERN = re.compile(
    r'(?i)(password|passwd|pwd|pass|cred(?:ential)?|secret|login)\s*([=:\-])\s*(\S+)'
)


def _get_attr(entry, attr, default=""):
    """Safely read an ldap3 Entry attribute value."""
    try:
        val = entry.get(attr)
        if val is None:
            return default
        if isinstance(val, list):
            return " ".join(str(v) for v in val)
        return str(val)
    except Exception:
        return default


def _looks_like_credential(description):
    if not description:
        return False, None
    desc_lower = description.lower()
    for kw in CREDENTIAL_KEYWORDS:
        if kw in desc_lower:
            return True, kw
    for pattern in CREDENTIAL_PATTERNS:
        m = pattern.search(description)
        if m:
            return True, m.group(0)
    return False, None


def _redact_desc(desc):
    """Return a copy of desc with credential values replaced by [[REDACTED]].

    For structured matches like 'pass=Secret123' the value portion is replaced.
    For keyword-only matches the whole description is left as-is since there is
    no isolated value to redact — the caller should still show the description
    so the analyst can see context, but any structured credential value is masked.
    """
    redacted = _REDACT_PATTERN.sub(
        lambda m: f"{m.group(1)}{m.group(2)}[[REDACTED]]",
        desc
    )
    return redacted


def run_check(connector, verbose=False):
    findings = []
    try:
        # Search both user accounts AND computer accounts
        search_configs = [
            {
                "label": "user",
                "filter": "(&(objectCategory=person)(objectClass=user)(description=*))",
            },
            {
                "label": "computer",
                "filter": "(&(objectClass=computer)(description=*))",
            },
        ]

        flagged = []

        for cfg in search_configs:
            results = connector.ldap_search(
                search_filter=cfg["filter"],
                attributes=[
                    "sAMAccountName",
                    "distinguishedName",
                    "description",
                    "adminCount",
                    "userAccountControl",
                ],
            )
            if not results:
                continue

            for entry in results:
                # ldap_search returns ldap3 Entry objects
                sam   = _get_attr(entry, "sAMAccountName", "unknown")
                dn    = _get_attr(entry, "distinguishedName")
                desc  = _get_attr(entry, "description")

                try:
                    admin_count = int(entry.get("adminCount") or 0)
                except Exception:
                    admin_count = 0

                try:
                    uac = int(entry.get("userAccountControl") or 0)
                except Exception:
                    uac = 0

                disabled = bool(uac & 0x2)

                hit, match_text = _looks_like_credential(desc)
                if hit:
                    flagged.append({
                        "sam":      sam,
                        "dn":       dn,
                        "desc":     desc[:120],
                        "match":    match_text,
                        "is_admin": bool(admin_count),
                        "status":   "DISABLED" if disabled else "ENABLED",
                        "type":     cfg["label"],
                    })

        if not flagged:
            findings.append({
                "title":       "Passwords in Descriptions: No credentials found",
                "severity":    "info",
                "deduction":   0,
                "description": (
                    "No user or computer accounts appear to have credentials "
                    "stored in their Description field."
                ),
                "recommendation": "Continue to audit description fields periodically.",
                "details": [],
            })
            return findings

        admin_hits = [f for f in flagged if f["is_admin"]]
        user_hits  = [f for f in flagged if not f["is_admin"]]

        detail_lines = []
        for f in flagged:
            tag = "[ADMIN] " if f["is_admin"] else ""
            # Always redact the full description -- it contains credential material.
            # The match keyword is also suppressed to avoid leaking the value.
            detail_lines.append(
                f"{tag}{f['type'].upper()}: {f['sam']} ({f['status']}) "
                f"| desc: [[REDACTED]]"
            )

        severity  = "critical" if admin_hits else "high"
        deduction = 20 if admin_hits else 15

        findings.append({
            "title": (
                f"Credentials Found in Description Fields: {len(flagged)} account(s) "
                f"({len(admin_hits)} admin, {len(user_hits)} standard)"
            ),
            "severity":  severity,
            "deduction": deduction,
            "description": (
                "One or more Active Directory accounts have what appears to be a "
                "password or credential stored in the Description field. "
                "The Description attribute is readable by all authenticated users "
                "by default, making this a significant information disclosure risk. "
                "Admin accounts with credentials in descriptions are particularly critical."
            ),
            "recommendation": (
                "Immediately remove any credentials from Description fields. "
                "Rotate the passwords of any accounts whose credentials were exposed. "
                "Use a password manager or PAM solution for credential storage. "
                "Consider auditing description fields regularly with: "
                "Get-ADUser -Filter * -Properties Description | "
                "Where-Object {$_.Description -match 'pass|pwd|cred'}"
            ),
            "details": detail_lines,
        })

    except Exception as e:
        findings.append({
            "title":       "Passwords in Descriptions: Check encountered an error",
            "severity":    "info",
            "deduction":   0,
            "description": f"The check could not complete: {e}",
            "recommendation": "Verify LDAP connectivity and permissions.",
            "details": [str(e)],
        })

    return findings
