"""
checks/check_optional_features.py - Optional AD Features checks

Checks:
  - AD Recycle Bin: Whether the feature is enabled                               -10
  - Privileged Access Management (PAM): Whether PAM is enabled                  -5
"""

CHECK_NAME = "Optional Features"
CHECK_ORDER = 16
CHECK_CATEGORY = ["Domain Hygiene"]
CHECK_WEIGHT   = 10   # max deduction at stake for this check module

def run_check(connector, verbose=False):
    findings = []
    log = connector.log

    features_dn = (
        "CN=Optional Features,CN=Directory Service,CN=Windows NT,"
        "CN=Services,CN=Configuration," + connector.base_dn
    )

    try:
        features = connector.ldap_search(
            features_dn,
            "(objectClass=msDS-OptionalFeature)",
            ["cn", "msDS-OptionalFeatureFlags", "msDS-OptionalFeatureGUID"],
            scope="ONELEVEL",
        ) or []
    except Exception as exc:
        log.warning("[OptionalFeatures] LDAP error: %s", exc)
        return findings

    feature_names = {f.get("cn", "").lower(): f for f in features}

    # AD Recycle Bin
    recycle_bin_enabled = False
    for fname, fobj in feature_names.items():
        if "recycle" in fname:
            recycle_bin_enabled = True
            break

    if not recycle_bin_enabled:
        findings.append({
            "title": "AD Recycle Bin Not Enabled",
            "severity": "medium",
            "deduction": 10,
            "description": (
                "The Active Directory Recycle Bin optional feature is not enabled. "
                "Without it, accidentally deleted AD objects (users, groups, computers) "
                "cannot be easily recovered and may require authoritative restore from backup, "
                "causing significant downtime."
            ),
            "recommendation": (
                "Enable the AD Recycle Bin using: "
                "Enable-ADOptionalFeature 'Recycle Bin Feature' "
                "-Scope ForestOrConfigurationSet -Target <forest_root_domain> "
                "Note: This requires Forest Functional Level 2008R2 or higher and cannot be undone."
            ),
            "details": [],
        })
    else:
        log.debug("[OptionalFeatures] AD Recycle Bin is enabled.")

    # Privileged Access Management (PAM)
    pam_enabled = False
    for fname, fobj in feature_names.items():
        if "privileged" in fname or "pam" in fname:
            pam_enabled = True
            break

    if not pam_enabled:
        findings.append({
            "title": "Privileged Access Management (PAM) Feature Not Enabled",
            "severity": "low",
            "deduction": 5,
            "description": (
                "The Privileged Access Management (PAM) optional feature is not enabled. "
                "PAM enables time-based group memberships (shadow principals) so privileged "
                "access can be granted temporarily and automatically expires, reducing the "
                "standing privilege attack surface."
            ),
            "recommendation": (
                "Consider enabling PAM if using Microsoft Identity Manager (MIM) or a "
                "third-party PAM solution that supports AD shadow principals. "
                "Requires Forest Functional Level 2016 or higher. "
                "Enable with: Enable-ADOptionalFeature 'Privileged Access Management Feature' "
                "-Scope ForestOrConfigurationSet -Target <forest_root_domain>"
            ),
            "details": [],
        })
    else:
        log.debug("[OptionalFeatures] PAM feature is enabled.")

    return findings
