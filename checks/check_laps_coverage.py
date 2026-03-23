CHECK_NAME = "LAPS Coverage"
CHECK_ORDER = 52
CHECK_CATEGORY = ["Privileged Accounts"]

def run_check(connector, verbose=False):
    """
    Check the percentage of non-DC computer accounts that have a LAPS-managed
    password stored in Active Directory.  Both legacy LAPS (ms-Mcs-AdmPwd) and
    Windows LAPS (msLAPS-Password / msLAPS-EncryptedPassword) are counted.

    Severity thresholds
    -------------------
    critical  : < 25 % covered
    high      : 25 - 49 %
    medium    : 50 - 74 %
    low       : 75 - 89 %
    info      : 90 - 100 % (good posture, no deduction)
    """
    findings = []

    try:
        # ------------------------------------------------------------------ #
        # 1. Enumerate all enabled, non-DC computer accounts                  #
        # ------------------------------------------------------------------ #
        all_computers = connector.ldap_search(
            search_filter=(
                "(&(objectClass=computer)"
                "(!(userAccountControl:1.2.840.113556.1.4.803:=8192))"   # exclude DCs
                "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"      # exclude disabled
                ")"
            ),
            attributes=[
                "cn",
                "distinguishedName",
                "ms-Mcs-AdmPwd",          # Legacy LAPS
                "msLAPS-Password",         # Windows LAPS (cleartext)
                "msLAPS-EncryptedPassword",# Windows LAPS (encrypted)
                "ms-Mcs-AdmPwdExpirationTime",
                "msLAPS-PasswordExpirationTime",
            ],
        )

        if all_computers is None:
            all_computers = []

        total = len(all_computers)

        if total == 0:
            findings.append({
                "title": "LAPS Coverage: No non-DC computer accounts found",
                "severity": "info",
                "deduction": 0,
                "description": (
                    "No enabled, non-DC computer accounts were found in the domain. "
                    "LAPS coverage is not applicable."
                ),
                "recommendation": "No action required.",
                "details": [],
            })
            return findings

        # ------------------------------------------------------------------ #
        # 2. Categorise computers                                             #
        # ------------------------------------------------------------------ #
        covered     = []   # has a LAPS password (either flavour)
        not_covered = []   # no LAPS password detected

        for entry in all_computers:
            cn = entry.get("cn", str(entry))

            has_legacy  = bool(entry.get("ms-Mcs-AdmPwd"))
            has_win_laps = (
                bool(entry.get("msLAPS-Password")) or
                bool(entry.get("msLAPS-EncryptedPassword"))
            )

            if has_legacy or has_win_laps:
                covered.append(cn)
            else:
                not_covered.append(cn)

        covered_count = len(covered)
        pct = (covered_count / total) * 100 if total > 0 else 0.0

        # ------------------------------------------------------------------ #
        # 3. Build the finding                                                 #
        # ------------------------------------------------------------------ #
        summary_line = (
            f"{covered_count} of {total} non-DC computers have a LAPS password "
            f"({pct:.1f}% coverage)."
        )

        if pct >= 90:
            # Good posture — informational only
            findings.append({
                "title": f"LAPS Coverage: {pct:.1f}% ({covered_count}/{total} computers)",
                "severity": "info",
                "deduction": 0,
                "description": (
                    f"LAPS coverage is excellent. {summary_line} "
                    "Local administrator passwords are being managed for the "
                    "vast majority of workstations and servers."
                ),
                "recommendation": (
                    "Maintain current LAPS deployment. Investigate the remaining "
                    f"{len(not_covered)} computer(s) and enrol them in LAPS if possible."
                ),
                "details": (
                    [f"Not covered: {c}" for c in sorted(not_covered)[:50]]
                    if not_covered else ["All non-DC computers are covered."]
                ),
            })

        elif pct >= 75:
            findings.append({
                "title": f"LAPS Coverage Low: {pct:.1f}% ({covered_count}/{total} computers)",
                "severity": "low",
                "deduction": 5,
                "description": (
                    f"LAPS coverage is below the recommended 90%% threshold. {summary_line} "
                    "Computers without LAPS retain a static local Administrator password "
                    "that may be reused across hosts, enabling lateral movement."
                ),
                "recommendation": (
                    "Deploy LAPS (legacy or Windows LAPS) to the remaining "
                    f"{len(not_covered)} computer(s). Prioritise servers and "
                    "privileged-access workstations first."
                ),
                "details": [f"Not covered: {c}" for c in sorted(not_covered)[:100]],
            })

        elif pct >= 50:
            findings.append({
                "title": f"LAPS Coverage Moderate Risk: {pct:.1f}% ({covered_count}/{total} computers)",
                "severity": "medium",
                "deduction": 8,
                "description": (
                    f"LAPS coverage is significantly below the recommended 90%% threshold. "
                    f"{summary_line} A large proportion of computers retain static local "
                    "Administrator passwords, increasing the risk of credential reuse and "
                    "lateral movement attacks (e.g. Pass-the-Hash)."
                ),
                "recommendation": (
                    "Urgently expand LAPS deployment to the remaining "
                    f"{len(not_covered)} computer(s). Consider using Group Policy or "
                    "Microsoft Endpoint Manager to enforce LAPS enrolment."
                ),
                "details": [f"Not covered: {c}" for c in sorted(not_covered)[:100]],
            })

        elif pct >= 25:
            findings.append({
                "title": f"LAPS Coverage High Risk: {pct:.1f}% ({covered_count}/{total} computers)",
                "severity": "high",
                "deduction": 15,
                "description": (
                    f"LAPS coverage is critically low. {summary_line} "
                    "The majority of computers have no managed local Administrator password, "
                    "creating significant lateral movement risk across the estate."
                ),
                "recommendation": (
                    "Deploy LAPS as a priority across the domain. Windows LAPS is built "
                    "into Windows 11 22H2+ and Windows Server 2019+. Legacy LAPS is "
                    "available for older systems via Microsoft Download Center. "
                    "Use Group Policy to enforce enrolment and set password rotation intervals."
                ),
                "details": [f"Not covered: {c}" for c in sorted(not_covered)[:200]],
            })

        else:
            # < 25% — critical
            findings.append({
                "title": f"LAPS Coverage Critical: {pct:.1f}% ({covered_count}/{total} computers)",
                "severity": "critical",
                "deduction": 20,
                "description": (
                    f"LAPS is effectively not deployed across the domain. {summary_line} "
                    "Almost all computers have static, unmanaged local Administrator passwords. "
                    "A single compromised local Administrator credential can lead to "
                    "domain-wide lateral movement."
                ),
                "recommendation": (
                    "Implement LAPS immediately across all non-DC computers. "
                    "Windows LAPS is built into Windows 11 22H2+ and Windows Server 2019+. "
                    "For older systems, deploy legacy LAPS via Group Policy. "
                    "Rotate all local Administrator passwords immediately as a short-term "
                    "mitigation while LAPS is being deployed."
                ),
                "details": [f"Not covered: {c}" for c in sorted(not_covered)[:200]],
            })

        # ------------------------------------------------------------------ #
        # 4. Always append the coverage summary as an informational detail     #
        # ------------------------------------------------------------------ #
        if findings:
            findings[-1]["details"].insert(0, summary_line)

    except Exception as e:
        findings.append({
            "title": "LAPS Coverage: Check encountered an error",
            "severity": "info",
            "deduction": 0,
            "description": f"The LAPS coverage check could not complete: {e}",
            "recommendation": "Run the check manually or verify LDAP connectivity.",
            "details": [str(e)],
        })

    return findings
