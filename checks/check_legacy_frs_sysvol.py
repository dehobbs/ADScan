CHECK_NAME = "Legacy FRS SYSVOL Replication"
CHECK_ORDER = 71
CHECK_CATEGORY = ["Domain Hygiene"]

# msDFSR-Flags values for the domain SYSVOL migration state
# These are stored on CN=DFSR-GlobalSettings,CN=System,<domain>
# and on each DC's CN=SYSVOL Subscription object.
#
# Domain controller migration state values (msDFSR-Flags):
#   0 = Start (FRS still in use — migration not begun)
#   1 = Prepared (DFSR created but FRS still authoritative)
#   2 = Redirected (DFSR authoritative; FRS stopped)
#   3 = Eliminated (FRS objects removed; fully migrated)

MIGRATION_STATES = {
    0: "START — FRS in use, migration not started",
    1: "PREPARED — DFSR created, FRS still authoritative",
    2: "REDIRECTED — DFSR authoritative, FRS stopped",
    3: "ELIMINATED — fully migrated to DFSR",
}


def run_check(connector, verbose=False):
    findings = []

    try:
        # Method 1: Check DFSR global settings object for migration state
        dfsr_dn = "CN=DFSR-GlobalSettings,CN=System," + connector.base_dn

        dfsr_results = connector.ldap_search(
            search_filter="(objectClass=msDFSR-GlobalSettings)",
            search_base=dfsr_dn,
            attributes=["msDFSR-Flags", "cn"],
        )

        # Method 2: Look for the FRS replica set (presence = FRS in use or migrating)
        frs_dn = "CN=File Replication Service,CN=System," + connector.base_dn
        frs_results = connector.ldap_search(
            search_filter="(objectClass=nTFRSReplicaSet)",
            search_base=frs_dn,
            attributes=["cn", "fRSReplicaSetType"],
        )

        # Method 3: Check DFSR subscription state per DC
        dfsr_sub_results = connector.ldap_search(
            search_filter="(objectClass=msDFSR-Subscription)",
            attributes=["cn", "msDFSR-Flags", "msDFSR-RootPath", "msDFSR-Enabled"],
        )

        has_frs = bool(frs_results)
        has_dfsr = bool(dfsr_results) or bool(dfsr_sub_results)

        # Parse migration state from global settings
        global_state = None
        if dfsr_results:
            for entry in dfsr_results:
                attrs = entry.get("attributes", {}) if isinstance(entry, dict) else {}
                flags = attrs.get("msDFSR-Flags")
                if flags is not None:
                    try:
                        global_state = int(flags)
                    except Exception:
                        pass
                    break

        # Determine situation
        if not has_frs and not has_dfsr:
            # Can't determine — report as informational
            findings.append({
                "title": "Legacy FRS SYSVOL: Unable to determine replication method",
                "severity": "info",
                "deduction": 0,
                "description": (
                    "Neither FRS nor DFSR replication objects could be found in the domain. "
                    "This may indicate insufficient permissions or a non-standard configuration."
                ),
                "recommendation": (
                    "Manually verify SYSVOL replication method: "
                    "dfsrmig /getmigrationstate"
                ),
                "details": [],
            })
            return findings

        if has_frs and global_state is None:
            # FRS objects exist but no DFSR migration started
            findings.append({
                "title": "SYSVOL Replication: FRS in use — migration to DFSR not started",
                "severity": "high",
                "deduction": 10,
                "description": (
                    "SYSVOL is still replicating using the deprecated File Replication Service (FRS). "
                    "FRS was deprecated in Windows Server 2008 R2 and removed in Windows Server 2022. "
                    "FRS is unreliable, has known data corruption issues, and lacks the "
                    "monitoring capabilities of DFSR. It also requires higher domain functional levels "
                    "to be disabled."
                ),
                "recommendation": (
                    "Migrate SYSVOL replication from FRS to DFSR using the dfsrmig tool:\n"
                    "1. dfsrmig /SetGlobalState 1  (Prepared)\n"
                    "2. dfsrmig /SetGlobalState 2  (Redirected)\n"
                    "3. dfsrmig /SetGlobalState 3  (Eliminated)\n"
                    "Requires Windows Server 2008 domain functional level or higher. "
                    "Full guide: https://docs.microsoft.com/en-us/windows-server/storage/dfs-replication/migrate-sysvol-to-dfsr"
                ),
                "details": [
                    "FRS replica set objects detected in CN=File Replication Service,CN=System",
                    "No DFSR global settings object found — migration has not been initiated",
                ],
            })

        elif has_frs and global_state in (0, 1):
            # Mid-migration / stalled
            state_label = MIGRATION_STATES.get(global_state, f"unknown ({global_state})")
            findings.append({
                "title": (
                    f"SYSVOL Replication: Mid-migration — state: {state_label}"
                ),
                "severity": "medium",
                "deduction": 8,
                "description": (
                    f"The SYSVOL migration from FRS to DFSR is in an intermediate state: "
                    f"'{state_label}'. The migration appears to have stalled and has not "
                    f"reached the Eliminated state (state 3). "
                    "Stalled migrations can cause SYSVOL inconsistencies, GPO replication "
                    "failures, and authentication issues."
                ),
                "recommendation": (
                    "Resume and complete the DFSR migration:\n"
                    f"Current state: {global_state} ({state_label})\n"
                    "Run: dfsrmig /GetMigrationState\n"
                    "Continue: dfsrmig /SetGlobalState 2 (then 3) once all DCs are prepared."
                ),
                "details": [
                    f"Global DFSR migration state: {global_state} — {state_label}",
                    "FRS replica sets still present: migration incomplete",
                ],
            })

        elif global_state == 2:
            findings.append({
                "title": "SYSVOL Replication: DFSR Redirected — FRS still present",
                "severity": "low",
                "deduction": 3,
                "description": (
                    "SYSVOL is in the 'Redirected' state — DFSR is now authoritative for SYSVOL "
                    "replication, but FRS objects have not been eliminated. "
                    "The migration should be completed to state 3 (Eliminated) to remove FRS."
                ),
                "recommendation": (
                    "Complete the migration: dfsrmig /SetGlobalState 3"
                ),
                "details": [
                    "DFSR migration state: 2 (Redirected)",
                    "Action: run dfsrmig /SetGlobalState 3 to eliminate FRS",
                ],
            })

        elif global_state == 3:
            findings.append({
                "title": "SYSVOL Replication: DFSR — fully migrated",
                "severity": "info",
                "deduction": 0,
                "description": (
                    "SYSVOL is fully migrated to DFSR (state 3: Eliminated). "
                    "FRS is no longer in use. This is the recommended configuration."
                ),
                "recommendation": "No action required.",
                "details": ["DFSR migration state: 3 (Eliminated) — fully migrated"],
            })

        elif not has_frs and has_dfsr:
            # DFSR present, no FRS — good
            findings.append({
                "title": "SYSVOL Replication: DFSR in use — no FRS detected",
                "severity": "info",
                "deduction": 0,
                "description": "SYSVOL is using DFSR replication. FRS is not in use.",
                "recommendation": "No action required.",
                "details": [],
            })

    except Exception as e:
        findings.append({
            "title": "Legacy FRS SYSVOL: Check encountered an error",
            "severity": "info",
            "deduction": 0,
            "description": f"The check could not complete: {e}",
            "recommendation": "Verify LDAP connectivity and permissions to CN=System.",
            "details": [str(e)],
        })

    return findings
