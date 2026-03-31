"""
checks/check_bloodhound.py - BloodHound Data Collection

Runs the BloodHound Python ingestor (bloodhound-python) to collect a full
snapshot of the Active Directory environment. The resulting ZIP archive is
saved to Reports/Artifacts/ for import into BloodHound for graph-based
attack path analysis.

This is a data collection step, not a security check — it produces no
scored findings. The ingestor output is saved regardless of what other
checks find.

Collection method: All (Group, LocalAdmin, Session, Trusts, ACL, DCOM, RDP,
PSRemote, ObjectProps, Default)
"""

CHECK_NAME     = "BloodHound Data Collection"
CHECK_ORDER    = 99
CHECK_CATEGORY = ["Domain Hygiene"]
CHECK_WEIGHT   = 0

import os
import subprocess

from lib.tools import ensure_tool


def _build_auth_args(connector):
    username = getattr(connector, "username", None) or ""
    password = getattr(connector, "password", None)
    nt_hash  = getattr(connector, "nt_hash", None)
    lm_hash  = getattr(connector, "lm_hash", "") or ""

    args = ["-u", username]
    if nt_hash:
        hash_str = f"{lm_hash}:{nt_hash}" if lm_hash else nt_hash
        args += ["--hashes", hash_str]
    elif password:
        args += ["-p", password]
    else:
        args += ["-no-pass"]
    return args


def run_check(connector, verbose=False):
    findings = []
    log      = connector.log

    bh_exe = ensure_tool("bloodhound")
    if bh_exe is None:
        findings.append({
            "title": "BloodHound Data Collection — bloodhound-python Not Found",
            "severity": "info",
            "deduction": 0,
            "description": (
                "bloodhound-python is required for BloodHound data collection but was not found. "
                "Install it with: uv tool install bloodhound  "
                "or run: python adscan.py --setup-tools"
            ),
            "recommendation": "Run: python adscan.py --setup-tools",
            "details": [],
        })
        return findings

    domain  = getattr(connector, "domain", None)
    dc_host = getattr(connector, "dc_host", None)
    if not domain or not dc_host:
        log.warning("  [WARN] No domain or DC host configured — skipping BloodHound collection.")
        return findings

    artifacts_dir = getattr(connector, "artifacts_dir", "Reports/Artifacts")
    os.makedirs(artifacts_dir, exist_ok=True)

    # Use the scan timestamp as the output file prefix so the ZIP is
    # identifiable alongside other artifacts from the same scan.
    run_ts = getattr(connector, "scan_timestamp", "bloodhound")

    cmd = [
        bh_exe,
        "--zip",
        "-c", "All",
        "-d", domain,
        "-dc", dc_host,
        "-op", run_ts,
        *_build_auth_args(connector),
    ]

    log.info("  [*] Starting BloodHound collection (this may take several minutes)...")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
            cwd=artifacts_dir,  # bloodhound-python writes to cwd
        )  # nosec B603 — validated list, no shell interpolation
    except subprocess.TimeoutExpired:
        findings.append({
            "title": "BloodHound Data Collection — Timed Out",
            "severity": "info",
            "deduction": 0,
            "description": "bloodhound-python did not complete within 10 minutes.",
            "recommendation": "Run bloodhound-python manually with a longer timeout or a narrower collection method.",
            "details": [],
        })
        return findings
    except Exception as exc:
        findings.append({
            "title": "BloodHound Data Collection — Failed",
            "severity": "info",
            "deduction": 0,
            "description": f"bloodhound-python raised an exception: {exc}",
            "recommendation": "Check that bloodhound-python is installed and credentials are valid.",
            "details": [],
        })
        return findings

    # Locate the ZIP written to artifacts_dir
    try:
        zip_files = sorted(
            f for f in os.listdir(artifacts_dir)
            if f.endswith(".zip") and run_ts in f
        )
        zip_path = os.path.join(artifacts_dir, zip_files[-1]) if zip_files else None
    except OSError:
        zip_path = None

    if result.returncode == 0 and zip_path:
        log.info("  [*] BloodHound ZIP saved: %s", zip_path)
        findings.append({
            "title": "BloodHound Data Collection — Complete",
            "severity": "info",
            "deduction": 0,
            "description": (
                "BloodHound data collection completed successfully. "
                "The ZIP archive contains graph data for all AD objects including users, "
                "groups, computers, ACLs, sessions, and trust relationships. "
                "Import the archive into BloodHound to visualise attack paths."
            ),
            "recommendation": (
                "Import the ZIP into BloodHound and run the built-in queries "
                "(e.g. 'Shortest Paths to Domain Admins') to identify attack paths."
            ),
            "details": [f"Archive: {zip_path}"],
        })
    else:
        stderr = (result.stderr or "").strip()
        findings.append({
            "title": "BloodHound Data Collection — Incomplete",
            "severity": "info",
            "deduction": 0,
            "description": (
                "bloodhound-python exited without producing a ZIP archive. "
                "This may indicate an authentication failure, DNS resolution issue, "
                "or insufficient permissions for the collecting account."
            ),
            "recommendation": (
                f"Re-run manually: {bh_exe} --zip -c All "
                f"-d {domain} -u <user> -p <pass> -dc {dc_host}"
            ),
            "details": ([stderr] if stderr else []),
        })

    return findings
