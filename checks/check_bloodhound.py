"""
checks/check_bloodhound.py - BloodHound Data Collection

When the bloodhound step runs, the user is prompted to choose between:
  [1] Legacy BloodHound (bloodhound-python, installed via uv tool install)
  [2] BloodHound Community Edition (bloodhound-ce-python, installed via
      pip install bloodhound-ce)

The resulting ZIP archive is saved to Reports/Artifacts/ for import into
BloodHound for graph-based attack path analysis.

This is a data collection step, not a security check — it produces no
scored findings. The ingestor output is saved regardless of what other
checks find.

Collection method: All (Group, LocalAdmin, Session, Trusts, ACL, DCOM, RDP,
PSRemote, ObjectProps, Default)

When dc_host is an IP address, a DNS SRV lookup against the DC is performed
to resolve the FQDN required by both ingestors (-dc flag). The IP is then
passed as the nameserver (-ns flag) so hostname resolution works without
relying on the local system's default DNS.

Non-interactive sessions default to Legacy BloodHound.
"""

CHECK_NAME     = "BloodHound Data Collection"
CHECK_ORDER    = 99
CHECK_CATEGORY = ["Domain Hygiene"]
CHECK_WEIGHT   = 0

import ipaddress
import os
import shutil
import socket
import subprocess
import sys
from contextlib import nullcontext

import dns.resolver

from lib.tools import ensure_tool


def _is_ip(value):
    """Return True if value is an IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _resolve_dc_fqdn(domain, dc_ip, log):
    """Query the DC for _ldap._tcp.dc._msdcs.<domain> SRV records and return
    the first DC FQDN found.

    Uses dc_ip as the nameserver so the lookup succeeds even when the local
    system's DNS does not know about the AD domain.

    Returns the FQDN string (without trailing dot), or None on failure.
    """
    srv_name = f"_ldap._tcp.dc._msdcs.{domain}"
    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [dc_ip]
        resolver.timeout = 5
        resolver.lifetime = 10
        answers = resolver.resolve(srv_name, "SRV")
        for rdata in answers:
            fqdn = str(rdata.target).rstrip(".")
            if fqdn:
                log.debug("  Resolved DC FQDN via SRV: %s", fqdn)
                return fqdn
    except Exception as exc:
        log.debug("  SRV lookup failed for %s: %s", srv_name, exc)
    return None


def _resolve_dns_ip(host, log):
    """Return an IP for -ns. If host is already an IP, return it; otherwise
    resolve via the local system's DNS. Returns None on failure."""
    if _is_ip(host):
        return host
    try:
        return socket.gethostbyname(host)
    except Exception as exc:
        log.debug("  Failed to resolve %s to IP: %s", host, exc)
        return None


def _build_auth_args(connector):
    """Build auth args understood by both bloodhound-python and bloodhound-ce-python."""
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


def _prompt_engine(connector):
    """Prompt the user to choose between Legacy BloodHound and BloodHound CE.

    Returns 'legacy' or 'ce'. Defaults to 'legacy' in non-interactive
    sessions or on Ctrl+C / EOF. Suspends the running spinner (if any)
    so it doesn't overwrite the prompt while the user is choosing.
    """
    log = connector.log
    if not sys.stdin.isatty():
        log.info("  [*] Non-interactive session — defaulting to Legacy BloodHound")
        return "legacy"

    sp = getattr(connector, "spinner", None)
    suspend_ctx = sp.suspended() if sp is not None and hasattr(sp, "suspended") else nullcontext()

    with suspend_ctx:
        print("\n  Choose BloodHound engine:")
        print("    [1] Legacy BloodHound              (bloodhound-python)")
        print("    [2] BloodHound Community Edition   (bloodhound-ce-python)")
        try:
            choice = input("  Selection [1/2] (default 1): ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return "legacy"
    return "ce" if choice == "2" else "legacy"


def _pip_install_bloodhound_ce(log):
    """Install bloodhound-ce via pip. Falls back to --break-system-packages
    on PEP 668 environments (e.g. Kali). Returns True on success."""
    log.info("  [*] Installing bloodhound-ce via pip...")
    for extra in ([], ["--break-system-packages"]):
        cmd = ["pip", "install", *extra, "bloodhound-ce"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        except Exception as exc:
            log.warning("  [WARN] pip install bloodhound-ce error: %s", exc)
            return False
        if result.returncode == 0:
            log.info("  [*] bloodhound-ce installed")
            return True
        if not extra and "externally-managed" in result.stderr.lower():
            log.info("  [*] PEP 668 detected — retrying with --break-system-packages")
            continue
        log.warning(
            "  [WARN] pip install bloodhound-ce failed (rc=%d): %s",
            result.returncode, result.stderr.strip()[:300],
        )
        return False
    return False


def _ensure_bloodhound_ce(log):
    """Return absolute path to bloodhound-ce-python, pip-installing if missing."""
    path = shutil.which("bloodhound-ce-python")
    if path:
        return path
    if not _pip_install_bloodhound_ce(log):
        return None
    return shutil.which("bloodhound-ce-python")


def run_check(connector, verbose=False):
    findings = []
    log      = connector.log

    engine = _prompt_engine(connector)
    log.info(
        "  [*] BloodHound engine: %s",
        "Community Edition" if engine == "ce" else "Legacy",
    )

    if engine == "ce":
        bh_exe     = _ensure_bloodhound_ce(log)
        tool_label = "bloodhound-ce-python"
        install_hint = "pip install bloodhound-ce"
    else:
        bh_exe     = ensure_tool("bloodhound")
        tool_label = "bloodhound-python"
        install_hint = "uv tool install bloodhound  (or: python adscan.py --setup-tools)"

    if bh_exe is None:
        findings.append({
            "title": f"BloodHound Data Collection — {tool_label} Not Found",
            "severity": "info",
            "deduction": 0,
            "description": (
                f"{tool_label} is required for BloodHound data collection but was not found. "
                f"Install it with: {install_hint}"
            ),
            "recommendation": f"Run: {install_hint}",
            "details": [],
        })
        return findings

    domain  = getattr(connector, "domain", None)
    dc_host = getattr(connector, "dc_host", None)
    if not domain or not dc_host:
        log.warning("  [WARN] No domain or DC host configured — skipping BloodHound collection.")
        return findings

    # Both ingestors require an FQDN for -dc. When dc_host is an IP, do an
    # SRV lookup against the DC to get the FQDN.
    dc_fqdn = dc_host
    if _is_ip(dc_host):
        log.info("  [*] dc_host is an IP — resolving DC FQDN via SRV lookup...")
        fqdn = _resolve_dc_fqdn(domain, dc_host, log)
        if fqdn:
            dc_fqdn = fqdn
            log.info("  [*] Using DC FQDN: %s  (nameserver: %s)", dc_fqdn, dc_host)
        else:
            log.warning(
                "  [WARN] Could not resolve DC FQDN for %s — collection may fail.",
                dc_host,
            )

    artifacts_dir = getattr(connector, "artifacts_dir", "Reports/Artifacts")
    os.makedirs(artifacts_dir, exist_ok=True)

    # Build engine-specific command
    if engine == "ce":
        ns_ip = _resolve_dns_ip(dc_host, log)
        if not ns_ip:
            findings.append({
                "title": "BloodHound CE Data Collection — Could Not Resolve DNS Server IP",
                "severity": "info",
                "deduction": 0,
                "description": (
                    f"BloodHound CE requires a DNS server IP for the -ns flag, but "
                    f"could not resolve one from dc_host '{dc_host}'."
                ),
                "recommendation": "Provide --dc-ip as an IP address (or ensure local DNS resolves it).",
                "details": [],
            })
            return findings
        cmd = [
            bh_exe,
            *_build_auth_args(connector),
            "-c", "All",
            "-d", domain,
            "-dc", dc_fqdn,
            "-ns", ns_ip,
            "--use-ldaps",
            "--zip",
        ]
    else:
        ns_args = ["-ns", dc_host] if _is_ip(dc_host) and dc_fqdn != dc_host else []
        cmd = [
            bh_exe,
            "--zip",
            "-c", "All",
            "-d", domain,
            "-dc", dc_fqdn,
            *ns_args,
            *_build_auth_args(connector),
        ]

    log.info("  [*] Starting BloodHound collection (this may take several minutes)...")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
            cwd=artifacts_dir,
        )  # nosec B603 — validated list, no shell interpolation
    except subprocess.TimeoutExpired:
        findings.append({
            "title": "BloodHound Data Collection — Timed Out",
            "severity": "info",
            "deduction": 0,
            "description": f"{tool_label} did not complete within 10 minutes.",
            "recommendation": f"Run {tool_label} manually with a longer timeout or a narrower collection method.",
            "details": [],
        })
        return findings
    except Exception as exc:
        findings.append({
            "title": "BloodHound Data Collection — Failed",
            "severity": "info",
            "deduction": 0,
            "description": f"{tool_label} raised an exception: {exc}",
            "recommendation": f"Check that {tool_label} is installed and credentials are valid.",
            "details": [],
        })
        return findings

    # Both ingestors name their ZIP automatically — pick the newest .zip in
    # the artifacts dir after the run.
    try:
        zip_candidates = [
            os.path.join(artifacts_dir, f)
            for f in os.listdir(artifacts_dir)
            if f.endswith(".zip")
        ]
        zip_path = max(zip_candidates, key=os.path.getmtime) if zip_candidates else None
    except OSError:
        zip_path = None

    if result.returncode == 0 and zip_path:
        log.info("  [*] BloodHound ZIP saved: %s", zip_path)
        findings.append({
            "title": "BloodHound Data Collection — Complete",
            "severity": "info",
            "deduction": 0,
            "description": (
                f"BloodHound data collection completed successfully via {tool_label}. "
                "The ZIP archive contains graph data for all AD objects including users, "
                "groups, computers, ACLs, sessions, and trust relationships. "
                "Import the archive into BloodHound to visualise attack paths."
            ),
            "recommendation": (
                "Import the ZIP into BloodHound and run the built-in queries "
                "(e.g. 'Shortest Paths to Domain Admins') to identify attack paths."
            ),
            "details": [f"Archive: {zip_path}", f"Engine: {tool_label}"],
        })
    else:
        stderr = (result.stderr or "").strip()
        if engine == "ce":
            ns_for_hint = dc_host if _is_ip(dc_host) else "<dns-ip>"
            hint = (
                f"{bh_exe} -u <user> -p <pass> -c All -d {domain} -dc {dc_fqdn} "
                f"-ns {ns_for_hint} --use-ldaps --zip"
            )
        else:
            hint = (
                f"{bh_exe} --zip -c All -d {domain} -u <user> -p <pass> -dc {dc_fqdn}"
                + (f" -ns {dc_host}" if _is_ip(dc_host) else "")
            )
        findings.append({
            "title": "BloodHound Data Collection — Incomplete",
            "severity": "info",
            "deduction": 0,
            "description": (
                f"{tool_label} exited without producing a ZIP archive. "
                "This may indicate an authentication failure, DNS resolution issue, "
                "or insufficient permissions for the collecting account."
            ),
            "recommendation": f"Re-run manually: {hint}",
            "details": ([stderr] if stderr else []),
        })

    return findings
