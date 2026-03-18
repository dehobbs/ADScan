#!/usr/bin/env python3
"""
ADScan - Active Directory Vulnerability Scanner

Main entry point for the scanner.

Usage:
    python adscan.py -d corp.local -dc-ip 192.168.1.10 -u administrator -p Password123
    python adscan.py -d corp.local -dc-ip 192.168.1.10 -u administrator --hash aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c
    python adscan.py -d corp.local -dc-ip 192.168.1.10 -u administrator -p Password123 --protocol ldaps
    python adscan.py -d corp.local -dc-ip 192.168.1.10 -u administrator   # prompts for password
    python adscan.py -d corp.local -dc-ip 192.168.1.10 -u administrator --kerberos
    python adscan.py -d corp.local -dc-ip 192.168.1.10 -u administrator --ccache /tmp/alice.ccache
"""
import argparse
import getpass
import logging
import sys
import importlib
import pkgutil
import os
from datetime import datetime

from lib.connector import ADConnector
from lib.report import generate_report, generate_json_report, generate_csv_report
from lib.audit_log import AuditLogger
from lib.debug_log import DebugLogger
from lib.scoring import ScoringConfig

BANNER = r"""
 _    ____  ____
/ \  |  _ \/ ___|
/ _ \ | | | \___ \
/ ___ \| |_| |___) |
(_/  \_(_|____/|____/
\___\__,_|_| |_|

Active Directory Vulnerability Scanner
Version 1.1 | github.com/dehobbs/ADScan
"""

# Default output directory for reports
REPORTS_DIR = "Reports"
ARTIFACTS_DIR = os.path.join(REPORTS_DIR, "Artifacts")


def configure_logging(verbose: bool, log_file: str | None) -> logging.Logger:
    """Configure the 'adscan' logger with a console handler and an optional file handler.

    Console handler level: verbose=False -> INFO, verbose=True -> DEBUG
    File handler (when --log-file is supplied): always DEBUG with timestamp prefix.
    """
    logger = logging.getLogger("adscan")
    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    fmt_console = logging.Formatter("%(message)s")
    fmt_file = logging.Formatter(
        "%(asctime)s %(levelname)-8s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG if verbose else logging.INFO)
    ch.setFormatter(fmt_console)
    logger.addHandler(ch)

    if log_file:
        log_dir = os.path.dirname(os.path.abspath(log_file))
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(fmt_file)
        logger.addHandler(fh)

    return logger


def load_checks():
    """Dynamically load all check modules from the checks/ directory."""
    checks = []
    checks_path = os.path.join(os.path.dirname(__file__), "checks")
    for _finder, name, _ispkg in pkgutil.iter_modules([checks_path]):
        module = importlib.import_module(f"checks.{name}")
        if hasattr(module, "run_check"):
            checks.append(module)
    return sorted(checks, key=lambda m: getattr(m, "CHECK_ORDER", 99))


def parse_args():
    parser = argparse.ArgumentParser(
        description="ADScan - Active Directory Vulnerability Scanner",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s -d corp.local -dc-ip 192.168.1.10 -u admin -p Password1\n"
            "  %(prog)s -d corp.local -dc-ip 192.168.1.10 -u admin --hash :NThash\n"
            "  %(prog)s -d corp.local -dc-ip 192.168.1.10 -u admin -p Pass --protocol ldaps\n"
            "  %(prog)s -d corp.local -dc-ip 192.168.1.10 -u admin  # prompts for password\n"
            "  %(prog)s -d corp.local -dc-ip 192.168.1.10 -u admin -p Pass --log-file scan.log\n"
            "  %(prog)s -d corp.local -dc-ip 192.168.1.10 -u admin -p Pass -v --log-file debug.log\n"
            "  %(prog)s -d corp.local -dc-ip 192.168.1.10 -u admin --kerberos\n"
            "  %(prog)s -d corp.local -dc-ip 192.168.1.10 -u admin --ccache /tmp/admin.ccache"
        ),
    )

    target_group = parser.add_argument_group("Target")
    target_group.add_argument(
        "-d", "--domain", required=True, help="Target domain FQDN (e.g. corp.local)"
    )
    target_group.add_argument(
        "-dc-ip", "--dc-ip", dest="dc_ip", required=True,
        help="Domain Controller IP or hostname"
    )
    target_group.add_argument(
        "--protocol",
        choices=["ldap", "ldaps", "smb", "all"],
        default="all",
        help="Connection protocol(s) to use (default: all)",
    )

    auth_group = parser.add_argument_group("Authentication")
    auth_group.add_argument("-u", "--username", required=True, help="Username for authentication")
    auth_creds = auth_group.add_mutually_exclusive_group(required=False)
    auth_creds.add_argument("-p", "--password", help="Password for authentication")
    auth_creds.add_argument(
        "--hash",
        metavar="NTLM_HASH",
        help="NTLM hash for pass-the-hash (format: LM:NT or just NT)",
    )
    auth_creds.add_argument(
        "--kerberos",
        action="store_true",
        default=False,
        help=(
            "Authenticate using a Kerberos ticket (ccache reuse).\n"
            "Reads the ccache from the KRB5CCNAME environment variable unless\n"
            "--ccache is also given. Ideal for assumed-breach scenarios and\n"
            "environments where NTLM authentication is disabled."
        ),
    )
    auth_group.add_argument(
        "--ccache",
        dest="ccache",
        default=None,
        metavar="PATH",
        help=(
            "Path to a Kerberos ccache file (implies --kerberos).\n"
            "Overrides the KRB5CCNAME environment variable."
        ),
    )

    output_group = parser.add_argument_group("Output")
    output_group.add_argument(
        "-o", "--output",
        default=None,
        help=f"Output report path stem (default: {REPORTS_DIR}/adscan_report_<timestamp>)",
    )
    output_group.add_argument(
        "-v", "--verbose",
        action="store_true",
        help=(
            "Show DEBUG-level output on the console: finding details and "
            "affected objects. When --log-file is also given the file always "
            "captures DEBUG output regardless of this flag."
        ),
    )
    output_group.add_argument(
        "--timeout", type=int, default=30,
        help="Connection timeout in seconds (default: 30)",
    )
    output_group.add_argument(
        "--format",
        choices=["html", "json", "csv", "all"],
        default="html",
        help="Output format(s): html, json, csv, or all (default: html)",
    )
    output_group.add_argument(
        "--log-file",
        dest="log_file",
        default=None,
        metavar="PATH",
        help=(
            "Write all log output (including DEBUG detail) to this file in "
            "addition to the console. The file always captures full DEBUG "
            "output regardless of --verbose."
        ),
    )
    output_group.add_argument(
        "--scoring-config",
        dest="scoring_config",
        default=None,
        metavar="PATH",
        help=(
            "Path to a TOML scoring config file "
            "(default: scoring.toml next to adscan.py).\n"
            "Override per-finding deductions or severity-tier weights."
        ),
    )
    return parser.parse_args()


def ensure_reports_dir(path):
    """Create the Reports directory (or any parent dirs) if it does not exist."""
    directory = os.path.dirname(os.path.abspath(path))
    if directory and not os.path.isdir(directory):
        os.makedirs(directory, exist_ok=True)


def main():
    args = parse_args()

    # --ccache implies --kerberos even if the flag was not set explicitly
    if args.ccache and not args.kerberos:
        args.kerberos = True

    # Configure logging first -- all subsequent output goes through the logger
    log = configure_logging(args.verbose, args.log_file)
    log.info(BANNER)

    # Load scoring config (scoring.toml is optional -- built-in weights used if absent)
    scoring = ScoringConfig.load(args.scoring_config)

    # Determine the effective auth method label for display / audit
    if args.kerberos:
        auth_method = "Kerberos (ccache)"
        ccache_source = args.ccache or os.environ.get("KRB5CCNAME", "(KRB5CCNAME not set)")
    elif args.hash:
        auth_method = "NTLM Hash"
        ccache_source = None
    else:
        auth_method = "Password"
        ccache_source = None

    # If neither -p, --hash, nor --kerberos was supplied, prompt interactively (no echo)
    if not args.kerberos and args.password is None and args.hash is None:
        try:
            args.password = getpass.getpass(
                prompt=f"[*] Password for {args.username}@{args.domain}: "
            )
        except (KeyboardInterrupt, EOFError):
            log.error("Password prompt cancelled. Exiting.")
            sys.exit(1)
        if not args.password:
            log.error("No password supplied. Use -p, --hash, or --kerberos.")
            sys.exit(1)

    # Generate a single scan timestamp used for all artifact naming
    scan_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Determine output stem (extension is added per format)
    if args.output is None:
        output_stem = os.path.join(REPORTS_DIR, f"adscan_report_{scan_timestamp}")
    else:
        output_stem, _ = os.path.splitext(args.output)

    # Make sure the output directory exists
    ensure_reports_dir(output_stem + ".html")

    # Create the Artifacts subdirectory for tool output (e.g. Certipy JSON)
    os.makedirs(ARTIFACTS_DIR, exist_ok=True)

    protocols = ["ldap", "ldaps", "smb"] if args.protocol == "all" else [args.protocol]

    log.info("[*] Target Domain : %s", args.domain)
    log.info("[*] DC Host       : %s", args.dc_ip)
    log.info("[*] Username      : %s", args.username)
    log.info("[*] Auth Method   : %s", auth_method)
    if ccache_source:
        log.info("[*] ccache        : %s", ccache_source)
    log.info("[*] Protocol(s)   : %s", ", ".join(p.upper() for p in protocols))
    log.info("[*] Output Stem   : %s.*", output_stem)
    log.info("[*] Format(s)     : %s", args.format)
    log.info("[*] Artifacts Dir : %s", ARTIFACTS_DIR)
    log.info("[*] Timeout       : %ss", args.timeout)
    log.info("[*] Scoring Config: %s", scoring.summary())
    log.info("[*] Log file      : %s", args.log_file or "(console only)")
    log.info("")

    # ------------------------------------------------------------------
    # Initialise audit logger + debug logger
    # ------------------------------------------------------------------
    audit = AuditLogger(
        domain=args.domain,
        dc_host=args.dc_ip,
        username=args.username,
        auth_method="kerberos" if args.kerberos else ("hash" if args.hash else "password"),
        scan_timestamp=scan_timestamp,
    )
    audit.log_file = args.log_file
    audit.start()

    dbg = DebugLogger(scan_timestamp=scan_timestamp)
    dbg.start()

    connector = ADConnector(
        domain=args.domain,
        dc_host=args.dc_ip,
        username=args.username,
        password=args.password,
        ntlm_hash=args.hash,
        use_kerberos=args.kerberos,
        ccache_path=args.ccache,
        protocols=protocols,
        verbose=args.verbose,
        timeout=args.timeout,
    )

    # Attach scan metadata so individual checks can use consistent naming
    connector.artifacts_dir = ARTIFACTS_DIR
    connector.scan_timestamp = scan_timestamp

    # Attach debug logger so connector.ldap_search() calls dbg.log_ldap() automatically
    connector.debug_log = dbg

    if not connector.connect():
        log.error("Failed to establish any connection to the Domain Controller.")
        log.error("Check your credentials, DC address, and firewall rules.")
        sys.exit(1)

    # ------------------------------------------------------------------
    # Log scan metadata -- written here so the connection is confirmed live.
    # ------------------------------------------------------------------
    log.info("=" * 60)
    log.info("SCAN METADATA")
    log.info(" Domain       : %s", args.domain)
    log.info(" DC Host      : %s", args.dc_ip)
    log.info(" Username     : %s", args.username)
    log.info(" Auth method  : %s", auth_method)
    if ccache_source:
        log.info(" ccache       : %s", ccache_source)
    log.info(" Protocol(s)  : %s", ", ".join(p.upper() for p in protocols))
    log.info(" Scan timestamp: %s", scan_timestamp)
    log.info(" Scoring config: %s", scoring.summary())
    log.info(" Log file     : %s", args.log_file or "(console only)")
    log.info("=" * 60)
    log.info("")

    checks = load_checks()
    if not checks:
        log.error("No check modules found in checks/ directory.")
        sys.exit(1)

    log.info("[+] Loaded %d check module(s)", len(checks))
    log.info("")
    log.info("=" * 60)

    findings = []
    score = 100

    for check in checks:
        log.info("")
        log.info("[*] Running: %s", check.CHECK_NAME)

        # Mark the check boundary in the debug log
        dbg.log_check_start(check.CHECK_NAME)
        try:
            result = check.run_check(connector, verbose=args.verbose)

            # Record end of check in debug log
            dbg.log_check_end(check.CHECK_NAME, result)

            if result:
                for finding in result:
                    log.info("  [!] %s", finding["title"])
                    log.info("      Severity  : %s", finding.get("severity", "N/A").upper())
                    _eff = scoring.deduction_for(finding)
                    log.info("      Deduction : -%s points", _eff)
                    if finding.get("details"):
                        for detail in finding["details"][:10]:
                            log.debug("       - %s", detail)
                        if len(finding["details"]) > 10:
                            log.debug(
                                "       ... and %d more",
                                len(finding["details"]) - 10,
                            )
                    _cat = getattr(check, "CHECK_CATEGORY", "Uncategorized")
                    finding.setdefault("category", _cat)
                    finding["deduction"] = scoring.deduction_for(finding)
                    score = max(0, score - finding["deduction"])
                    findings.append(finding)
            else:
                log.info("  [OK] No issues found.")

            # Record this check in the audit log
            audit.record_check(check.CHECK_NAME, result)

        except Exception as e:
            log.warning(
                "[WARN] %s raised an exception and was skipped: %s",
                check.CHECK_NAME,
                e,
            )
            log.debug("Traceback for %s:", check.CHECK_NAME, exc_info=True)
            audit.record_check_error(check.CHECK_NAME, e)
            dbg.log_error(context=check.CHECK_NAME, error=e)

    log.info("")
    log.info("=" * 60)
    connector.disconnect()

    formats = ["html", "json", "csv"] if args.format == "all" else [args.format]
    report_args = dict(
        domain=args.domain,
        dc_host=args.dc_ip,
        username=args.username,
        protocols=protocols,
        findings=findings,
        score=score,
    )

    for fmt in formats:
        out_path = f"{output_stem}.{fmt}"
        log.info("")
        log.info("[*] Generating %s report -> %s", fmt.upper(), out_path)
        if fmt == "html":
            generate_report(output_file=out_path, **report_args)
        elif fmt == "json":
            generate_json_report(output_file=out_path, **report_args)
        elif fmt == "csv":
            generate_csv_report(output_file=out_path, **report_args)
        log.info("[+] Saved : %s", out_path)

    log.info("")
    log.info("[+] Final Score : %s/100", score)
    grade = (
        "A" if score >= 90
        else "B" if score >= 75
        else "C" if score >= 60
        else "D" if score >= 40
        else "F"
    )
    log.info("[+] Grade       : %s", grade)

    primary_ext = "html" if "html" in formats else formats[0]
    audit.finish(score=score, report_path=os.path.abspath(f"{output_stem}.{primary_ext}"))
    dbg.finish()

    log.info("[*] Audit log : %s", audit.log_path)
    log.info("[*] Debug log : %s", dbg.log_path)
    if args.log_file:
        log.info("[*] Log file  : %s", os.path.abspath(args.log_file))


if __name__ == "__main__":
    main()
