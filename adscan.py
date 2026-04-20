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
    python adscan.py -d corp.local -dc-ip 192.168.1.10 -u administrator -p Password123 --checks kerberos,delegation
    python adscan.py -d corp.local -dc-ip 192.168.1.10 -u administrator -p Password123 --skip gpp,smb
    python adscan.py --list-checks
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
from lib.spinner import spinner
from lib.report import generate_report, generate_json_report, generate_csv_report, generate_docx_report
from lib.audit_log import AuditLogger
from lib.debug_log import DebugLogger
from lib.scoring import ScoringConfig, compute_scores
from lib.tools import setup_all_tools, TOOL_REGISTRY

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


def _check_slugs(module):
    """Return the set of lowercase match tokens for a check module.

    Tokens include:
      - the bare module name without the 'check_' prefix  (e.g. 'kerberos')
      - every word in CHECK_NAME split by spaces/underscores (e.g. 'kerberos', 'attack', 'surface')
      - every value in CHECK_CATEGORY lowercased           (e.g. 'kerberos')
    """
    slugs = set()
    # module file slug: checks.check_kerberos -> 'kerberos'
    mod_name = module.__name__.split(".")[-1]  # e.g. 'check_kerberos'
    if mod_name.startswith("check_"):
        mod_name = mod_name[len("check_"):]
    slugs.add(mod_name)

    # words from CHECK_NAME
    check_name = getattr(module, "CHECK_NAME", "")
    for word in check_name.lower().replace("-", " ").replace("_", " ").split():
        slugs.add(word)

    # category values
    for cat in getattr(module, "CHECK_CATEGORY", []):
        slugs.add(cat.lower().replace(" ", "_"))
        for word in cat.lower().split():
            slugs.add(word)

    return slugs


def load_checks(only=None, skip=None):
    """Dynamically load check modules from the checks/ directory.

    Args:
        only: set of lowercase slug strings — if non-empty, only modules whose
              slugs intersect this set are included.
        skip: set of lowercase slug strings — modules whose slugs intersect
              this set are excluded (applied after *only* filtering).
    """
    checks = []
    checks_path = os.path.join(os.path.dirname(__file__), "checks")
    for _finder, name, _ispkg in pkgutil.iter_modules([checks_path]):
        module = importlib.import_module(f"checks.{name}")
        if not hasattr(module, "run_check"):
            continue
        slugs = _check_slugs(module)
        if only and not slugs.intersection(only):
            continue
        if skip and slugs.intersection(skip):
            continue
        checks.append(module)
    return sorted(checks, key=lambda m: getattr(m, "CHECK_ORDER", 99))


def list_checks():
    """Print all available check modules with their name, slug, category, and order."""
    checks_path = os.path.join(os.path.dirname(__file__), "checks")
    all_checks = []
    for _finder, name, _ispkg in pkgutil.iter_modules([checks_path]):
        module = importlib.import_module(f"checks.{name}")
        if hasattr(module, "run_check"):
            all_checks.append(module)
    all_checks = sorted(all_checks, key=lambda m: getattr(m, "CHECK_ORDER", 99))

    print(f"{'ORDER':<6} {'SLUG':<35} {'CATEGORY':<25} CHECK NAME")
    print("-" * 100)
    for m in all_checks:
        mod_slug = m.__name__.split(".")[-1]
        if mod_slug.startswith("check_"):
            mod_slug = mod_slug[len("check_"):]
        cats = ", ".join(getattr(m, "CHECK_CATEGORY", ["Uncategorized"]))
        print(f"{getattr(m, 'CHECK_ORDER', 99):<6} {mod_slug:<35} {cats:<25} {getattr(m, 'CHECK_NAME', '?')}")


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
            "  %(prog)s -d corp.local -dc-ip 192.168.1.10 -u admin --ccache /tmp/admin.ccache\n"
            "  %(prog)s -d corp.local -dc-ip 192.168.1.10 -u admin -p Pass --checks kerberos,delegation\n"
            "  %(prog)s -d corp.local -dc-ip 192.168.1.10 -u admin -p Pass --skip gpp,smb\n"
            "  %(prog)s --list-checks\n"
            "  %(prog)s --setup-tools"
        ),
    )

    target_group = parser.add_argument_group("Target")
    target_group.add_argument(
        "-d", "--domain", required=False, help="Target domain FQDN (e.g. corp.local)"
    )
    target_group.add_argument(
        "-dc-ip", "--dc-ip", dest="dc_ip", required=False,
        help="Domain Controller IP or hostname"
    )
    target_group.add_argument(
        "--protocol",
        choices=["ldap", "ldaps", "smb", "all"],
        default="all",
        help="Connection protocol(s) to use (default: all)",
    )

    auth_group = parser.add_argument_group("Authentication")
    auth_group.add_argument("-u", "--username", required=False, help="Username for authentication")
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
        "--output-dir",
        default=None,
        metavar="DIR",
        dest="output_dir",
        help=(
            "Directory for output reports (overrides the default Reports/ folder). "
            "The filename is auto-generated as adscan_report_<timestamp>. "
            "Ignored if -o/--output is also specified."
        ),
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
        choices=["html", "json", "csv", "docx", "all"],
        default="html",
        help="Output format(s): html, json, csv, docx, or all (default: html)",
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

    filter_group = parser.add_argument_group("Check Filtering")
    filter_group.add_argument(
        "--checks",
        dest="checks",
        default=None,
        metavar="SLUG[,SLUG...]",
        help=(
            "Comma-separated list of check slugs to run (all others are skipped).\n"
            "Slugs are matched against module name, CHECK_NAME words, and CHECK_CATEGORY.\n"
            "Example: --checks kerberos,delegation,adcs\n"
            "Run --list-checks to see all available slugs."
        ),
    )
    filter_group.add_argument(
        "--skip",
        dest="skip",
        default=None,
        metavar="SLUG[,SLUG...]",
        help=(
            "Comma-separated list of check slugs to skip (all others still run).\n"
            "Example: --skip gpp,smb,dns\n"
            "Run --list-checks to see all available slugs."
        ),
    )
    filter_group.add_argument(
        "--list-checks",
        dest="list_checks",
        action="store_true",
        default=False,
        help="Print all available check modules (slug, category, name) and exit.",
    )

    setup_group = parser.add_argument_group("Tool Management")
    setup_group.add_argument(
        "--setup-tools",
        dest="setup_tools",
        action="store_true",
        default=False,
        help=(
            "Install all external CLI tools (certipy-ad, netexec) into isolated\n"
            "virtual environments via uv and exit. No domain credentials required.\n"
            "Requires uv: curl -LsSf https://astral.sh/uv/install.sh | sh"
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

    # --list-checks: print available modules and exit immediately (no connection needed)
    if args.list_checks:
        list_checks()
        sys.exit(0)

    # --setup-tools: install external CLI tools into isolated venvs and exit
    if args.setup_tools:
        configure_logging(verbose=True, log_file=None)
        print(BANNER)
        print("[*] Installing external tools via uv tool install ...\n")
        with spinner("Installing tools..."):
            results = setup_all_tools()
        print(f"\n{'TOOL':<15} {'PACKAGE':<20} {'STATUS'}")
        print("-" * 60)
        for slug, path in results.items():
            spec = TOOL_REGISTRY[slug]
            status = path if path else "FAILED (see warnings above)"
            print(f"{spec.exe:<15} {spec.pip_spec:<20} {status}")
        sys.exit(0 if all(results.values()) else 1)

    # Validate required connection args (not needed for --list-checks, already exited above)
    missing = []
    if not args.domain:
        missing.append("-d/--domain")
    if not args.dc_ip:
        missing.append("-dc-ip/--dc-ip")
    if not args.username:
        missing.append("-u/--username")
    if missing:
        import sys as _sys
        print(f"adscan.py: error: the following arguments are required: {', '.join(missing)}", file=_sys.stderr)
        _sys.exit(2)


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
    if args.output is not None:
        output_stem, _ = os.path.splitext(args.output)
    elif args.output_dir is not None:
        os.makedirs(args.output_dir, exist_ok=True)
        output_stem = os.path.join(args.output_dir, f"adscan_report_{scan_timestamp}")
    else:
        output_stem = os.path.join(REPORTS_DIR, f"adscan_report_{scan_timestamp}")

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

    with spinner("Connecting to domain controller..."):
        connected = connector.connect()
    if not connected:
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

    # Parse --checks / --skip slug filters into sets
    only_slugs = set()
    skip_slugs = set()
    if args.checks:
        only_slugs = {s.strip().lower() for s in args.checks.split(",") if s.strip()}
    if args.skip:
        skip_slugs = {s.strip().lower() for s in args.skip.split(",") if s.strip()}

    checks = load_checks(only=only_slugs or None, skip=skip_slugs or None)
    if not checks:
        if only_slugs:
            log.error(
                "No checks matched --checks filter: %s  (run --list-checks to see available slugs)",
                ", ".join(sorted(only_slugs)),
            )
        else:
            log.error("No check modules found in checks/ directory.")
        sys.exit(1)

    if only_slugs:
        log.info("[+] Check filter (--checks): %s", ", ".join(sorted(only_slugs)))
    if skip_slugs:
        log.info("[+] Skipping (--skip)      : %s", ", ".join(sorted(skip_slugs)))
    log.info("[+] Loaded %d check module(s)", len(checks))
    log.info("")
    log.info("=" * 60)

    findings   = []
    checks_run = []  # metadata for every check that executes (clean or not)

    for check in checks:
        log.info("")
        log.info("[*] Running: %s", check.CHECK_NAME)

        # Mark the check boundary in the debug log
        dbg.log_check_start(check.CHECK_NAME)
        try:
            with spinner(check.CHECK_NAME, enabled=not args.verbose):
                result = check.run_check(connector, verbose=args.verbose)

            # Record end of check in debug log
            dbg.log_check_end(check.CHECK_NAME, result)

            # Record this check for scoring purposes regardless of outcome
            checks_run.append({
                "categories": list(getattr(check, "CHECK_CATEGORY", ["Uncategorised"])),
                "weight":     int(getattr(check, "CHECK_WEIGHT", 0)),
            })

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
                    # Attach the check's category to the finding for sub-score grouping
                    finding.setdefault("check_category", getattr(check, "CHECK_CATEGORY", ["Uncategorised"]))
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

    # Archive ~/.nxc (NetExec scan data) into Artifacts if it exists
    _nxc_dir = os.path.expanduser("~/.nxc")
    if os.path.isdir(_nxc_dir):
        import zipfile
        _nxc_zip = os.path.join(ARTIFACTS_DIR, f"nxc_{scan_timestamp}.zip")
        log.info("[*] Archiving ~/.nxc -> %s", _nxc_zip)
        with spinner("Archiving ~/.nxc..."):
            with zipfile.ZipFile(_nxc_zip, "w", zipfile.ZIP_DEFLATED) as _zf:
                for _root, _dirs, _files in os.walk(_nxc_dir):
                    for _file in _files:
                        _full = os.path.join(_root, _file)
                        _arc  = os.path.relpath(_full, os.path.dirname(_nxc_dir))
                        _zf.write(_full, _arc)
        log.info("[+] Saved : %s", _nxc_zip)

    formats = ["html", "json", "csv", "docx"] if args.format == "all" else [args.format]
    # Compute ratio-based overall + per-category scores
    score_data      = compute_scores(findings, scoring, checks_run=checks_run)
    score           = score_data["overall"]
    category_scores = score_data["categories"]

    report_args = dict(
        domain=args.domain,
        dc_host=args.dc_ip,
        username=args.username,
        protocols=protocols,
        findings=findings,
        score=score,
        category_scores=category_scores,
    )

    for fmt in formats:
        out_path = f"{output_stem}.{fmt}"
        log.info("")
        log.info("[*] Generating %s report -> %s", fmt.upper(), out_path)
        with spinner(f"Generating {fmt.upper()} report..."):
            if fmt == "html":
                generate_report(output_file=out_path, **report_args)
            elif fmt == "json":
                generate_json_report(output_file=out_path, **report_args)
            elif fmt == "csv":
                generate_csv_report(output_file=out_path, **report_args)
            elif fmt == "docx":
                generate_docx_report(output_file=out_path, **report_args)
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
