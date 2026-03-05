#!/usr/bin/env python3
"""
ADScan - Active Directory Vulnerability Scanner

Main entry point for the scanner.

Usage:
    python adscan.py -d corp.local -dc-ip 192.168.1.10 -u administrator -p Password123
    python adscan.py -d corp.local -dc-ip 192.168.1.10 -u administrator --hash aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c
    python adscan.py -d corp.local -dc-ip 192.168.1.10 -u administrator -p Password123 --protocol ldaps
"""

import argparse
import sys
import importlib
import pkgutil
import os
from datetime import datetime

from lib.connector import ADConnector
from lib.report import generate_report

BANNER = r"""
    _    ____  ____
   / \  | _ \/ ___|  ___  __ _ _ __
  / _ \ | | | \___ \ / __/ _` | '_ \
 / ___ \| |_| |___) | (_| (_| | | | |
/_/   \_\____/|____/ \___\__,_|_| |_|

  Active Directory Vulnerability Scanner
  Version 1.0 | github.com/dehobbs/ADScan
"""

# Default output directory for reports
REPORTS_DIR = "Reports"
ARTIFACTS_DIR = os.path.join(REPORTS_DIR, "Artifacts")


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
            "  %(prog)s -d corp.local -dc-ip 192.168.1.10 -u admin -p Pass --protocol ldaps"
        ),
    )

    target_group = parser.add_argument_group("Target")
    target_group.add_argument(
        "-d", "--domain",
        required=True,
        help="Target domain FQDN (e.g. corp.local)"
    )
    target_group.add_argument(
        "-dc-ip", "--dc-ip",
        dest="dc_ip",
        required=True,
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
    auth_creds = auth_group.add_mutually_exclusive_group(required=True)
    auth_creds.add_argument("-p", "--password", help="Password for authentication")
    auth_creds.add_argument(
        "--hash",
        metavar="NTLM_HASH",
        help="NTLM hash for pass-the-hash (format: LM:NT or just NT)",
    )

    output_group = parser.add_argument_group("Output")
    output_group.add_argument(
        "-o", "--output",
        default=None,
        help=(
            f"Output HTML report path (default: {REPORTS_DIR}/adscan_report_<timestamp>.html)"
        ),
    )
    output_group.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output (show affected objects)"
    )

    return parser.parse_args()


def ensure_reports_dir(path):
    """Create the Reports directory (or any parent dirs) if it does not exist."""
    directory = os.path.dirname(os.path.abspath(path))
    if directory and not os.path.isdir(directory):
        os.makedirs(directory, exist_ok=True)
        print(f"[*] Created output directory: {directory}")

def main():
    print(BANNER)
    args = parse_args()

    # Generate a single scan timestamp used for all artifact naming
    scan_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Determine output path
    if args.output is None:
        args.output = os.path.join(REPORTS_DIR, f"adscan_report_{scan_timestamp}.html")

    # Make sure the output directory exists
    ensure_reports_dir(args.output)

    # Create the Artifacts subdirectory for tool output (e.g. Certipy JSON)
    os.makedirs(ARTIFACTS_DIR, exist_ok=True)

    protocols = ["ldap", "ldaps", "smb"] if args.protocol == "all" else [args.protocol]

    print(f"[*] Target Domain    : {args.domain}")
    print(f"[*] Domain Controller: {args.dc_ip}")
    print(f"[*] Username         : {args.username}")
    print(f"[*] Auth Method      : {'NTLM Hash' if args.hash else 'Password'}")
    print(f"[*] Protocol(s)      : {', '.join(p.upper() for p in protocols)}")
    print(f"[*] Output File      : {args.output}")
    print(f"[*] Artifacts Dir    : {ARTIFACTS_DIR}")
    print()

    connector = ADConnector(
        domain=args.domain,
        dc_host=args.dc_ip,
        username=args.username,
        password=args.password,
        ntlm_hash=args.hash,
        protocols=protocols,
        verbose=args.verbose,
    )

    # Attach scan metadata so individual checks can use consistent naming
    connector.artifacts_dir = ARTIFACTS_DIR
    connector.scan_timestamp = scan_timestamp

    if not connector.connect():
        print("[-] Failed to establish any connection to the Domain Controller.")
        print("    Check your credentials, DC address, and firewall rules.")
        sys.exit(1)

    checks = load_checks()
    if not checks:
        print("[-] No check modules found in checks/ directory.")
        sys.exit(1)

    print(f"[+] Loaded {len(checks)} check module(s)\n")
    print("=" * 60)

    findings = []
    score = 100

    for check in checks:
        print(f"\n[*] Running: {check.CHECK_NAME}")
        try:
            result = check.run_check(connector, verbose=args.verbose)
            if result:
                for finding in result:
                    print(f"  [!] {finding['title']}")
                    print(f"      Severity : {finding.get('severity', 'N/A').upper()}")
                    print(f"      Deduction: -{finding['deduction']} points")
                    if args.verbose and finding.get("details"):
                        for detail in finding["details"][:10]:
                            print(f"        - {detail}")
                        if len(finding["details"]) > 10:
                            print(f"        ... and {len(finding['details']) - 10} more")
                    _cat = getattr(check, "CHECK_CATEGORY", "Uncategorized")
                    finding.setdefault("category", _cat)
                    score = max(0, score - finding["deduction"])
                    findings.append(finding)
            else:
                print(f"  [OK] No issues found.")
        except Exception as e:
            print(f"  [ERROR] {check.CHECK_NAME} raised an exception: {e}")
            if args.verbose:
                import traceback
                traceback.print_exc()

    print()
    print("=" * 60)

    connector.disconnect()

    print(f"\n[*] Generating HTML report -> {args.output}")
    generate_report(
        output_file=args.output,
        domain=args.domain,
        dc_host=args.dc_ip,
        username=args.username,
        protocols=protocols,
        findings=findings,
        score=score,
    )

    print(f"[+] Report saved  : {args.output}")
    print(f"[+] Final Score   : {score}/100")
    grade = (
        "A" if score >= 90
        else "B" if score >= 75
        else "C" if score >= 60
        else "D" if score >= 40
        else "F"
    )
    print(f"[+] Grade         : {grade}")


if __name__ == "__main__":
    main()
