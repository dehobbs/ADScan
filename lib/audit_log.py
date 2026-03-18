"""
lib/audit_log.py -- ADScan Audit Logger

Creates a structured audit log in the Logs/ directory every time adscan.py
is run. The log captures:

  * Run metadata   : timestamp, operator, target domain / DC, auth method,
                     companion log-file path
  * Check results  : per-check status, findings count, severity breakdown
  * Score timeline : starting score, per-finding deductions, final score
  * Runtime        : elapsed wall-clock time for the full scan
  * Report path    : where the HTML report was saved

Log file naming:
    Logs/adscan_<YYYYMMDD_HHMMSS>.log

Usage (from adscan.py)::

    from lib.audit_log import AuditLogger

    logger = AuditLogger(domain=args.domain, dc_host=args.dc_ip,
                         username=args.username,
                         auth_method="hash" if args.hash else "password",
                         scan_timestamp=scan_timestamp)
    logger.log_file = args.log_file   # companion --log-file path (may be None)
    logger.start()

    # After each check:
    logger.record_check(check_name, findings_list)

    # At the end:
    logger.finish(score=score, report_path=args.output)
"""

import os
import sys
import time
from datetime import datetime

# Where audit logs live relative to the project root
LOGS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "Logs")


class AuditLogger:
    """Writes a human-readable audit log for every ADScan run."""

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    def __init__(
        self,
        domain: str,
        dc_host: str,
        username: str,
        auth_method: str,       # "password" or "hash"
        scan_timestamp: str,    # YYYYMMDD_HHMMSS (shared with report)
        logs_dir: str | None = None,
    ) -> None:
        self.domain = domain
        self.dc_host = dc_host
        self.username = username
        self.auth_method = auth_method
        self.scan_timestamp = scan_timestamp
        self.logs_dir = logs_dir or LOGS_DIR
        self.log_file: str | None = None   # companion --log-file; set by adscan.py
        self._start_time: float = 0.0
        self._check_records: list[dict] = []
        self._log_path: str = ""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Call once at the very beginning of the scan."""
        os.makedirs(self.logs_dir, exist_ok=True)
        self._log_path = os.path.join(
            self.logs_dir, f"adscan_{self.scan_timestamp}.log"
        )
        self._start_time = time.monotonic()
        self._write_header()

    def record_check(self, check_name: str, findings: list[dict] | None) -> None:
        """Call after each check module completes.

        Args:
            check_name: The CHECK_NAME constant from the check module.
            findings:   The list returned by run_check(), or None / [] for clean.
        """
        findings = findings or []
        record = {
            "check": check_name,
            "status": "FINDINGS" if findings else "PASS",
            "count": len(findings),
            "severities": _count_severities(findings),
            "deduction": sum(f.get("deduction", 0) for f in findings),
        }
        self._check_records.append(record)
        self._append_check_line(record)

    def record_check_error(self, check_name: str, error: Exception) -> None:
        """Call when a check raises an unhandled exception."""
        record = {
            "check": check_name,
            "status": "ERROR",
            "count": 0,
            "severities": {},
            "deduction": 0,
            "error": str(error),
        }
        self._check_records.append(record)
        self._append_check_line(record)

    def finish(self, score: int, report_path: str) -> None:
        """Call once after the scan is fully complete (report generated)."""
        elapsed = time.monotonic() - self._start_time
        self._write_footer(score=score, report_path=report_path, elapsed=elapsed)

    @property
    def log_path(self) -> str:
        return self._log_path

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _write_header(self) -> None:
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lines = [
            "=" * 70,
            " ADScan Audit Log",
            "=" * 70,
            f"  Run Timestamp  : {now_str}",
            f"  Operator       : {self.username}",
            f"  Target Domain  : {self.domain}",
            f"  DC Host        : {self.dc_host}",
            f"  Auth Method    : {self.auth_method}",
            f"  Python         : {sys.version.split()[0]}",
            f"  Log file       : {self.log_file or '(none)'}",
            "=" * 70,
            "",
            f"{'CHECK':<45} {'STATUS':<10} {'FINDINGS':>8} {'DEDUCT':>6} SEVERITIES",
            "-" * 100,
        ]
        self._write_lines(lines)

    def _append_check_line(self, record: dict) -> None:
        sev_str = _format_severities(record["severities"])
        if record["status"] == "ERROR":
            sev_str = f"ERROR: {record.get('error', '')}"
        line = (
            f"{record['check']:<45} "
            f"{record['status']:<10} "
            f"{record['count']:>8} "
            f"{record['deduction']:>6} "
            f"{sev_str}"
        )
        self._write_lines([line])

    def _write_footer(self, score: int, report_path: str, elapsed: float) -> None:
        total_findings  = sum(r["count"] for r in self._check_records)
        total_deduction = sum(r["deduction"] for r in self._check_records)
        checks_with_findings = sum(
            1 for r in self._check_records if r["status"] == "FINDINGS"
        )
        checks_errored = sum(
            1 for r in self._check_records if r["status"] == "ERROR"
        )

        combined_severities: dict[str, int] = {}
        for r in self._check_records:
            for sev, cnt in r.get("severities", {}).items():
                combined_severities[sev] = combined_severities.get(sev, 0) + cnt

        grade = (
            "A" if score >= 90 else
            "B" if score >= 75 else
            "C" if score >= 60 else
            "D" if score >= 40 else
            "F"
        )

        lines = [
            "-" * 100,
            "",
            "SUMMARY",
            "-" * 40,
            f"  Checks run          : {len(self._check_records)}",
            f"  Checks with findings: {checks_with_findings}",
            f"  Checks errored      : {checks_errored}",
            f"  Total findings      : {total_findings}",
            f"  Total deduction     : -{total_deduction} points",
            f"  Severity breakdown  : {_format_severities(combined_severities)}",
            "",
            f"  Starting score      : 100",
            f"  Final score         : {score}/100 (Grade: {grade})",
            "",
            f"  Elapsed time        : {_format_elapsed(elapsed)}",
            f"  Report saved to     : {report_path}",
            f"  Log file            : {self.log_file or '(none)'}",
            "",
            "=" * 70,
            " End of audit log",
            "=" * 70,
        ]
        self._write_lines(lines)

    def _write_lines(self, lines: list[str]) -> None:
        with open(self._log_path, "a", encoding="utf-8") as fh:
            for line in lines:
                fh.write(line + "\n")


# ------------------------------------------------------------------
# Module-level helpers
# ------------------------------------------------------------------

_SEV_ORDER = ("critical", "high", "medium", "low", "info")


def _count_severities(findings: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "info").lower()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _format_severities(counts: dict[str, int]) -> str:
    if not counts:
        return "-"
    parts = []
    for sev in _SEV_ORDER:
        if sev in counts:
            parts.append(f"{sev.upper()[0]}:{counts[sev]}")
    for sev, cnt in counts.items():
        if sev not in _SEV_ORDER:
            parts.append(f"{sev.upper()}:{cnt}")
    return " ".join(parts) if parts else "-"


def _format_elapsed(seconds: float) -> str:
    mins, secs = divmod(int(seconds), 60)
    if mins:
        return f"{mins}m {secs}s"
    return f"{secs:.1f}s".replace(".0s", "s")
