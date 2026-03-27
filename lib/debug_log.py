"""
lib/debug_log.py -- ADScan Command-Execution Debug Logger

Records every command actually executed during a scan run so that errors
can be diagnosed after the fact.

Three categories of operations are logged:

LDAP queries
    Logged automatically via connector.ldap_search() -- no changes needed in
    individual check files.  Each entry records:
        - search_base, search_filter, attributes requested
        - number of entries returned
        - full ldap3 error string if the search throws an exception

Subprocess commands (e.g. Certipy)h
    Call connector.debug_log.log_subprocess() immediately after any
    subprocess.run() call inside a check.  Each entry records:
        - full command line (argv list joined with spaces)
        - working directory
        - return code
        - full stdout
        - full stderr

SMB / file-system operations
    Call connector.debug_log.log_smb() for SMB path traversal or file reads.
    Each entry records:
        - operation type (e.g. "listPath", "getFile")
        - path / UNC share
        - result summary or error

Errors / exceptions
    Call connector.debug_log.log_error() for any caught exception that should
    be recorded without re-raising.

Log file naming: Logs/adscan_debug_<YYYYMMDD_HHMMSS>.log

Usage (from adscan.py)::

    from lib.debug_log import DebugLogger
    dbg = DebugLogger(scan_timestamp=scan_timestamp)
    dbg.start()
    # Attach to connector -- ldap_search() will call dbg.log_ldap() automatically
    connector.debug_log = dbg
    # After each check:
    dbg.log_check_start(check_name)
    result = check.run_check(connector, verbose=args.verbose)
    dbg.log_check_end(check_name, result)
    # At the end:
    dbg.finish()

Usage inside check files (subprocess example)::

    rc, out, err = _run_certipy(creds, prefix, cwd=cwd)
    dbg = getattr(connector, "debug_log", None)
    if dbg:
        dbg.log_subprocess(
            cmd=["certipy-ad", "find", "..."],
            cwd=str(cwd),
            returncode=rc,
            stdout=out,
            stderr=err,
        )
"""

import os
import re
import traceback
from datetime import datetime

from lib.audit_log import LOGS_DIR  # reuse the same Logs/ path constant


class DebugLogger:
    """
    Writes a command-execution debug log to Logs/adscan_debug_<ts>.log.

    Designed to be attached to the connector as connector.debug_log so that
    the connector's ldap_search() method can call log_ldap() automatically.
    """

    # ------------------------------------------------------------------#
    # Construction                                                        #
    # ------------------------------------------------------------------#

    def __init__(
        self,
        scan_timestamp: str,
        logs_dir: str | None = None,
    ) -> None:
        self.scan_timestamp = scan_timestamp
        self.logs_dir = logs_dir or LOGS_DIR
        self._log_path: str = ""
        self._seq: int = 0                # monotonic sequence number across all ops
        self._check_seq: int = 0          # per-check operation counter (reset each check)
        self._current_check: str = ""

    # ------------------------------------------------------------------#
    # Lifecycle                                                           #
    # ------------------------------------------------------------------#

    def start(self) -> None:
        """Open the log file and write the header."""
        os.makedirs(self.logs_dir, exist_ok=True)
        self._log_path = os.path.join(
            self.logs_dir, f"adscan_debug_{self.scan_timestamp}.log"
        )
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._write([
            "=" * 80,
            f" ADScan Debug Log -- {now}",
            " Records every LDAP query, subprocess command, and SMB operation",
            " executed during the scan, with full input/output for debugging.",
            "=" * 80,
            "",
        ])

    def finish(self) -> None:
        """Write the footer."""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._write([
            "",
            "=" * 80,
            f" End of debug log -- {now}",
            f" Total operations logged: {self._seq}",
            "=" * 80,
        ])
    
    @property
    def log_path(self) -> str:
        return self._log_path

    # ------------------------------------------------------------------#
    # Check boundaries                                                    #
    # ------------------------------------------------------------------#

    def log_check_start(self, check_name: str) -> None:
        """Call before each check.run_check() to mark the boundary in the log."""
        self._current_check = check_name
        self._check_seq = 0
        self._write([
            "",
            "=" * 80,
            f" CHECK: {check_name}",
            f" Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "=" * 80,
        ])

    def log_check_end(self, check_name: str, findings: list | None) -> None:
        """Call after each check.run_check() to record the finding summary."""
        count = len(findings) if findings else 0
        status = f"{count} finding(s)" if count else "PASS (no findings)"
        self._write([
            "",
            f" CHECK END: {check_name} -- {status}",
            f" Finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "-" * 80,
        ])

    # ------------------------------------------------------------------#
    # LDAP query logging                                                  #
    # ------------------------------------------------------------------#

    def log_ldap(
        self,
        search_filter: str,
        search_base: str,
        attributes: list,
        entry_count: int,
        error: str | None = None,
    ) -> None:
        """
        Log one LDAP search operation.

        Called automatically by connector.ldap_search() -- no manual calls
        needed in check files.
        """
        self._seq += 1
        self._check_seq += 1
        tag = f"[LDAP #{self._seq}]"
        lines = [
            "",
            f"{tag} --- LDAP Search ---",
            f" Base DN    : {search_base}",
            f" Filter     : {search_filter}",
            f" Attributes : {', '.join(attributes) if attributes else '*'}",
        ]
        if error:
            lines.append(f" Result     : ERROR -- {error}")
        else:
            lines.append(f" Result     : {entry_count} entr{'y' if entry_count == 1 else 'ies'} returned")
        self._write(lines)

    # ------------------------------------------------------------------#
    # Subprocess logging                                                  #
    # ------------------------------------------------------------------#

    def log_subprocess(
        self,
        cmd: list | str,
        returncode: int,
        stdout: str = "",
        stderr: str = "",
        cwd: str | None = None,
    ) -> None:
        """
        Log a subprocess.run() call and its output.

        Call this from any check that invokes an external tool::

            rc, out, err = _run_certipy(creds, prefix, cwd=cwd)
            dbg = getattr(connector, "debug_log", None)
            if dbg:
                dbg.log_subprocess(cmd=cmd, returncode=rc,
                                   stdout=out, stderr=err, cwd=str(cwd))
        """
        self._seq += 1
        self._check_seq += 1
        tag = f"[SUBPROCESS #{self._seq}]"
        # Redact password values before logging
        _PASSWORD_FLAGS = {"-p", "--password", "-P", "--secret", "--hashes", "--hash"}
        def _redact_cmd(cmd):
            if isinstance(cmd, str):
                return re.sub(
                    r'(?<=[\s]|^)(-p|--password|-P|--secret|--hashes|--hash)(\s+)(\S+)',
                    lambda m: m.group(1) + m.group(2) + 'REDACTED',
                    cmd
                )
            out = []
            skip_next = False
            for tok in cmd:
                if skip_next:
                    out.append("REDACTED")
                    skip_next = False
                elif str(tok) in _PASSWORD_FLAGS:
                    out.append(str(tok))
                    skip_next = True
                else:
                    out.append(str(tok))
            return out
        cmd_redacted = _redact_cmd(cmd)
        cmd_str = " ".join(cmd_redacted) if isinstance(cmd_redacted, list) else cmd_redacted
        lines = [
            "",
            f"{tag} --- Subprocess ---",
            f" Command    : {cmd_str}",
            f" CWD        : {cwd or '(not set)'}",
            f" Return code: {returncode}",
        ]
        # Redact credential strings from subprocess output
        # (e.g. nxc prints "domain\\user:password" on [+] success lines)
        def _redact_output(text):
            return re.sub(
                r'([A-Za-z0-9._-]+\\[A-Za-z0-9._-]+):(\S+)',
                r'\1:REDACTED',
                text or "",
            )
        if stdout and stdout.strip():
            lines.append(" stdout:")
            lines.extend(" " + line for line in _redact_output(stdout).rstrip().splitlines())
        else:
            lines.append(" stdout     : (empty)")
        if stderr and stderr.strip():
            lines.append(" stderr:")
            lines.extend(" " + line for line in _redact_output(stderr).rstrip().splitlines())
        else:
            lines.append(" stderr     : (empty)")
        self._write(lines)

    # ------------------------------------------------------------------#
    # SMB / file-system logging                                           #
    # ------------------------------------------------------------------#

    def log_smb(
        self,
        operation: str,
        path: str,
        result: str = "",
        error: str | None = None,
    ) -> None:
        """
        Log an SMB or file-system operation.

        Call from check files that do SMB traversal::

            dbg = getattr(connector, "debug_log", None)
            if dbg:
                dbg.log_smb("listPath", sysvol_path,
                             result=f"{len(entries)} entries")
        """
        self._seq += 1
        self._check_seq += 1
        tag = f"[SMB #{self._seq}]"
        lines = [
            "",
            f"{tag} --- SMB Operation ---",
            f" Operation: {operation}",
            f" Path     : {path}",
        ]
        if error:
            lines.append(f" Result   : ERROR -- {error}")
        else:
            lines.append(f" Result   : {result or 'OK'}")
        self._write(lines)

    # ------------------------------------------------------------------#
    # Error / exception logging                                           #
    # ------------------------------------------------------------------#

    def log_error(
        self,
        context: str,
        error: Exception,
        include_traceback: bool = True,
    ) -> None:
        """
        Log a caught exception with optional full traceback.

        Call from check files or adscan.py when an exception is caught and
        you want it recorded in the debug log without re-raising::

            except Exception as e:
                if connector.debug_log:
                    connector.debug_log.log_error("Certipy phase", e)
        """
        self._seq += 1
        tag = f"[ERROR #{self._seq}]"
        lines = [
            "",
            f"{tag} --- Error ---",
            f" Context  : {context}",
            f" Exception: {type(error).__name__}: {error}",
        ]
        if include_traceback:
            tb = traceback.format_exc()
            if tb and tb.strip() != "NoneType: None":
                lines.append(" Traceback:")
                lines.extend(" " + line for line in tb.rstrip().splitlines())
        self._write(lines)

    # ------------------------------------------------------------------#
    # Internal helpers                                                    #
    # ------------------------------------------------------------------#

    def _write(self, lines: list[str]) -> None:
        with open(self._log_path, "a", encoding="utf-8") as fh:
            for line in lines:
                fh.write(line + "\n")
