"""
tests/test_check_webclient_webdav.py

Unit tests for checks/check_webclient_webdav.py. Output parsing and helpers are
pure; run_check is exercised with ensure_tool and _run_cmd monkeypatched so no
real nxc subprocess is launched.
"""
import logging

from checks import check_webclient_webdav as wd

SAMPLE_OUTPUT = """\
SMB     10.0.0.10  445  WS01  [*] Windows 10 (name:WS01) (domain:corp.local) (signing:False) (SMBv1:False)
SMB     10.0.0.10  445  WS01  [+] corp.local\\alice:REDACTED
WEBDAV  10.0.0.10  445  WS01  WebClient Service enabled on: WS01
SMB     10.0.0.11  445  WS02  [*] Windows 10 (name:WS02) (domain:corp.local) (signing:True) (SMBv1:False)
SMB     10.0.0.11  445  WS02  [+] corp.local\\alice:REDACTED
"""


class FakeConnector:
    def __init__(self, computers=None, artifacts_dir=".", ldap_up=True):
        self._computers = computers if computers is not None else [
            {"dNSHostName": "ws01.corp.local"},
            {"dNSHostName": "ws02.corp.local"},
        ]
        self.ldap_conn = object() if ldap_up else None
        self.artifacts_dir = artifacts_dir
        self.base_dn = "DC=corp,DC=local"
        self.domain = "corp.local"
        self.username = "alice"
        self.password = "P@ss"
        self.nt_hash = None
        self.lm_hash = ""
        self.dns_server = None
        self.dns_tcp = False
        self.debug_log = None
        self.log = logging.getLogger("test")

    def ldap_search(self, search_base=None, search_filter=None, attributes=None, **kwargs):
        return list(self._computers)


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def test_parse_identifies_enabled_and_reachable():
    enabled, reachable = wd._parse_webdav_results(SAMPLE_OUTPUT)
    assert reachable == 2
    assert len(enabled) == 1
    assert "WS01" in enabled[0] and "10.0.0.10" in enabled[0]


def test_parse_none_enabled():
    out = (
        "SMB  10.0.0.11  445  WS02  [*] Windows 10\n"
        "SMB  10.0.0.11  445  WS02  [+] corp.local\\alice\n"
    )
    enabled, reachable = wd._parse_webdav_results(out)
    assert enabled == []
    assert reachable == 1


def test_parse_highlight_only_line():
    enabled, _ = wd._parse_webdav_results("WebClient Service enabled on: 10.0.0.5")
    assert enabled == ["10.0.0.5"]


def test_parse_empty():
    assert wd._parse_webdav_results("") == ([], 0)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def test_redact_cmd_masks_password():
    cmd = ["nxc", "smb", "targets.txt", "-u", "alice", "-p", "S3cret", "-M", "webdav"]
    assert wd._redact_cmd(cmd) == "nxc smb targets.txt -u alice -p REDACTED -M webdav"


def test_redact_cmd_masks_hash():
    cmd = ["nxc", "smb", "t.txt", "-u", "alice", "-H", "aad3b:deadbeef"]
    assert "REDACTED" in wd._redact_cmd(cmd)
    assert "deadbeef" not in wd._redact_cmd(cmd)


def test_auth_args_password_and_hash():
    assert wd._build_nxc_smb_auth_args(FakeConnector()) == ["-u", "alice", "-p", "P@ss", "-d", "corp.local"]
    conn = FakeConnector()
    conn.password, conn.nt_hash = None, "deadbeef"
    assert wd._build_nxc_smb_auth_args(conn) == ["-u", "alice", "-H", "deadbeef", "-d", "corp.local"]


def test_enumerate_computers_dedups():
    conn = FakeConnector(computers=[
        {"dNSHostName": "a.corp.local"},
        {"dNSHostName": "a.corp.local"},
        {"cn": "B"},
    ])
    assert wd._enumerate_computers_via_ldap(conn) == ["a.corp.local", "B"]


def test_enumerate_no_ldap_returns_empty():
    assert wd._enumerate_computers_via_ldap(FakeConnector(ldap_up=False)) == []


# ---------------------------------------------------------------------------
# run_check integration
# ---------------------------------------------------------------------------

def test_run_check_tool_missing(monkeypatch):
    monkeypatch.setattr(wd, "ensure_tool", lambda name: None)
    findings = wd.run_check(FakeConnector())
    assert len(findings) == 1 and findings[0]["severity"] == "info"
    assert "NetExec Not Found" in findings[0]["title"]


def test_run_check_no_computers(monkeypatch, tmp_path):
    monkeypatch.setattr(wd, "ensure_tool", lambda name: "/usr/bin/nxc")
    findings = wd.run_check(FakeConnector(computers=[], artifacts_dir=str(tmp_path)))
    assert findings[0]["severity"] == "info"
    assert "No Computers Found" in findings[0]["title"]


def test_run_check_enabled_host_high(monkeypatch, tmp_path):
    monkeypatch.setattr(wd, "ensure_tool", lambda name: "/usr/bin/nxc")
    monkeypatch.setattr(wd, "_run_cmd", lambda cmd, timeout=300: (0, SAMPLE_OUTPUT, ""))
    findings = wd.run_check(FakeConnector(artifacts_dir=str(tmp_path)))
    high = [f for f in findings if f["severity"] == "high"]
    assert len(high) == 1
    assert high[0]["deduction"] == 15
    assert high[0]["affected_count"] == 1
    assert "1 host(s)" in high[0]["title"]
    assert "raw_output" in high[0]


def test_run_check_clean_is_info(monkeypatch, tmp_path):
    monkeypatch.setattr(wd, "ensure_tool", lambda name: "/usr/bin/nxc")
    clean = (
        "SMB  10.0.0.11  445  WS02  [*] Windows 10\n"
        "SMB  10.0.0.11  445  WS02  [+] corp.local\\alice\n"
    )
    monkeypatch.setattr(wd, "_run_cmd", lambda cmd, timeout=300: (0, clean, ""))
    findings = wd.run_check(FakeConnector(artifacts_dir=str(tmp_path)))
    assert all(f["severity"] == "info" for f in findings)
    assert "Not Enabled on Reachable Hosts" in findings[0]["title"]


def test_run_check_writes_targets_file(monkeypatch, tmp_path):
    monkeypatch.setattr(wd, "ensure_tool", lambda name: "/usr/bin/nxc")
    monkeypatch.setattr(wd, "_run_cmd", lambda cmd, timeout=300: (0, SAMPLE_OUTPUT, ""))
    wd.run_check(FakeConnector(artifacts_dir=str(tmp_path)))
    written = list(tmp_path.glob("computers_*.txt"))
    assert len(written) == 1
    assert "ws01.corp.local" in written[0].read_text()
