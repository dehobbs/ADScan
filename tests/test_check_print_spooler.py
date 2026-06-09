"""
tests/test_check_print_spooler.py

Unit tests for checks/check_print_spooler.py. Output parsing and argument
building are pure; run_check is exercised with ensure_tool and _scan_dc
monkeypatched so no real nxc subprocess is launched.
"""
import logging

from checks import check_print_spooler as spooler


class FakeConnector:
    def __init__(self, dc_entries=None, **attrs):
        self._dc_entries = dc_entries if dc_entries is not None else [
            {"dNSHostName": "dc01.corp.local"},
            {"dNSHostName": "dc02.corp.local"},
        ]
        self.base_dn = "DC=corp,DC=local"
        self.dc_host = "dc01.corp.local"
        self.domain = "corp.local"
        self.username = "alice"
        self.password = "P@ss"
        self.nt_hash = None
        self.lm_hash = ""
        self.dns_server = None
        self.dns_tcp = False
        self.log = logging.getLogger("test")
        for k, v in attrs.items():
            setattr(self, k, v)

    def ldap_search(self, search_base=None, search_filter=None, attributes=None, **kwargs):
        return list(self._dc_entries)


# ---------------------------------------------------------------------------
# Output parsing
# ---------------------------------------------------------------------------

def test_parse_enabled():
    out = "SPOOLER  10.0.0.1  445  DC01  Spooler service enabled"
    assert spooler._parse_spooler_status(out) == "enabled"


def test_parse_disabled():
    out = "SPOOLER  10.0.0.1  445  DC01  Spooler service disabled"
    assert spooler._parse_spooler_status(out) == "disabled"


def test_parse_inconclusive():
    assert spooler._parse_spooler_status("connection refused / timeout") is None


def test_parse_is_case_insensitive():
    assert spooler._parse_spooler_status("SPOOLER SERVICE ENABLED") == "enabled"


# ---------------------------------------------------------------------------
# Argument builders
# ---------------------------------------------------------------------------

def test_auth_args_password():
    args = spooler._build_auth_args(FakeConnector())
    assert args == ["-d", "corp.local", "-u", "alice", "-p", "P@ss"]


def test_auth_args_hash_pth():
    conn = FakeConnector(password=None, nt_hash="abc123", lm_hash="")
    args = spooler._build_auth_args(conn)
    assert args == ["-d", "corp.local", "-u", "alice", "-H", "abc123"]


def test_dns_args_forwarded():
    conn = FakeConnector(dns_server="10.0.0.1", dns_tcp=True)
    assert spooler._build_dns_args(conn) == ["--dns-server", "10.0.0.1", "--dns-tcp"]


def test_dns_args_empty_by_default():
    assert spooler._build_dns_args(FakeConnector()) == []


# ---------------------------------------------------------------------------
# DC enumeration
# ---------------------------------------------------------------------------

def test_get_dc_hosts_from_ldap():
    hosts = spooler._get_dc_hosts(FakeConnector())
    assert hosts == ["dc01.corp.local", "dc02.corp.local"]


def test_get_dc_hosts_falls_back_to_dc_host():
    hosts = spooler._get_dc_hosts(FakeConnector(dc_entries=[]))
    assert hosts == ["dc01.corp.local"]


# ---------------------------------------------------------------------------
# run_check integration (ensure_tool + _scan_dc monkeypatched)
# ---------------------------------------------------------------------------

def test_run_check_tool_missing(monkeypatch):
    monkeypatch.setattr(spooler, "ensure_tool", lambda name: None)
    findings = spooler.run_check(FakeConnector())
    assert len(findings) == 1
    assert findings[0]["severity"] == "info"
    assert "NetExec Not Found" in findings[0]["title"]


def test_run_check_enabled_dc_produces_high_finding(monkeypatch):
    monkeypatch.setattr(spooler, "ensure_tool", lambda name: "/usr/bin/nxc")
    statuses = {"dc01.corp.local": "enabled", "dc02.corp.local": "disabled"}
    monkeypatch.setattr(spooler, "_scan_dc",
                        lambda exe, auth, dns, dc, log: statuses[dc])
    findings = spooler.run_check(FakeConnector())
    high = [f for f in findings if f["severity"] == "high"]
    assert len(high) == 1
    assert high[0]["deduction"] == 15
    assert high[0]["details"] == ["dc01.corp.local"]
    assert "1 DC(s)" in high[0]["title"]


def test_run_check_all_disabled_is_clean(monkeypatch):
    monkeypatch.setattr(spooler, "ensure_tool", lambda name: "/usr/bin/nxc")
    monkeypatch.setattr(spooler, "_scan_dc",
                        lambda exe, auth, dns, dc, log: "disabled")
    findings = spooler.run_check(FakeConnector())
    assert findings == []


def test_run_check_inconclusive_reports_info(monkeypatch):
    monkeypatch.setattr(spooler, "ensure_tool", lambda name: "/usr/bin/nxc")
    monkeypatch.setattr(spooler, "_scan_dc",
                        lambda exe, auth, dns, dc, log: None)
    findings = spooler.run_check(FakeConnector())
    assert len(findings) == 1
    assert findings[0]["severity"] == "info"
    assert "Inconclusive" in findings[0]["title"]
    assert set(findings[0]["details"]) == {"dc01.corp.local", "dc02.corp.local"}
