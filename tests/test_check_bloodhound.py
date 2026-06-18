"""
tests/test_check_bloodhound.py

Unit tests for checks/check_bloodhound.py engine selection and the
preflight() hook that hoists the engine prompt ahead of the scan loop.
The prompt itself is exercised with sys.stdin.isatty and builtins.input
monkeypatched, and run_check is exercised with ensure_tool monkeypatched
so no real bloodhound ingestor subprocess is launched.
"""
import logging

from checks import check_bloodhound as bh


class FakeConnector:
    def __init__(self, **attrs):
        self.domain = "corp.local"
        self.dc_host = "dc01.corp.local"
        self.username = "alice"
        self.password = "P@ss"
        self.nt_hash = None
        self.lm_hash = ""
        self.dns_server = None
        self.dns_tcp = False
        self.log = logging.getLogger("test")
        for k, v in attrs.items():
            setattr(self, k, v)


# ---------------------------------------------------------------------------
# _prompt_engine
# ---------------------------------------------------------------------------

def test_prompt_engine_non_interactive_defaults_to_legacy(monkeypatch):
    monkeypatch.setattr(bh.sys.stdin, "isatty", lambda: False)
    assert bh._prompt_engine(FakeConnector()) == "legacy"


def test_prompt_engine_choice_two_selects_ce(monkeypatch):
    monkeypatch.setattr(bh.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "2")
    assert bh._prompt_engine(FakeConnector()) == "ce"


def test_prompt_engine_default_is_legacy(monkeypatch):
    monkeypatch.setattr(bh.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": "")
    assert bh._prompt_engine(FakeConnector()) == "legacy"


# ---------------------------------------------------------------------------
# preflight hook
# ---------------------------------------------------------------------------

def test_preflight_stores_engine_on_connector(monkeypatch):
    monkeypatch.setattr(bh, "_prompt_engine", lambda connector: "ce")
    conn = FakeConnector()
    bh.preflight(conn)
    assert conn.bloodhound_engine == "ce"


# ---------------------------------------------------------------------------
# run_check honours the pre-selected engine without re-prompting
# ---------------------------------------------------------------------------

def test_run_check_uses_preflight_engine_without_prompting(monkeypatch):
    def _boom(connector):
        raise AssertionError("run_check must not prompt when engine is pre-set")

    monkeypatch.setattr(bh, "_prompt_engine", _boom)
    # ensure_tool -> None makes run_check return early after the engine is
    # resolved, so the finding title tells us which engine was selected.
    monkeypatch.setattr(bh, "ensure_tool", lambda name: None)

    findings = bh.run_check(FakeConnector(bloodhound_engine="ce"))

    assert len(findings) == 1
    assert "bloodhound-ce-python Not Found" in findings[0]["title"]


def test_run_check_falls_back_to_prompt_when_engine_unset(monkeypatch):
    monkeypatch.setattr(bh, "_prompt_engine", lambda connector: "legacy")
    monkeypatch.setattr(bh, "ensure_tool", lambda name: None)

    findings = bh.run_check(FakeConnector())  # no bloodhound_engine attribute

    assert len(findings) == 1
    assert "bloodhound-python Not Found" in findings[0]["title"]
