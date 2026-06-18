"""
tests/test_preflight.py

Unit tests for adscan.run_preflight -- the generic hook runner that invokes
each loaded check's optional preflight(connector) before the scan loop. A
buggy hook must not abort the scan; remaining hooks still run.
"""
import logging
import types

import adscan


def _module(name, **attrs):
    m = types.ModuleType(name)
    for k, v in attrs.items():
        setattr(m, k, v)
    return m


def test_run_preflight_invokes_hooks_in_order():
    calls = []
    a = _module("a", CHECK_NAME="A", preflight=lambda c: calls.append("a"))
    b = _module("b", CHECK_NAME="B")  # no preflight hook -> skipped
    c = _module("c", CHECK_NAME="C", preflight=lambda c: calls.append("c"))

    adscan.run_preflight([a, b, c], object(), logging.getLogger("test"))

    assert calls == ["a", "c"]


def test_run_preflight_swallows_hook_exceptions():
    def _boom(connector):
        raise RuntimeError("nope")

    ran = []
    a = _module("a", CHECK_NAME="A", preflight=_boom)
    b = _module("b", CHECK_NAME="B", preflight=lambda c: ran.append("b"))

    # Must not raise, and b still runs after a's hook fails.
    adscan.run_preflight([a, b], object(), logging.getLogger("test"))

    assert ran == ["b"]
