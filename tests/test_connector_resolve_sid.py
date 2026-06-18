"""
tests/test_connector_resolve_sid.py

Unit tests for ADConnector.resolve_sid well-known SID handling. Well-known SIDs
(Authenticated Users, SYSTEM, Everyone, BUILTIN groups, ...) are not directory
objects, so an LDAP objectSid lookup cannot resolve them -- they must map to a
friendly name from a static table so reports show names, not raw SIDs.

The connector is constructed without connecting (ldap_conn stays None), which
exercises the table without any network access.
"""
from lib.connector import ADConnector


def _conn():
    return ADConnector(
        domain="corp.local", dc_host="dc01", username="u", password="p",
    )


def test_resolve_authenticated_users():
    assert _conn().resolve_sid("S-1-5-11") == "Authenticated Users"


def test_resolve_system():
    assert _conn().resolve_sid("S-1-5-18") == "SYSTEM"


def test_resolve_everyone():
    assert _conn().resolve_sid("S-1-1-0") == "Everyone"


def test_resolve_builtin_administrators():
    assert _conn().resolve_sid("S-1-5-32-544") == "Administrators"


def test_unknown_domain_sid_without_connection_returns_sid_unchanged():
    sid = "S-1-5-21-1111111111-2222222222-3333333333-1105"
    assert _conn().resolve_sid(sid) == sid


def test_empty_input_returns_input():
    assert _conn().resolve_sid("") == ""
