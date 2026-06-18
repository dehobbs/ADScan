"""
tests/test_check_adminsdholder_acl.py

Unit tests for checks/check_adminsdholder_acl.py expected-principal matching.

Regression focus: well-known privileged groups (Domain Admins, Enterprise
Admins, Schema Admins, Administrators, Domain Controllers) must be recognized
by their SID RID even when SID->name resolution fails and the trustee name is
just the raw SID string. Custom principals must still be flagged.
"""
from checks import check_adminsdholder_acl as adm

DOMAIN = "S-1-5-21-1111111111-2222222222-3333333333"


# ---------------------------------------------------------------------------
# _rid_of
# ---------------------------------------------------------------------------

def test_rid_of_extracts_trailing_rid():
    assert adm._rid_of(f"{DOMAIN}-512") == 512
    assert adm._rid_of("S-1-5-32-544") == 544


def test_rid_of_handles_non_sid_and_empty():
    assert adm._rid_of("") is None
    assert adm._rid_of(None) is None
    assert adm._rid_of("not-a-sid") is None


# ---------------------------------------------------------------------------
# _is_expected: RID match works even when the name is an unresolved raw SID
# ---------------------------------------------------------------------------

def test_domain_admins_expected_by_rid_when_name_unresolved():
    sid = f"{DOMAIN}-512"
    assert adm._is_expected(sid, sid) is True  # name == raw SID (resolution failed)


def test_enterprise_admins_expected_by_rid():
    sid = f"{DOMAIN}-519"
    assert adm._is_expected(sid, sid) is True


def test_schema_admins_expected_by_rid():
    sid = f"{DOMAIN}-518"
    assert adm._is_expected(sid, sid) is True


def test_domain_controllers_expected_by_rid():
    sid = f"{DOMAIN}-516"
    assert adm._is_expected(sid, sid) is True


def test_builtin_administrators_expected():
    assert adm._is_expected("S-1-5-32-544", "S-1-5-32-544") is True


# ---------------------------------------------------------------------------
# Custom / non-privileged principals are still flagged
# ---------------------------------------------------------------------------

def test_custom_user_not_expected_when_name_unresolved():
    sid = f"{DOMAIN}-1105"
    assert adm._is_expected(sid, sid) is False


def test_custom_group_not_expected_by_resolved_name():
    assert adm._is_expected("Tier0-CustomAdmins", f"{DOMAIN}-1240") is False


# ---------------------------------------------------------------------------
# run_check integration: a real binary security descriptor must have its ACE
# SIDs converted to canonical form, so expected principals are NOT flagged.
# Regression for SIDs shown as raw hex blobs (str(sid) instead of
# formatCanonical()) in the report.
# ---------------------------------------------------------------------------

import logging

from impacket.ldap.ldaptypes import (
    SR_SECURITY_DESCRIPTOR, ACL, ACE, ACCESS_ALLOWED_ACE, ACCESS_MASK, LDAP_SID,
)

FULL_CONTROL = 0x000F01FF
# READ_CONTROL | DS_READ_PROP | LIST | LIST_OBJECT -- a benign read-only ACE.
READ_ONLY = 0x00020000 | 0x10 | 0x04 | 0x80
WRITE_DACL = 0x00040000  # WRITE_DAC -- a genuine dangerous write right.

# Privileged principals that ARE allowed full control on AdminSDHolder.
EXPECTED_CANON = [
    f"{DOMAIN}-512",   # Domain Admins
    f"{DOMAIN}-519",   # Enterprise Admins
    "S-1-5-32-544",    # BUILTIN\\Administrators
    "S-1-5-18",        # SYSTEM
]
AUTH_USERS = "S-1-5-11"          # low-priv: read OK, write must be flagged
CUSTOM_CANON = f"{DOMAIN}-1105"  # a non-privileged account -> must be flagged


def _sid_bytes(canonical):
    sid = LDAP_SID()
    sid.fromCanonical(canonical)
    return sid.getData()


def _build_sd_mixed(sid_mask_pairs):
    """Build a self-relative SD whose DACL has one allow-ACE per (sid, mask)."""
    dacl = ACL()
    dacl["AclRevision"] = 0x02
    dacl["Sbz1"] = 0
    dacl["Sbz2"] = 0
    aces = []
    for canon, mask in sid_mask_pairs:
        aa = ACCESS_ALLOWED_ACE()
        aa["Mask"] = ACCESS_MASK()
        aa["Mask"]["Mask"] = mask
        aa["Sid"] = _sid_bytes(canon)
        ace = ACE()
        ace["AceType"] = ACCESS_ALLOWED_ACE.ACE_TYPE
        ace["AceFlags"] = 0x00
        ace["Ace"] = aa
        aces.append(ace)
    dacl.aces = aces
    sd = SR_SECURITY_DESCRIPTOR()
    sd["Revision"] = b"\x01"
    sd["Sbz1"] = b"\x00"
    sd["Control"] = 0x8004  # SE_SELF_RELATIVE | SE_DACL_PRESENT
    sd["OwnerSid"] = b""
    sd["GroupSid"] = b""
    sd["Sacl"] = b""
    sd["Dacl"] = dacl
    return sd.getData()


def _build_sd(canonical_sids, mask=FULL_CONTROL):
    return _build_sd_mixed([(s, mask) for s in canonical_sids])


class SDConnector:
    def __init__(self, raw_sd):
        self.base_dn = "DC=corp,DC=local"
        self._raw_sd = raw_sd
        self.log = logging.getLogger("test")

    def ldap_search(self, **kwargs):
        return [{"nTSecurityDescriptor": self._raw_sd, "cn": "AdminSDHolder"}]

    def resolve_sid(self, sid):
        # Mirror the real connector: well-known SIDs resolve to a friendly
        # name; everything else (no live LDAP) returns the SID unchanged.
        from lib.connector import WELL_KNOWN_SIDS
        return WELL_KNOWN_SIDS.get(sid, sid)


def test_run_check_expected_principals_not_flagged():
    raw = _build_sd(EXPECTED_CANON)
    findings = adm.run_check(SDConnector(raw))
    assert len(findings) == 1
    assert findings[0]["severity"] == "info"
    assert "No unexpected" in findings[0]["title"]


def test_run_check_flags_only_custom_principal_with_canonical_sid():
    raw = _build_sd(EXPECTED_CANON + [CUSTOM_CANON])
    findings = adm.run_check(SDConnector(raw))
    assert len(findings) == 1
    f = findings[0]
    assert f["severity"] == "critical"
    assert "1 unexpected" in f["title"]
    # Exactly the custom principal, shown as a canonical SID -- never a hex blob.
    assert len(f["details"]) == 1
    assert CUSTOM_CANON in f["details"][0]
    assert "0105" not in f["details"][0]


# ---------------------------------------------------------------------------
# Authenticated Users: read access is fine, write access must be flagged.
# (Auth Users is NOT in the expected-privileged allowlist.)
# ---------------------------------------------------------------------------

def test_authenticated_users_not_in_expected_allowlist():
    assert adm._is_expected("Authenticated Users", AUTH_USERS) is False


def test_run_check_authenticated_users_read_only_not_flagged():
    # A read-only ACE must not be reported as a write violation.
    findings = adm.run_check(SDConnector(_build_sd_mixed(
        [(s, FULL_CONTROL) for s in EXPECTED_CANON] + [(AUTH_USERS, READ_ONLY)]
    )))
    assert len(findings) == 1
    assert findings[0]["severity"] == "info"
    assert "No unexpected" in findings[0]["title"]


def test_run_check_authenticated_users_with_write_is_flagged():
    findings = adm.run_check(SDConnector(_build_sd_mixed(
        [(s, FULL_CONTROL) for s in EXPECTED_CANON] + [(AUTH_USERS, WRITE_DACL)]
    )))
    assert len(findings) == 1
    f = findings[0]
    assert f["severity"] == "critical"
    assert "1 unexpected" in f["title"]
    # Report shows the friendly name (and the SID), not a bare SID.
    assert "Authenticated Users" in f["details"][0]
    assert AUTH_USERS in f["details"][0]
    assert "WriteDACL" in f["details"][0]

