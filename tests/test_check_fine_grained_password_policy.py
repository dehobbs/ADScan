"""
tests/test_check_fine_grained_password_policy.py

Unit tests for checks/check_fine_grained_password_policy.py. The PSO evaluation
logic is pure (no LDAP), and run_check is exercised through a minimal fake
connector that returns canned msDS-PasswordSettings entries.
"""
import logging

from checks import check_fine_grained_password_policy as pso_check

# FILETIME helpers: AD stores these durations as negative 100-nanosecond units.
DAY_TICKS = 10_000_000 * 86_400
MIN_TICKS = 10_000_000 * 60
NEVER_EXPIRES = -0x8000000000000000   # msDS-MaximumPasswordAge "never" sentinel


def _days(d):
    return -(d * DAY_TICKS)


def _mins(m):
    return -(m * MIN_TICKS)


def _strong_pso(**overrides):
    """A PSO that meets every recommended threshold."""
    base = {
        "cn": "Strong-PSO",
        "distinguishedName": "CN=Strong-PSO,CN=Password Settings Container,CN=System,DC=corp,DC=local",
        "msDS-PasswordSettingsPrecedence": 10,
        "msDS-MinimumPasswordLength": 15,
        "msDS-PasswordComplexityEnabled": True,
        "msDS-PasswordReversibleEncryptionEnabled": False,
        "msDS-LockoutThreshold": 5,
        "msDS-MaximumPasswordAge": _days(90),
        "msDS-MinimumPasswordAge": _days(1),
        "msDS-LockoutObservationWindow": _mins(30),
        "msDS-PSOAppliesTo": "CN=Some Group,OU=Groups,DC=corp,DC=local",
    }
    base.update(overrides)
    return base


class FakeConnector:
    def __init__(self, entries):
        self._entries = entries
        self.base_dn = "DC=corp,DC=local"
        self.log = logging.getLogger("test")

    def ldap_search(self, search_base=None, search_filter=None, attributes=None, **kwargs):
        return list(self._entries)


# ---------------------------------------------------------------------------
# Pure evaluation logic
# ---------------------------------------------------------------------------

def test_strong_pso_has_no_weaknesses():
    assert pso_check.evaluate_pso(_strong_pso()) == []


def test_no_lockout_is_critical():
    weaknesses = pso_check.evaluate_pso(_strong_pso(**{"msDS-LockoutThreshold": 0}))
    assert pso_check._worst_severity(weaknesses) == "critical"


def test_reversible_encryption_is_critical():
    weaknesses = pso_check.evaluate_pso(
        _strong_pso(**{"msDS-PasswordReversibleEncryptionEnabled": "TRUE"})
    )
    assert pso_check._worst_severity(weaknesses) == "critical"


def test_short_length_is_high():
    weaknesses = pso_check.evaluate_pso(_strong_pso(**{"msDS-MinimumPasswordLength": 8}))
    assert pso_check._worst_severity(weaknesses) == "high"


def test_never_expires_sentinel_is_high():
    weaknesses = pso_check.evaluate_pso(_strong_pso(**{"msDS-MaximumPasswordAge": NEVER_EXPIRES}))
    assert any("never expire" in text.lower() for _, text in weaknesses)
    assert pso_check._worst_severity(weaknesses) == "high"


def test_high_lockout_threshold_is_medium():
    weaknesses = pso_check.evaluate_pso(_strong_pso(**{"msDS-LockoutThreshold": 50}))
    assert pso_check._worst_severity(weaknesses) == "medium"


def test_short_observation_window_is_low_only():
    weaknesses = pso_check.evaluate_pso(_strong_pso(**{"msDS-LockoutObservationWindow": _mins(5)}))
    assert pso_check._worst_severity(weaknesses) == "low"


def test_string_boolean_parsing():
    # ldap3 may return the literal string 'FALSE' rather than a Python bool.
    weaknesses = pso_check.evaluate_pso(_strong_pso(**{"msDS-PasswordComplexityEnabled": "FALSE"}))
    assert any("complexity disabled" in text.lower() for _, text in weaknesses)


# ---------------------------------------------------------------------------
# run_check integration via fake connector
# ---------------------------------------------------------------------------

def test_no_psos_returns_info_only():
    findings = pso_check.run_check(FakeConnector([]))
    assert len(findings) == 1
    assert findings[0]["severity"] == "info"
    assert findings[0]["deduction"] == 0
    assert "No Fine-Grained Password Policies" in findings[0]["title"]


def test_all_strong_psos_returns_clean_info():
    findings = pso_check.run_check(FakeConnector([_strong_pso(), _strong_pso(cn="Strong-2")]))
    assert len(findings) == 1
    assert findings[0]["severity"] == "info"
    assert "No Issues Found" in findings[0]["title"]


def test_weak_pso_produces_finding_with_name_in_title():
    weak = _strong_pso(cn="ServiceAccounts-PSO", **{"msDS-LockoutThreshold": 0})
    findings = pso_check.run_check(FakeConnector([weak]))
    weak_findings = [f for f in findings if f["title"].startswith("Weak Fine-Grained")]
    assert len(weak_findings) == 1
    assert "ServiceAccounts-PSO" in weak_findings[0]["title"]
    assert weak_findings[0]["severity"] == "critical"


def test_privileged_link_escalates_low_to_high():
    # A low-severity weakness becomes high when the PSO is linked to a privileged group.
    weak = _strong_pso(
        cn="VIP-PSO",
        **{
            "msDS-LockoutObservationWindow": _mins(5),
            "msDS-PSOAppliesTo": "CN=Domain Admins,CN=Users,DC=corp,DC=local",
        },
    )
    findings = pso_check.run_check(FakeConnector([weak]))
    weak_findings = [f for f in findings if f["title"].startswith("Weak Fine-Grained")]
    assert len(weak_findings) == 1
    assert weak_findings[0]["severity"] == "high"
    assert "PRIVILEGED" in weak_findings[0]["description"]


def test_multivalue_applies_to_is_handled():
    weak = _strong_pso(
        cn="Multi-PSO",
        **{
            "msDS-MinimumPasswordLength": 6,
            "msDS-PSOAppliesTo": [
                "CN=Group A,DC=corp,DC=local",
                "CN=Group B,DC=corp,DC=local",
            ],
        },
    )
    findings = pso_check.run_check(FakeConnector([weak]))
    weak_findings = [f for f in findings if f["title"].startswith("Weak Fine-Grained")]
    assert len(weak_findings) == 1
    applies_line = [d for d in weak_findings[0]["details"] if d.startswith("Applies to:")][0]
    assert "Group A" in applies_line and "Group B" in applies_line
