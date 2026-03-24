""" checks/check_dangerous_constrained_delegation.py

DEPRECATED — logic merged into check_constrained_delegation.py.
This stub exists only to avoid import errors and is a no-op.
"""

CHECK_NAME     = "Dangerous Constrained Delegation Targets"
CHECK_ORDER    = 69
CHECK_CATEGORY = ["Kerberos"]


def run_check(connector, verbose=False):
    """No-op stub. DC-targeting analysis now runs inside check_constrained_delegation."""
    return []
