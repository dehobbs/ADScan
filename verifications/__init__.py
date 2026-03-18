"""
verifications/ - Modular Manual Verification and Remediation data for ADScan.

Each verify_*.py module in this package defines verification tool cards and
remediation guidance for one or more ADScan findings.

Module constants required by the auto-discovery system in lib/report.py:
    MATCH_KEYS  (list[str])  -- lowercase substrings matched against finding titles
    TOOLS       (list[dict]) -- tool card definitions for the Manual Verification section
    REMEDIATION (dict)       -- remediation guidance with title and steps
"""
