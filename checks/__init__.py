"""
checks/__init__.py

ADScan Check Module Package

Each check module in this directory must expose:

  CHECK_NAME  (str)  - Human-readable name shown during scanning
  CHECK_ORDER (int)  - Optional run order (lower = runs first, default: 99)

  run_check(connector: ADConnector, verbose: bool = False) -> list[dict] | None

Each returned finding dict must contain:
  {
    "title":          str,   # Short finding title
    "severity":       str,   # critical / high / medium / low / info
    "deduction":      int,   # Points deducted from 100 (0-30 recommended per finding)
    "description":    str,   # Detailed description
    "recommendation": str,   # Remediation guidance
    "details":        list,  # Affected objects / raw evidence (optional)
  }

To add a new check:
  1. Create a new .py file in this directory (e.g. checks/my_check.py)
  2. Define CHECK_NAME and optionally CHECK_ORDER
  3. Implement run_check(connector, verbose=False)
  4. Return a list of finding dicts, or None / [] if no issues found

The check will be automatically discovered and executed on the next run.
"""
