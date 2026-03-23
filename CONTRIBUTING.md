# Contributing to ADScan

Thank you for your interest in improving ADScan. The most impactful way to
contribute is to write a new security check; the auto-discovery system means
a single well-formed Python file is all it takes.

This guide covers everything you need to write, test, and submit a check.

---

## Table of Contents

1. [Project layout](#project-layout)
2. [How auto-discovery works](#how-auto-discovery-works)
3. [Check module interface](#check-module-interface)
   - [Module-level constants](#module-level-constants)
   - [The `run_check` function](#the-run_check-function)
   - [The `connector` object](#the-connector-object)
   - [Finding schema](#finding-schema)
4. [Severity and deduction guidelines](#severity-and-deduction-guidelines)
5. [Step-by-step: writing your first check](#step-by-step-writing-your-first-check)
6. [Complete minimal example](#complete-minimal-example)
7. [Naming and ordering conventions](#naming-and-ordering-conventions)
8. [Scoring config integration](#scoring-config-integration)
9. [Common patterns and helpers](#common-patterns-and-helpers)
10. [Adding Manual Verification, Remediation, and References](#adding-manual-verification-remediation-and-references)
11. [Submitting a pull request](#submitting-a-pull-request)

---

## Project layout

```
ADScan/
├── adscan.py            # Entry point: arg parsing, check runner, report dispatch
├── scoring.toml         # Optional per-check severity weight overrides
├── requirements.txt
├── checks/              # Drop new check_*.py files here
│   ├── __init__.py
│   ├── check_password_policy.py
│   ├── check_kerberos.py
│   └── ...              # 37 built-in checks
├── lib/
    │   ├── connector.py     # ADConnector, LDAP/LDAPS/SMB connection manager
    │   ├── report.py        # HTML / JSON / CSV report generators
    │   ├── scoring.py       # ScoringConfig, loads scoring.toml
    │   ├── audit_log.py     # Structured audit trail
    │   └── debug_log.py     # Low-level LDAP query debug log
    └── verifications/           # Manual verification & remediation data
        ├── verify_kerberoast.py
        ├── verify_laps.py
        └── ...                  # one file per check topic
```

---

## How auto-discovery works

At startup `adscan.py` does the following:

```python
import importlib, glob
modules = sorted(
    glob.glob("checks/check_*.py"),
    key=lambda p: getattr(importlib.import_module(...), "CHECK_ORDER", 999)
)
```

Any file whose name matches `checks/check_*.py` is imported and its
`run_check()` function is called automatically. No registration step is
required — just drop the file in `checks/` and it runs.

---

## Check module interface

### Module-level constants

Every check module **must** define these three names at the top level:

| Name | Type | Purpose |
|------|------|---------|
| `CHECK_NAME` | `str` | Human-readable name shown in the report header and console |
| `CHECK_ORDER` | `int` | Sort order for execution and report display (lower = earlier) |
| `CHECK_CATEGORY` | `list[str]` | One or more category labels (used for report grouping) |

```python
CHECK_NAME     = "My New Check"
CHECK_ORDER    = 70          # choose a number not already used by another check
CHECK_CATEGORY = ["Account Hygiene"]
```

See [Naming and ordering conventions](#naming-and-ordering-conventions) for
the current `CHECK_ORDER` allocation table.

### The `run_check` function

The entry point that ADScan calls for every check:

```python
def run_check(connector, verbose=False):
    """
    Execute this check against the target domain controller.

    Parameters
    ----------
    connector : ADConnector
        Active connection manager. Use connector.ldap_search() for LDAP
        queries and connector.smb_available() / connector.get_smb_shares()
        for SMB operations.
    verbose : bool
        When True, print additional diagnostic output to stdout.
        Controlled by the -v / --verbose CLI flag.

    Returns
    -------
    list[dict]
        A list of finding dictionaries. Return an empty list if the check
        cannot run (e.g. no LDAP connection). Never return None.
    """
    findings = []
    # ... your logic here ...
    return findings
```

**Rules:**

- Always return a `list`. An empty list means "nothing to report"; the check
  is silently skipped in the report.
- Never `raise` exceptions out of `run_check`. Catch all exceptions and
  return a single info-severity finding with `deduction: 0` describing the
  error (see [Common patterns](#common-patterns-and-helpers)).
- Never call `sys.exit()` or modify global state.

### The `connector` object

`connector` is an instance of `lib.connector.ADConnector`. The public API
available to check modules is:

| Method / Attribute | Description |
|--------------------|-------------|
| `connector.domain` | Target domain FQDN (e.g. `corp.local`) |
| `connector.base_dn` | LDAP base DN (e.g. `DC=corp,DC=local`) |
| `connector.dc_host` | Domain controller hostname or IP |
| `connector.ldap_search(search_filter, attributes, search_base)` | Perform an LDAP search; returns a list of `ldap3` result entries or `[]` |
| `connector.smb_available()` | Returns `True` if an SMB session is active |
| `connector.get_smb_shares()` | Returns a list of share name strings |
| `connector.verbose` | Mirror of the `--verbose` CLI flag |

**`ldap_search` signature:**

```python
entries = connector.ldap_search(
    search_filter="(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))",
    attributes=["sAMAccountName", "distinguishedName"],
    search_base=None,   # defaults to connector.base_dn
)
```

Each entry in the returned list is an `ldap3` entry object. Access attributes
safely:

```python
for entry in entries:
    # Safe attribute access; always guard with try/except
    try:
        sam = entry["sAMAccountName"].value
    except Exception:
        sam = "?"
```

Or use the dict-based pattern (entries returned as dicts when using
`ldap3.RESTARTABLE` strategy; check the connector for the active strategy):

```python
def _get_attr(entry, key):
    """Return a normalised string value for an ldap3 result entry attribute."""
    try:
        attrs = entry.get("attributes", {}) if isinstance(entry, dict) else {}
        val = attrs.get(key)
        if val is None:
            return None
        return str(val) if not hasattr(val, "value") else str(val.value)
    except Exception:
        return None
```

### Finding schema

Each dict in the returned list **must** contain these keys:

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `title` | `str` | ✅ | Short, unique, descriptive title. Shown in the report card header and used as the key for `scoring.toml` overrides. |
| `severity` | `str` | ✅ | One of: `critical`, `high`, `medium`, `low`, `info` (case-insensitive) |
| `deduction` | `int` | ✅ | Points deducted from the risk score (0–20). See guidelines below. |
| `description` | `str` | ✅ | 2–5 sentence explanation of the issue and its impact. |
| `recommendation` | `str` | ✅ | Actionable remediation guidance. |
| `details` | `list[str]` | ✅ | Specific affected objects (account names, DNs, GPO names, etc.). Pass `[]` if none. |

> **Note:** `deduction` is the *default* value used when no `scoring.toml`
> override applies. The scoring engine may replace it at runtime; your
> hardcoded value is always the safe fallback.

---

## Severity and deduction guidelines

Use these bands consistently so the risk score remains comparable across
engagements:

| Severity | Deduction range | When to use |
|----------|-----------------|-------------|
| `critical` | 20 | Immediate, trivially exploitable, or equivalent to domain compromise (e.g. no lockout policy, reversible password encryption) |
| `high` | 12–15 | Significant attack surface with clear exploitation path (e.g. Kerberoastable service accounts, unconstrained delegation on non-DCs) |
| `medium` | 6–10 | Meaningful risk that requires additional conditions to exploit (e.g. accounts not in Protected Users, weak password length) |
| `low` | 3–5 | Defence-in-depth gap or best-practice deviation (e.g. short lockout observation window) |
| `info` | 0 | Observation only, clean-pass confirmation, or check error — no score impact |

**Tips:**
- A check that finds no issues should return a single `info / deduction=0`
  finding with a title like `"My Check: No Issues Found"`. This provides
  visible evidence in the report that the check ran and passed.
- Do not return multiple findings at the same severity for the same root
  cause; collapse them into one finding with a `details` list.

---

## Step-by-step: writing your first check

**1. Choose a name and order number.**
   Pick a `CHECK_ORDER` integer not already used. See the allocation table
   in [Naming and ordering conventions](#naming-and-ordering-conventions).
   If in doubt, use a number > 90.

**2. Create the file.**
   Name it `checks/check_<topic>.py` using lowercase and underscores.

**3. Define the module constants.**
   `CHECK_NAME`, `CHECK_ORDER`, `CHECK_CATEGORY` at the top of the file.

**4. Write `run_check(connector, verbose=False)`.**
   - Query LDAP with `connector.ldap_search()`.
   - Evaluate results against your security criteria.
   - Build a list of finding dicts.
   - Return the list.

**5. Handle errors gracefully.**
   Wrap the body in a `try/except Exception as e` and return an
   `info / deduction=0` finding on failure.

**6. Verify auto-discovery.**
   Run `python adscan.py -d test.local --dc-ip 127.0.0.1 -u user -p pass`
   (even against a non-existent target) and look for your `CHECK_NAME` in
   the startup banner; it will appear even if the LDAP connection fails.

---

## Complete minimal example

```python
"""
checks/check_example_stale_computers.py - Stale Computer Accounts

Flags enabled computer accounts that have not authenticated in over 90 days.
Stale computer accounts are a persistence and enumeration risk.
"""

from datetime import datetime, timezone, timedelta

CHECK_NAME     = "Stale Computer Accounts"
CHECK_ORDER    = 95
CHECK_CATEGORY = ["Account Hygiene"]

_STALE_DAYS = 90


def run_check(connector, verbose=False):
    findings = []
    try:
        # LDAP filter: enabled computers only
        entries = connector.ldap_search(
            search_filter="(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            attributes=["sAMAccountName", "lastLogonTimestamp"],
        )

        cutoff = datetime.now(timezone.utc) - timedelta(days=_STALE_DAYS)
        stale = []

        for entry in entries:
            try:
                ts = entry["lastLogonTimestamp"].value
                # ldap3 returns datetime objects for LDAP GeneralizedTime
                if isinstance(ts, datetime):
                    if ts.tzinfo is None:
                        ts = ts.replace(tzinfo=timezone.utc)
                    if ts < cutoff:
                        sam = entry["sAMAccountName"].value
                        stale.append(f"{sam} (last logon: {ts.date()})")
                        if verbose:
                            print(f"  [!] Stale computer: {sam}")
            except Exception:
                continue

        if stale:
            findings.append({
                "title": f"Stale Computer Accounts: {len(stale)} account(s)",
                "severity": "low",
                "deduction": 5,
                "description": (
                    f"{len(stale)} enabled computer account(s) have not authenticated "
                    f"in over {_STALE_DAYS} days. Stale accounts expand the attack "
                    "surface and may indicate abandoned or forgotten systems."
                ),
                "recommendation": (
                    "Disable or delete computer accounts inactive for more than "
                    f"{_STALE_DAYS} days after confirming the machines are decommissioned. "
                    "Use fine-grained policies if different retention periods are required."
                ),
                "details": stale,
            })
        else:
            findings.append({
                "title": "Stale Computer Accounts: No Issues Found",
                "severity": "info",
                "deduction": 0,
                "description": (
                    f"All enabled computer accounts have authenticated within the last "
                    f"{_STALE_DAYS} days."
                ),
                "recommendation": "Continue to review stale accounts periodically.",
                "details": [],
            })

    except Exception as e:
        findings.append({
            "title": "Stale Computer Accounts: Check Encountered an Error",
            "severity": "info",
            "deduction": 0,
            "description": f"The check could not complete: {e}",
            "recommendation": "Verify LDAP connectivity and account permissions.",
            "details": [str(e)],
        })

    return findings
```

---

## Naming and ordering conventions

**File naming:** `checks/check_<topic>.py`; lowercase, underscores, no spaces.

**`CHECK_ORDER` allocation (built-in checks):**

| Range | Domain |
|-------|--------|
| 1–9 | Password policies |
| 10–19 | Account hygiene (stale accounts, disabled accounts) |
| 20–29 | Privileged account configuration |
| 30–39 | Kerberos (AS-REP, Kerberoasting, encryption types, RC4) |
| 40–49 | Delegation (unconstrained, constrained, RBCD) |
| 50–59 | SMB and legacy protocol security |
| 60–69 | Privileged group membership (Protected Users, AdminSDHolder) |
| 70–79 | Certificate services (ADCS) |
| 80–89 | GPO, audit policy, LAPS, domain trusts |
| 90–99 | Infrastructure (domain controllers, replication, DNS, subnets) |
| 100+  | Miscellaneous / custom checks |

New checks in the 100+ range are safest; they will not collide with
built-in checks added in future releases.

**`CHECK_CATEGORY` values in current use:**
`Account Hygiene`, `Kerberos`, `Delegation`, `Privileged Accounts`,
`Password Policy`, `SMB`, `Legacy Protocols`, `Certificate Services`,
`GPO`, `LAPS`, `Domain Trusts`, `Infrastructure`, `Audit Policy`,
`Miscellaneous`

You may introduce new category names; they will appear as a new section
in the HTML report.

---

## Scoring config integration

The `deduction` value you hardcode in each finding dict is used as-is unless
the operator has configured `scoring.toml`. No action is required from check
authors, the scoring engine applies overrides transparently at runtime.

However, to make your check override-friendly, follow these two practices:

**1. Use stable, descriptive `title` strings.**
The `[overrides]` section in `scoring.toml` matches on the exact finding
`title`. Titles that change between versions break operator overrides. If you
need to include a dynamic count (e.g. `"X account(s)"`), put it in
`description` rather than `title`, or keep the variable part minimal and
document it.

**2. Choose a consistent `severity` tier.**
The `[severity_weights]` fallback in `scoring.toml` uses the `severity`
field. Operators who have not written an explicit title override will rely on
this tier. Assigning an inconsistent severity undermines their config.

To add a suggested override entry to `scoring.toml` for your check, simply
uncomment or add a line in the `[overrides]` section:

```toml
[overrides]
# Stale Computer Accounts: 3 account(s) = 4   # reduce from default 5
```

> Note: title matching in `[overrides]` is case-sensitive and must be an
> exact match to the `title` field of the finding dict.

---

## Common patterns and helpers

**Safe LDAP attribute access (dict-style entries):**

```python
def _get_attr(entry, key, default=None):
    try:
        attrs = entry.get("attributes", {}) if isinstance(entry, dict) else {}
        val = attrs.get(key)
        if val is None:
            return default
        return str(val) if not hasattr(val, "value") else str(val.value)
    except Exception:
        return default
```

**Checking a UAC flag:**

```python
_UAC_DISABLED = 0x2
_UAC_DONT_REQUIRE_PREAUTH = 0x400000

def _uac_flag_set(entry, flag):
    try:
        uac = int(entry["userAccountControl"].value)
        return bool(uac & flag)
    except Exception:
        return False
```

**Converting LDAP FileTime to days:**

```python
def _filetime_to_days(filetime_val):
    try:
        val = int(filetime_val)
        if val == 0:
            return 0   # never expires
        return int(abs(val) / (10_000_000 * 86_400))
    except (TypeError, ValueError):
        return None
```

**Graceful error finding:**

```python
except Exception as e:
    findings.append({
        "title": "My Check: Check Encountered an Error",
        "severity": "info",
        "deduction": 0,
        "description": f"The check could not complete: {e}",
        "recommendation": "Verify LDAP connectivity and permissions.",
        "details": [str(e)],
    })
```

**Verbose output convention:**

```python
if verbose:
    print(f"  [*] Checking {something} ...")
    print(f"  [!] Found issue: {detail}")
    print(f"  [OK] No issues for {topic}")
```

Use two-space indentation for `[*]`/`[!]`/`[OK]` prefixes so output aligns
with the main runner's console style.

---

## Adding Manual Verification, Remediation, and References

Every finding in the HTML report can display three collapsible panels below the description:

- **Manual Verification**: step-by-step tool cards showing how to confirm the finding by hand.
- **Remediation**: numbered steps with optional code blocks for fixing the issue.
- **References**: tagged links to CVEs, MITRE techniques, vendor docs, and research.

These panels are driven by files in the `verifications/` directory. Each file is a plain Python module that defines structured data; no HTML required. `report.py` discovers and renders them automatically.

---

### How the matching works

`report.py` calls `_build_verification_db()` at startup, which imports every `verifications/verify_*.py` module and builds a lookup table keyed on `MATCH_KEYS`. When rendering a finding card, it lowercases the finding `title` and checks whether any key in `MATCH_KEYS` is a substring of it. The first match wins.

```
finding title (lowercased): "account lockout disabled"
MATCH_KEYS = ["account lockout"]   ← "account lockout" ⊂ title → match ✓
```

`MATCH_KEYS` entries should be distinctive enough to avoid false matches across different findings, but broad enough to cover all severity variants of the same issue (e.g. `"kerberoast"` matches both `"Kerberoastable Service Accounts"` and `"High-Value Kerberoastable Accounts"`).

---

### File naming and location

| Convention | Example |
|------------|---------|
| Location | `verifications/verify_<topic>.py` |
| Naming | `verify_kerberoast.py`, `verify_laps.py`, `verify_account_lockout.py` |
| Topic | Match the check slug (use the same stem as the corresponding `check_*.py` file) |

---

### Module structure

A verification file defines up to four module-level names:

| Name | Type | Required | Purpose |
|------|------|----------|---------|
| `MATCH_KEYS` | `list[str]` | ✅ | Lowercase substrings matched against finding titles |
| `TOOLS` | `list[dict]` | ✅ | Tool cards shown in the Manual Verification panel |
| `REMEDIATION` | `dict` | recommended | Numbered steps shown in the Remediation panel |
| `REFERENCES` | `list[dict]` | recommended | Tagged links shown in the References panel |

---

### TOOLS

Each entry in `TOOLS` renders as one card in a 2-column grid. Cards whose `icon` is `"netexec"` or `"impacket"` are placed on the **Linux** tab; all others (`"ps"`, `"cmd"`, `"aduc"`) go on the **Windows** tab.

**Tool card keys:**

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `tool` | `str` | ✅ | Display name in the card header (e.g. `"NetExec"`, `"PowerShell"`) |
| `icon` | `str` | ✅ | One of: `"netexec"`, `"impacket"`, `"ps"`, `"cmd"`, `"aduc"` |
| `desc` | `str` | ✅ | One-sentence description of what this tool does for this check |
| `code` | `str` | — | Command to run (rendered as a monospace code block) |
| `steps` | `list[str]` | — | Numbered steps for GUI tools; use instead of or alongside `code` |
| `confirm` | `str` | — | Italic text explaining what output confirms the finding; supports inline HTML |

Use `code` for CLI tools. Use `steps` for GUI tools (ADUC, GPMC). `confirm` is always shown at the bottom of the card regardless of which body fields are used.

**Example" CLI tool:**

```python
{
    "tool": "NetExec",
    "icon": "netexec",
    "desc": "Enumerate Kerberoastable accounts quickly without retrieving hashes.",
    "code": "netexec ldap <DC_IP> -u <username> -p <password> --kerberoasting",
    "confirm": "Any account listed is Kerberoastable.",
},
```

**Example: GUI tool with numbered steps:**

```python
{
    "tool": "ADUC (dsa.msc)",
    "icon": "aduc",
    "desc": "Find user accounts with SPNs via the GUI attribute editor.",
    "steps": [
        "Open <code>dsa.msc</code> → View → Advanced Features",
        "Find a user → Properties → Attribute Editor",
        "Locate <strong>servicePrincipalName</strong> attribute",
        "Any non-empty value on a user account (not computer) is Kerberoastable.",
    ],
},
```

> Inline HTML is supported in `desc`, `steps`, and `confirm` values, use `<code>`, `<strong>`, and `<em>` for emphasis. The `code` field is HTML-escaped by `report.py`, so use plain text there.

---

### REMEDIATION

`REMEDIATION` is a single dict with a `title` and a `steps` list.

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `title` | `str` | ✅ | Brief description of the recommended fix, shown as the panel header |
| `steps` | `list[dict]` | ✅ | Ordered remediation steps |

Each step dict:

| Key | Type | Description |
|-----|------|-------------|
| `text` | `str` | Step description; supports inline HTML |
| `code` | `str` | Optional command block rendered in monospace |
| `steps` | `list[str]` | Optional nested sub-steps rendered as a numbered list |

**Example:**

```python
REMEDIATION = {
    "title": "Remove unnecessary SPNs and enforce AES-only encryption",
    "steps": [
        {
            "text": "Audit and remove unnecessary SPNs from user accounts:",
            "code": "Set-ADUser -Identity <username> -ServicePrincipalNames @{Remove='<SPN>'}",
        },
        {
            "text": "Enforce AES-only encryption to make offline cracking infeasible:",
            "code": "Set-ADUser -Identity <username> `\n    -KerberosEncryptionType AES128,AES256",
        },
        {
            "text": "Migrate service accounts to <strong>gMSAs</strong> where possible.",
        },
    ],
}
```

---

### REFERENCES

`REFERENCES` is a list of link dicts. Each entry renders as a tagged pill + hyperlink in the collapsible References panel.

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `title` | `str` | ✅ | Link display text |
| `url` | `str` | ✅ | Full URL (https://...) |
| `tag` | `str` | ✅ | One of the tag values below |

**Tag values:**

| Tag | Colour | Use for |
|-----|--------|---------|
| `"vendor"` | Blue | Official vendor docs (Microsoft Docs, CIS Benchmarks) |
| `"attack"` | Red | MITRE ATT&CK techniques, PoC tools used offensively |
| `"defense"` | Green | Detection guidance, hardening references, monitoring alerts |
| `"research"` | Purple | Blog posts, conference talks, academic papers |
| `"tool"` | Amber | Open-source offensive or audit tools (Impacket, Rubeus, NetExec) |

**Example:**

```python
REFERENCES = [
    {
        "title": "MITRE ATT&CK: Kerberoasting (T1558.003)",
        "url": "https://attack.mitre.org/techniques/T1558/003/",
        "tag": "attack",
    },
    {
        "title": "Kerberoasting Without Mimikatz - Will Schroeder",
        "url": "https://www.harmj0y.net/blog/powershell/kerberoasting-without-mimikatz/",
        "tag": "research",
    },
    {
        "title": "Rubeus - Kerberoasting Module",
        "url": "https://github.com/GhostPack/Rubeus",
        "tag": "tool",
    },
    {
        "title": "Detecting Kerberoasting - Defender for Identity",
        "url": "https://learn.microsoft.com/en-us/defender-for-identity/credential-access-alerts",
        "tag": "defense",
    },
]
```

Aim for 4–8 references per finding. Prioritise: the MITRE ATT&CK technique, the relevant Microsoft Docs page, one detection reference, and one or two commonly used offensive tools.

---

### Checklist for a new verification file

- [ ] File is named `verifications/verify_<topic>.py` matching the corresponding `check_<topic>.py` slug
- [ ] `MATCH_KEYS` contains at least one distinctive lowercase substring of the finding title
- [ ] `TOOLS` has at least one Linux tool (`"netexec"` or `"impacket"`) and one Windows tool (`"ps"` or `"aduc"`)
- [ ] Every tool card has `tool`, `icon`, `desc`, and either `code` or `steps`
- [ ] Every tool card that has a verifiable success condition includes `confirm`
- [ ] `REMEDIATION` has a `title` and at least one `steps` entry
- [ ] `REFERENCES` has 4–8 entries covering attack, vendor, defense, and tool tags

---
## Submitting a pull request

1. Fork the repository and create a branch named `check/<topic>`
   (e.g. `check/stale-computers`).
2. Add your `checks/check_<topic>.py` file.
3. If your check requires a new Python dependency, add it to
   `requirements.txt` with a comment explaining why.
4. Update `README.md`; increment the check count in the description
   and add a row to the checks table if one exists.
5. Open a pull request against `main` with a title like:
   `Add check: <CHECK_NAME>`.
6. Describe in the PR body: what the check detects, the LDAP filter(s)
   used, severity rationale, and any edge cases handled.

**Code style:**
- 4-space indentation, no tabs.
- PEP 8 names: `snake_case` for functions and variables, `UPPER_CASE` for
  module-level constants.
- Keep helper functions prefixed with `_` to signal they are internal.
- No external dependencies beyond `ldap3`, `impacket`, and `pyOpenSSL`
  unless absolutely necessary.

---

*ADScan is intended for authorised security assessments only.*
*Always obtain written permission before scanning an Active Directory environment.*
