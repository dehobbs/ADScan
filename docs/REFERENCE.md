# ADScan Developer Reference

A complete reference for the ADScan codebase: architecture, modules, contracts, and design decisions.

---

## 1. Project Overview

**What it is.** ADScan is a modular Active Directory vulnerability scanner. It connects to a domain controller via LDAP/LDAPS/SMB, runs ~40 security checks (LDAP queries + external tools like Certipy, NetExec, and BloodHound), computes a ratio-based risk score with per-category sub-scores, and produces HTML/JSON/CSV/DOCX reports with manual verification commands and remediation guidance.

**Top-level directory layout.**

```
adscan.py              # Entry point — argparse, orchestration loop, report driver
lib/                   # Core libraries (connector, scoring, report, logging, tools, spinner)
checks/                # 40 check_*.py modules — auto-discovered, executed in CHECK_ORDER
verifications/         # 60 verify_*.py modules — auto-discovered, matched to findings
scoring.toml           # Risk-scoring config (severity weights + per-finding overrides)
Reports/               # Generated reports (gitignored)
Reports/Artifacts/     # Tool outputs (Certipy JSON, BloodHound ZIP, nxc archive)
Logs/                  # Audit + debug logs (gitignored)
```

**Data flow at a glance.**

```
CLI args → ADConnector.connect() → for each check module:
   AuditLogger + DebugLogger boundaries → check.run_check(connector) → list[finding]
findings → ScoringConfig.deduction_for() → compute_scores() → overall + per-category
findings + scores → generate_report() / generate_json_report() / etc.
                  → report.py auto-discovers verify_*.py → matches MATCH_KEYS to titles
```

---

## 2. Entry Point — `adscan.py`

**Role.** CLI argument parsing, check auto-discovery, orchestration loop, report dispatch.

### Key functions

| Function | Purpose |
|----------|---------|
| `configure_logging(verbose, log_file)` | Builds the `adscan` logger. Console handler at INFO (or DEBUG if `--verbose`); file handler always DEBUG with timestamps when `--log-file` is set. Returns the logger. |
| `_check_slugs(module)` | Generates the lowercase set of match tokens for `--checks` / `--skip` filtering. Tokens come from the module name (without `check_` prefix), every word of `CHECK_NAME`, and every value in `CHECK_CATEGORY`. |
| `load_checks(only, skip)` | Walks `checks/` via `pkgutil.iter_modules`, imports each, keeps modules with a `run_check` callable, intersects `only` / `skip` slug sets, returns sorted by `CHECK_ORDER`. |
| `list_checks()` | Implementation of `--list-checks` — prints a table of all check modules. |
| `parse_args()` | Builds the argparse parser with five argument groups: Target, Authentication, Output, Check Filtering, Tool Management. The Target group holds the connection-level flags including `--protocol`, `--dns-server` (alias `-ns`), `--dns-tcp`, and `--timeout`. A top-level `--version` / `-V` action prints the module-level `__version__` constant and exits. |
| `ensure_reports_dir(path)` | Creates the parent dir of an output path if missing. |
| `main()` | The orchestration loop (described below). |

### Orchestration loop (inside `main`)

1. **Early exits** for `--list-checks` (print and quit) and `--setup-tools` (call `setup_all_tools()` and quit).
2. **Argument validation** — domain, dc-ip, username are required for a real scan.
3. **`--ccache` implies `--kerberos`** automatically.
4. **Auth method detection** for display: Kerberos (ccache) → NTLM hash → Password. If none of `-p`/`--hash`/`--kerberos` is set, prompts via `getpass`.
5. **Generate scan timestamp** (`YYYYMMDD_HHMMSS`) — used for all artifact filenames.
6. **Determine output stem** — `--output` (explicit), then `--output-dir/...`, fallback to `Reports/adscan_report_<ts>`.
7. **Initialise `AuditLogger` + `DebugLogger`**, attach `dbg` to the connector so `connector.ldap_search()` automatically logs queries.
8. **Build `ADConnector`**, attach `connector.artifacts_dir` + `connector.scan_timestamp` so checks have consistent naming.
9. **Connect** under a spinner. Exit if no protocol succeeded.
10. **Parse `--checks`/`--skip` slugs**, call `load_checks()`.
11. **Per-check loop**:
    - `dbg.log_check_start(name)` → enter `spinner(...)` context, bind it to `connector.spinner` so checks can suspend it around interactive prompts → `check.run_check(connector, verbose)` → exit spinner context → `connector.spinner = None` → `dbg.log_check_end(name, result)`.
    - Append `{categories, weight}` to `checks_run` for ratio scoring.
    - For each finding: log title + severity + deduction; copy `category` + `check_category` onto the finding; replace `finding["deduction"]` with `scoring.deduction_for(finding)` so the report shows the effective value.
    - If the check took ≥5 s, log the elapsed wall-clock duration on the next line.
    - `audit.record_check(...)` regardless of outcome.
    - On exception: `audit.record_check_error()` + `dbg.log_error()` — never re-raise.
12. **Disconnect, archive `~/.nxc`** to `Reports/Artifacts/nxc_<ts>.zip` if it exists.
13. **Compute scores** via `compute_scores(findings, scoring, checks_run)`.
14. **Report variants** — always emit the redacted "customer" report; if `--unredacted`, also emit `_operator` variant. Loop format × variant; dispatch to the appropriate `generate_*_report()`.
15. **Print final score + grade**, call `audit.finish()` and `dbg.finish()`.

### Non-obvious decisions

- **Check exception isolation.** A check that raises is logged and recorded as an error in the audit log, but the scan continues. Checks themselves are also expected to catch exceptions internally and return info-severity findings (see CLAUDE.md contract).
- **Connector decoration.** `connector.artifacts_dir`, `connector.scan_timestamp`, and `connector.debug_log` are all attached after construction so `ADConnector` doesn't need to know about logging or output paths.
- **Two-phase report generation.** The scoring happens once; then up to 8 reports may be emitted (4 formats × 2 variants).

---

## 3. Core Library Modules (`lib/`)

### 3.1 `lib/connector.py` — `ADConnector`

Manages LDAP/LDAPS/SMB connections to a DC. Every check module receives a connector instance.

**Constructor parameters:** `domain`, `dc_host`, `username`, `password=None`, `ntlm_hash=None`, `use_kerberos=False`, `ccache_path=None`, `protocols=["ldap","ldaps","smb"]`, `verbose=False`, `timeout=30`, `dns_server=None`, `dns_tcp=False`. NTLM hash is parsed into `(lm_hash, nt_hash)` at construction time via `_parse_ntlm_hash` — supports either `LM:NT` or just `NT` (LM defaults to `aad3b435b51404eeaad3b435b51404ee`).

**Public API:**

| Method | Purpose |
|--------|---------|
| `connect()` | Probes DC for LDAP signing / LDAPS channel binding requirements (1-2 s overhead), then connects each requested protocol. Returns True if any protocol succeeded. |
| `disconnect()` | Closes ldap_conn / smb_conn. Swallows exceptions if already dropped. |
| `ldap_search(search_base=None, search_filter="(objectClass=*)", attributes=["*"], scope="SUBTREE", controls=None)` | Runs an LDAP search; returns a `list[dict]` of entries (via `_entry_to_dict`). Auto-logs to `debug_log` if attached. Returns `[]` on failure (never raises). |
| `smb_available()` | True if `smb_conn` is bound. |
| `get_smb_shares()` | Returns share name list from SMBConnection.listShares(). |
| `resolve_sid(sid_str)` | LDAP `(objectSid=…)` lookup → `sAMAccountName`. Returns the original SID on failure. |
| `log` (property) | Returns the shared `adscan` logger so check modules can write through `connector.log`. |

**Private helpers:**

- `_probe_dc_requirements()` — Two probes:
  - **Probe 1 (port 389):** anonymous SIMPLE bind. Result code 8 (`strongerAuthRequired`) ⇒ signing required.
  - **Probe 2 (port 636):** NTLM bind without CBT. Extended error `80090346` (`SEC_E_BAD_BINDINGS`) ⇒ channel binding required.
- `_connect_ldap(use_ssl, requires_signing, requires_channel_binding)` — Builds `Server` + `Connection` with the right modifiers:
  - When signing is enforced and not LDAPS, sets `session_security=ldap3.ENCRYPT` (sign+seal).
  - When LDAPS channel binding is enforced, sets `channel_binding=ldap3.TLS_CHANNEL_BINDING` (requires `ldap3 >= 2.10.0rc1`; older versions get a clear upgrade message).
  - Kerberos path uses `SASL` + `GSSAPI` and sets `KRB5CCNAME` env var.
  - **Stall detector.** Every `Connection(...)` call passes `receive_timeout=self.timeout`. ldap3 resets the socket-recv timer every time the server sends data, so paged searches keep flowing as long as progress is being made; if the server goes silent for `timeout` seconds the operation errors instead of hanging the scan.
- `_connect_smb()` — `impacket.SMBConnection` to port 445; supports password / NTLM hash / Kerberos ccache.
- `_resolve_ccache()` — Priority: explicit `--ccache` path > `KRB5CCNAME` env var.
- `_ensure_krb5_config()` — When `use_kerberos=True` and the system `krb5.conf` is missing or has no `default_realm`, synthesizes a temp config (`<DOMAIN.UPPER>` as realm, `dc_host` as KDC, `udp_preference_limit=1`, `dns_lookup_*=false`), points `KRB5_CONFIG` env var at it, and registers an `atexit` cleanup. Avoids the "Configuration file does not specify default realm" GSS error on hosts without an AD-aware krb5.conf.
- `_ensure_kerberos_target()` — When `use_kerberos=True` and `dc_host` is an IP, GSSAPI would build the SPN as `ldap/<ip>` or `cifs/<ip>` and the KDC would respond `KDC_ERR_S_PRINCIPAL_UNKNOWN`. This helper does an SRV lookup against the DC for `_ldap._tcp.dc._msdcs.<domain>`, then calls `_install_dns_resolver` and registers `<fqdn> -> <ip>` in the override dict so subsequent ldap3/impacket connections route TCP to the original IP but build the correct SPN from the FQDN. Replaces `self.dc_host` with the resolved FQDN.
- `_install_dns_resolver()` — Monkey-patches `socket.getaddrinfo` once per process. Resolution order: (1) the explicit override dict (Kerberos FQDN routing); (2) when `dns_server` is set and the host isn't already an IP, do a dnspython A-record lookup against the operator-supplied resolver (using `dns_tcp` for transport); (3) fall through to the original `getaddrinfo`. This is how `--dns-server` makes ldap3 and impacket bind through the chosen resolver without per-call wiring.
- `_resolve_dc_fqdn_via_srv()` — SRV lookup with `dns_server` (preferred) or `dc_host` as the nameserver.
- `_entry_to_dict(entry)` — Converts ldap3 `Entry` to plain dict; collapses single-element lists to scalars; ensures `dn` and `distinguishedName` are present.

**Non-obvious decisions:**

- **Probing is ~1-2 s overhead but prevents wasted bind attempts** on hardened DCs that would otherwise return cryptic 00002028 errors.
- **`ldap_search` returns dicts, not raw `Entry` objects** — every check module assumes dict-style access.
- **The DNS monkey-patch is one-shot per process** — guarded by `socket._adscan_dns_patched`. Reusing the same hook for both the Kerberos FQDN→IP override and the `--dns-server` redirect keeps the contract simple.
- **`receive_timeout` is a stall detector, not a wall-clock cap.** A legitimately slow but progressing paged LDAP search keeps going; a server that has gone silent gets caught quickly.
- **Graceful degradation** if `ldap3` or `impacket` aren't installed — `HAS_LDAP3` / `HAS_IMPACKET` flags skip the relevant protocol with a warning instead of crashing.

### 3.2 `lib/tools.py` — External CLI tool manager

**Purpose.** Resolves external CLI tool paths, auto-installing them via `uv tool install` into isolated venvs (preventing dependency conflicts with ADScan's own packages).

**`ToolSpec` dataclass:** `package` (PyPI name), `exe` (primary executable), `description`, `version` (optional pin), `fallback_exe` (legacy name to check before installing).

**`TOOL_REGISTRY`:**

| Slug | Package | Exe | Purpose |
|------|---------|-----|---------|
| `certipy` | `certipy-ad` | `certipy` | ADCS / PKI vulnerability scanner. Falls back to `certipy-ad` exe name on Kali. |
| `nxc` | `netexec` | `nxc` | SMB signing / SMBv1 / NoPac / ADCS / Pre-2k detection. |
| `bloodhound` | `bloodhound` | `bloodhound-python` | Legacy BloodHound AD ingestor for graph analysis. |
| `bloodhound-ce` | `bloodhound-ce` | `bloodhound-ce-python` | BloodHound Community Edition ingestor. |

**Public API:**

- `ensure_tool(slug)` — Lookup order: primary exe on PATH → fallback exe on PATH → `uv tool install <pip_spec>` → re-check PATH. Returns absolute path or `None` (with a warning containing manual install instructions).
- `setup_all_tools()` — Calls `_bootstrap_uv()` first, then installs every tool in the registry. Used by `--setup-tools`.
- `_bootstrap_uv()` — If `uv` is not already on PATH, runs Astral's official installer (`curl -LsSf https://astral.sh/uv/install.sh | sh`) and prepends `~/.local/bin` and `~/.cargo/bin` to the current process `PATH` so the freshly-installed binary is discoverable without sourcing a shell rc file. Lets the pipx one-liner work on a fresh machine: `pipx install git+https://github.com/dehobbs/ADScan.git && adscan --setup-tools`.

**Non-obvious decisions:**

- **`uv tool install`, not `pip install`** — keeps tool dependencies isolated from ADScan's own venv. Means certipy 5.x's Python 3.12 requirement doesn't break ADScan running on 3.10.
- **Tools are best-effort.** Checks that need a tool call `ensure_tool` and emit an info-level finding ("X Not Installed") rather than failing.
- **`_bootstrap_uv` is opt-in via `--setup-tools`.** Mid-scan `ensure_tool` calls do not auto-install uv — they fall back to the existing "uv not on PATH" warning. The auto-install of uv only fires when the operator explicitly runs the setup command.

### 3.3 `lib/scoring.py` — Ratio-based risk scoring

**`ScoringConfig` class** holds severity weights, per-finding title overrides, and a configurable initial score (default 100).

- `ScoringConfig.load(path=None)` — Loads from path, default `scoring.toml` next to `adscan.py`. If file missing or TOML library unavailable, falls back to built-in defaults silently. Parses `[severity_weights]` and `[overrides]` tables.
- `deduction_for(finding)` — Priority resolution:
  1. `[overrides]` — exact match on `finding["title"]`
  2. `[severity_weights]` — match on `finding["severity"]`
  3. `finding["deduction"]` — the check module's hardcoded value
- `summary()` — One-line description for the startup banner.

**Built-in severity defaults:** critical=20, high=15, medium=8, low=5, info=0.

**`compute_scores(findings, scoring_config, checks_run=None)`:**

The scoring model is **earned / possible × 100**, not deduction-from-100.

```
Step 1: For every check that ran, add CHECK_WEIGHT to each of its categories' "possible".
        Start "earned" at the same value (a clean check = full credit).
Step 2: For every failing finding, subtract the resolved deduction from "earned" in
        each of the finding's categories (floor at 0). Info-severity / 0-deduction
        findings are recorded as "pass" but don't reduce earned.
Step 3: For each category, sub-score = round(earned / possible × 100), 100 if no
        weights existed. Overall = sum(earned) / sum(possible) × 100.
```

Returns `{"overall": int, "categories": {name: {"score", "earned", "possible", "counts": {critical/high/medium/low/info/pass}}}}`.

**Non-obvious decisions:**

- **Findings can attach to multiple categories** via `check_category` (a list). Each category gets credited / debited independently.
- **A `_seen` set is initialised but unused** — likely vestigial guard against double-counting that was simplified out.
- **Legacy fallback when `checks_run` is None** — adds weight to possible only when a finding is raised. Old behaviour, preserved for backwards compatibility.

### 3.4 `lib/report.py` — HTML / JSON / CSV / DOCX report generators

Centralises all output. The HTML report is self-contained (embedded CSS/JS, light/dark mode toggle).

**Top-level generators** (all share the same signature: `output_file, domain, dc_host, username, protocols, findings, score, category_scores=None, redact=False`):

| Function | Output |
|----------|--------|
| `generate_report` | Self-contained HTML dashboard with severity filter chips, category sidebar, executive summary, score gauge, per-finding cards, manual verification commands, remediation, and references. Renders the verification database for each finding. |
| `generate_json_report` | Structured JSON: `{metadata, score, category_scores, findings: [...]}`. |
| `generate_csv_report` | One row per finding with title / severity / deduction / category / description / details. |
| `generate_docx_report` | Word document via `python-docx`. Mirrors the HTML structure. |

**Verification database build (key architectural piece):**

```python
def _build_verification_db():
    # pkgutil.iter_modules over verifications/
    # importlib.import_module each
    # Read MATCH_KEYS, TOOLS, REMEDIATION, REFERENCES
    # Flatten: {match_key: {tools, remediation, references}}
```

`VERIFICATION_DB` is built at module import time. `_get_verification(finding)` does a substring scan over keys against `finding["title"].lower()` — **first match wins**, so MATCH_KEYS ordering matters when multiple modules could match.

**Internal helpers:**

| Function | Purpose |
|----------|---------|
| `_score_color(score)` | Maps 0-100 to a hex colour (green / lime / amber / orange / red). |
| `_grade(score)` | A/B/C/D/F bucketing at 90/75/60/40. |
| `_severity_badge_html(severity)` | Coloured pill-shaped severity tag. |
| `_finding_card(finding, idx, redact)` | Per-finding card: title, severity badge, deduction, description, details (redacted or full), category, references, manual verification, remediation. |
| `_get_details(finding, redact)` | Returns `details_redacted` if `redact` is True and the key exists; otherwise `details`. **Critical:** any check module that produces credential data in `details` MUST also produce `details_redacted`, or credentials will leak into the customer report. |
| `_manual_verification_html(finding)` | Renders the 2-column tool grid using `_get_verification(finding)`. |
| `_remediation_html(finding)` | Renders the structured remediation steps from the verification module. |
| `_references_html(finding)` | Collapsible references list with tag colour-coding (vendor/attack/defense/research/tool). |
| `_exec_summary_html(...)` | Score gauge, severity counts, top priority findings. |
| `_category_scores_html(category_scores)` | Per-category bar chart with earned/possible labels. |
| `_tool_card_html(tool_data)`, `_tool_icon_html(icon_type)` | Renders an individual verification tool card with a coloured SVG icon (netexec / impacket / ps / cmd / aduc). |

**Non-obvious decisions:**

- **HTML is fully escaped via `html.escape`** at every user-supplied insertion point (domain, username, finding titles/descriptions/details).
- **Dark mode is CSS-only** (CSS variables flipped by a class toggle); no server-side theming.
- **Severity sort order is fixed at `["critical","high","medium","low","info"]`** — `_SEV_RANK` lookups everywhere ensure consistent ordering.

### 3.5 `lib/audit_log.py` — `AuditLogger`

Writes a human-readable audit log to `Logs/adscan_<ts>.log`. **Never logs credentials** — only auth method labels.

| Method | Purpose |
|--------|---------|
| `start()` | Writes the header (run timestamp, operator, target domain/DC, auth method, Python version, log-file path) and the check table column headers. |
| `record_check(check_name, findings)` | Appends one tabular line: check name, status (PASS/FINDINGS), count, deduction, severity breakdown. |
| `record_check_error(check_name, error)` | Same row format but status=ERROR with the exception string. |
| `finish(score, report_path)` | Appends the summary footer: total findings, total deduction, severity histogram, final score + grade, elapsed time, report path. |
| `log_path` (property) | Returns the absolute log path. |

Module helpers `_count_severities`, `_format_severities`, `_format_elapsed` handle the tabular output formatting.

### 3.6 `lib/debug_log.py` — `DebugLogger`

Records every LDAP query, subprocess invocation, SMB operation, and exception to `Logs/adscan_debug_<ts>.log` for post-mortem diagnosis.

| Method | Purpose |
|--------|---------|
| `start()` / `finish()` | Header / footer. Total operation count is tracked by `_seq`. |
| `log_check_start(name)` / `log_check_end(name, findings)` | Per-check section markers with timestamps. Resets `_check_seq`. |
| `log_ldap(filter, base, attributes, count, error=None)` | Called automatically by `connector.ldap_search()`. |
| `log_subprocess(cmd, returncode, stdout, stderr, cwd)` | Called manually by checks that invoke external tools. **Redacts password values** before writing — strips values following `-p`, `--password`, `-P`, `--secret`, `--hashes`, `--hash`. Also redacts `domain\user:password` patterns from stdout/stderr (NetExec output format). |
| `log_smb(operation, path, result, error=None)` | For SMB file/path operations. |
| `log_error(context, error, include_traceback=True)` | Records a caught exception with full traceback. |

**Non-obvious decisions:**

- **The redaction logic is the only line of defence against credentials leaking to disk.** Any check that calls a tool with a different password flag spelling will leak — keep `_PASSWORD_FLAGS` in sync with the tools you call.
- **The connector calls `dbg.log_ldap()` automatically**, so check modules don't need to log LDAP themselves — but they do need to call `dbg.log_subprocess()` after every subprocess call (the connector can't know about external tools).

### 3.7 `lib/spinner.py` — Terminal spinner

A 2-second-delay spinner that only activates if `sys.stderr.isatty()` is True (so piped output stays clean).

- `Spinner` class — context manager. Displays nothing for the first 2 s, then prints `\r {frame} {label} {elapsed}s ` at 10 Hz using `\r` to overwrite the same line.
- `pause()` / `resume()` / `suspended()` — Lets the active check temporarily hide the spinner around an interactive prompt. `pause()` clears the spinner line and stops drawing; `resume()` continues; `suspended()` is the context-manager form (`with sp.suspended(): choice = input(...)`).
- `_NoOp` class — null context manager with matching no-op `pause/resume/suspended` so callers don't need to type-check.
- `spinner(label, delay=2.0, enabled=True)` — Factory that returns Spinner or NoOp depending on TTY + `enabled`.

**Integration with checks.** `adscan.py:main` binds the active spinner to `connector.spinner` for the duration of each check (and clears it after). Checks that need to prompt the operator (e.g. `check_bloodhound.py:_prompt_engine`) read `connector.spinner` and wrap their `input()` call in `sp.suspended()` so the spinner doesn't overwrite the question.

---

## 4. Check Module Pattern (`checks/check_*.py`)

### 4.1 The contract

Every check module is auto-discovered by `pkgutil.iter_modules` over `checks/`. To be loaded, a module must:

1. Be named `check_<slug>.py`
2. Define a callable `run_check(connector, verbose=False) -> list[dict]`
3. Define module-level constants: `CHECK_NAME` (str), `CHECK_ORDER` (int), `CHECK_CATEGORY` (list[str]), `CHECK_WEIGHT` (int)

### 4.2 Finding dict schema

```python
{
    "title":          str,         # display name; matched against verify_*.py MATCH_KEYS
    "severity":       str,         # "critical" | "high" | "medium" | "low" | "info"
    "deduction":      int,         # default points to subtract; may be overridden by scoring
    "description":    str,         # what the issue is and why it matters
    "recommendation": str,         # how to remediate (high-level)
    "details":        list[str],   # affected objects (UNREDACTED — operator report uses this)
    "details_redacted": list[str], # OPTIONAL but REQUIRED when details may contain credentials
    "category":       str | list[str],  # optional override; usually inherited from CHECK_CATEGORY
}
```

### 4.3 Hard rules

- **Never `raise` out of `run_check()`.** Catch exceptions and return an info-severity finding with deduction 0.
- **Never call `sys.exit()`.** Same reason.
- **Use `connector.log` for output**, not `print()`.
- **Use `connector.ldap_search()`, never bare `ldap3.Connection.search()`** — `ldap_search` handles range controls, dict conversion, and debug logging automatically.
- **Tool-using checks must call `ensure_tool(slug)`** to resolve the path, and emit an info-level finding ("X Not Installed") if the path is None.
- **Tool-using checks must call `connector.debug_log.log_subprocess(...)`** after every `subprocess.run` to record the command + outputs (with credential redaction).
- **Any check that produces credential material in `details`** must also produce a `details_redacted` list with the credentials replaced by `[[REDACTED]]` markers.

### 4.4 `--checks` / `--skip` slug matching

A check matches a slug if any of the following intersects the user-supplied slug set:

- The module file basename without the `check_` prefix (e.g. `check_kerberos` → `kerberos`)
- Each whitespace-/underscore-separated word in `CHECK_NAME`
- Each value in `CHECK_CATEGORY` lowercased + whitespace-replaced

This means `--checks kerberos` matches `check_kerberos.py`, `check_constrained_delegation.py` (category includes "Kerberos"), `check_unconstrained_delegation.py`, etc.

---

## 5. Check Module Catalog

Ordered by `CHECK_ORDER`. Each entry: name • category • weight • method • notable findings • design notes.

### Tier-A scoring (weight ≥ 20)

#### `check_password_policy.py` — Domain Password Policy
- **Category:** Account Hygiene • **Order:** 1 • **Weight:** 20
- **Method:** LDAP query of the domainDNS object for `minPwdLength`, `pwdProperties`, `maxPwdAge`, `lockoutThreshold`, etc.
- **Findings:** Account Lockout Disabled (critical), Min Length <15 (high), Complexity Disabled (high), Passwords Never Expire (high), Reversible Encryption (critical), Min Age Not Enforced (medium), Max Age >365d (medium), Lockout Window Too Short (low).
- **Helpers:** `_filetime_to_days`, `_filetime_to_minutes` for negative LDAP FILETIME values.
- **Notes:** `maxPwdAge=0` interpreted as "never expires"; complexity check uses `pwdProperties` bit 0x1; reversible encryption is bit 0x10.

#### `check_unconstrained_delegation.py` — Unconstrained Delegation
- **Category:** Kerberos • **Order:** 2 • **Weight:** 25
- **Method:** LDAP filter `(userAccountControl:1.2.840.113556.1.4.803:=524288)` (bitwise UAC=0x80000).
- **Findings:** User accounts with UD (critical, -25 — overridden); Computer accounts with UD (high, -20 — overridden).
- **Notes:** Excludes DCs (legitimate). User UD is rated higher than computer UD because user TGT capture is a direct credential theft path; computer UD is exploited via printer-spooler / coerce-auth.

#### `check_privileged_accounts.py` — Privileged Account Security
- **Category:** Privileged Accounts • **Order:** 4 • **Weight:** 20
- **Method:** Reverse `memberOf` lookup for sensitive groups; checks UAC, `pwdLastSet`, `lastLogonTimestamp`, description; special handling for krbtgt and RID 500.
- **Findings:** Excessive Domain Admins (medium), Non-expiring privileged passwords (high), Stale privileged accounts (high), **Passwords Found in Privileged Account Description Fields** (critical), Built-in Administrator issues (high), krbtgt never reset (critical), krbtgt not rotated 180d (critical), Sensitive delegated groups have active members (low).
- **Helpers:** `_resolve_members` (reverse-memberOf to avoid range controls), `_filetime_to_dt`, `_description_has_password`, `_get_rid` (RID from objectSid bytes).
- **Notes:** **Known bug** — the password-in-description finding does not provide `details_redacted`, so plaintext passwords leak into the redacted customer report. See [security assessment plan](../../.claude/plans/analyze-my-repo-and-streamed-glade.md). krbtgt skipped from stale/non-expiring checks (would always trigger).

#### `check_kerberos.py` — Kerberos Attack Surface
- **Category:** Kerberos • **Order:** 5 • **Weight:** 20
- **Method:** UAC bitwise filters: 0x400000 (DONT_REQ_PREAUTH), 0x200000 (USE_DES_KEY_ONLY); checks `servicePrincipalName`, `msDS-SupportedEncryptionTypes`.
- **Findings:** High-Value Kerberoastable (adminCount=1 + SPN + DONT_EXPIRE) (critical), Kerberoastable Service Accounts (high), AS-REP Roastable (high), DES-Only Encryption (medium).
- **Notes:** krbtgt skipped from Kerberoastable; DES detected via either UAC flag or `msDS-SupportedEncryptionTypes`.

#### `check_adcs.py` — ADCS / PKI Vulnerabilities
- **Category:** ADCS / PKI Vulnerabilities • **Order:** 6 • **Weight:** 20
- **Method:** Three phases:
  - **Phase 1 (LDAP)** — currently muted. Queries `pKIEnrollmentService` and `pKICertificateTemplate` in the Configuration NC; bitwise checks `msPKI-Certificate-Name-Flag` (0x100=ENROLLEE_SUPPLIES_SAN, 0x80000=NO_SECURITY_EXTENSION) and `msPKI-Private-Key-Flag` (0x40000=EDITF_ATTRIBUTESUBJECTALTNAME2). Function preserved — uncomment in `run_check()` to re-enable.
  - **Phase 2 (Certipy)** — `certipy-ad find -u <upn> -p <pass> -dc-ip <ip> -enabled -vulnerable`. LDAPS→LDAP fallback if SSL/TLS error patterns appear in output. Parses JSON artifact.
  - **Phase 3 (NetExec)** — `nxc ldap <dc-ip> -d <domain> -u <user> -p/-H <cred> -M adcs`. Regex-extracts CA names and ESC labels from output.
- **Findings:** ESC1 / ESC2 / ESC3 / ESC4 / ESC6 / ESC7 / ESC8 / ESC9 / ESC10 / ESC11 / ESC13 / ESC15 / ESC16 with severities ranging high–critical; ADCS CA inventory (info); Certipy/NXC Not Installed (info).
- **Helpers:** `_get_str/int/list` (safe attribute accessors), `_ekus` (collects from policy + extension attrs), `_build_auth_args` (nxc creds), `_resolve_certipy`, `_is_ldaps_error`, `_parse_certipy_json` (handles both dict and list JSON formats).
- **Notes:** Certipy takes priority over NXC for the same ESC number (Certipy has richer ACL context); NXC fills gaps for ESC numbers Certipy didn't report. Phase 1 muted because Certipy is more accurate when ACL parsing matters; preserved for future reactivation.

#### `check_domain_trusts.py` — Domain Trust Analysis
- **Category:** Domain Hygiene • **Order:** 7 • **Weight:** 20
- **Method:** LDAP for `trustedDomain`; analyses `trustAttributes`, `trustDirection`, `trustType`.
- **Findings:** Bidirectional w/o SID filtering (critical), Forest trust w/o SID filtering (high), Forest trust configured (medium), TGT delegation across trust (high), External bidirectional (medium), MIT realm trusts (low), RC4 on trusts (low), Trust inventory (info).
- **Notes:** Within-forest parent-child trusts (flag 0x20) silently skipped — they're expected.

#### `check_account_hygiene.py` — Account Hygiene
- **Category:** Account Hygiene • **Order:** 8 • **Weight:** 20
- **Method:** LDAP enumeration of users/computers; FILETIME comparison; SPN duplicate detection via dict.
- **Findings:** Reversible Encryption per-account (critical), PASSWD_NOTREQD (high), Duplicate SPNs (high), Stale users / computers / never-logged-on / old passwords (medium), Computers never authenticated (low).
- **Notes:** Disabled accounts excluded entirely; DC computers (UAC 0x2000) excluded from stale-computer check; old-password check skips DONT_EXPIRE_PASSWD accounts.

#### `check_protocol_security.py` — Protocol Security
- **Category:** Protocol Security • **Order:** 9 • **Weight:** unweighted in module
- **Method:** LDAP for `msDS-Behavior-Version` (DFL), Configuration NC `crossRefContainer` (FFL), DCs.
- **Findings:** DFL <6 (critical), DFL=6 (low), FFL <6 (high), Legacy DC OS (high), LDAP signing/CBT verify (medium info), NTLMv1/WDigest verify (medium info).
- **Notes:** Registry-based settings (LDAP signing, NTLMv1, WDigest) are info-level because they cannot be passively verified.

#### `check_laps.py` — LAPS Deployment
- **Category:** Privileged Accounts • **Order:** 11 • **Weight:** 20
- **Method:** Schema search for `ms-Mcs-AdmPwd` (legacy) and `msLAPS-*` attrs; enumerates non-DC enabled computers, checks if any LAPS attribute has a value.
- **Findings:** LAPS Not Deployed (critical); Coverage thresholds: <25% critical, 25-49% high, 50-74% medium, 75-89% low, 90%+ info (pass).

#### `check_domain_controllers.py` — DC Security
- **Category:** Domain Hygiene • **Order:** 13 • **Weight:** 20
- **Method:** UAC 0x2000 (SERVER_TRUST_ACCOUNT) filter; FSMO role owner DN parsing.
- **Findings:** Single DC (critical), Legacy DC OS (high), All FSMO on one DC (high), RODC permissive PRP (low), FSMO inventory (info).
- **Notes:** RODC permissive PRP detected via substring match for "domain users" / "authenticated users" in `msDS-RevealOnDemandGroup`.

#### `check_foreign_security_principals.py` — FSPs in Privileged Groups
- **Category:** Groups Hygiene • **Order:** 67 (mismatched in module) • **Weight:** 20
- **Method:** LDAP search of `CN=ForeignSecurityPrincipals`; `memberOf` substring match against 16 hardcoded sensitive group names.
- **Findings:** FSPs in Privileged Groups (critical), FSPs in Standard Groups (medium), No memberships / None found (info).

#### `check_acl_permissions.py` — ACL / Permissions
- **Category:** Privileged Accounts • **Order:** 15 • **Weight:** 25
- **Method:** LDAP retrieval of certificate templates and PKI containers; **string-matching `nTSecurityDescriptor`** for keywords (WriteDacl, GenericWrite, ManageCertificates, etc.); reverses memberOf for Protected Users; searches for `msDS-AllowedToActOnBehalfOfOtherIdentity` for RBCD.
- **Findings:** ESC4 (critical), ESC5 (high), ESC7 (high), DCSync Rights (critical, -25 override), Protected Users empty/sparse (low), RBCD Configured (medium, -10 override).
- **Notes:** Binary nTSecurityDescriptor parsing is deferred to Certipy (more accurate). ADScan does string-pattern matching as a fallback that's better than nothing.

#### `check_pre_windows_2000.py` — Pre-Windows 2000 Compatible Access
- **Category:** Domain Hygiene • **Order:** 68 • **Weight:** 20
- **Method:** LDAP query for the group's members.
- **Findings:** Critical if Everyone / Anonymous Logon present; medium if Authenticated Users; pass otherwise.

#### `check_gpp_cpassword.py` — GPP cpassword Discovery
- **Category:** Domain Hygiene • **Order:** 62 • **Weight:** 20
- **Method:** SMB walk of SYSVOL → finds Group Policy Preference XML files → decrypts `cpassword` attributes using Microsoft's MS14-025-published AES key.
- **Findings:** Critical if any cpassword found.
- **Notes:** Provides both `details` and `details_redacted` ✅.

#### `check_deprecated_os.py` — End-of-Life OS Detection
- **Category:** Deprecated Operating Systems • **Order:** 20 • **Weight:** 20
- **Method:** Substring match on `operatingSystem` attribute against keyword lists.
- **Findings:** EOL Workstation OS (critical), EOL Server OS (critical), Near-EOL Server OS (high — Server 2012/2012R2).

### Tier-B scoring (weight 10-15)

#### `check_constrained_delegation.py` — Constrained Delegation
- **Order:** 3 • **Weight:** 20 (treated as Tier-B by content)
- **Method:** Reads `msDS-AllowedToDelegateTo`; UAC flag 0x1000000 (TRUSTED_TO_AUTH_FOR_DELEGATION = protocol transition / S4U2Self); compares targets against DC list.
- **Findings:** KCD + Protocol Transition (high), KCD targeting high-value services (high), Dangerous KCD on DCs (critical), KCD targets DCs (high), High-value KCD (medium), KCD configured (info).

#### `check_dns_infrastructure.py` — DNS & Infrastructure
- **Category:** Network Hygiene • **Order:** 12 • **Weight:** 15
- **Method:** Wildcard DNS detection via `dc=*` filter on `dnsNode`; site/subnet enumeration in Configuration NC.
- **Findings:** Wildcard DNS records (high), LLMNR/NetBIOS verify (info), No subnets defined (low), Subnets unassigned (low), AD Sites inventory (info).

#### `check_smb.py` — SMB Signing & SMBv1
- **Category:** Protocol Security • **Order:** 22 • **Weight:** 15
- **Method:** Phase 1 — LDAP `(objectClass=computer)` enumeration via the connector's signed/encrypted LDAP (avoids 00002028 errors). Phase 2 — `nxc smb computers.txt`; regex `(signing:False|True)` and `(SMBv1:True|False)`.
- **Findings:** SMB Signing Not Enforced (high), Signing All Enforced (info), SMBv1 Enabled (high), SMBv1 Disabled (info), nxc Not Found (info).
- **Notes:** Computers list written to `Reports/Artifacts/computers_<ts>.txt`; debug log redacts password flags.

#### `check_legacy_protocols.py` — Legacy Protocols
- **Category:** Protocol Security • **Order:** 21 • **Weight:** 15
- **Method:** SMB dialect probe via `connector.smb_conn.getDialect()`.
- **Findings:** SMBv1 (high), SMBv1 limited check (info), Null Session (info), NTLMv1/WDigest (info).

#### `check_misc_hardening.py` — Miscellaneous Hardening
- **Category:** Domain Hygiene • **Order:** 19 • **Weight:** 15
- **Findings:** Machine Account Quota >0 (high), Tombstone <180 days (medium), Guest enabled (high), Permanent Schema/Enterprise Admins (medium), Audit policy verify (info).

#### `check_computer_password_age.py` — Computer Account Password Age
- **Category:** Account Hygiene • **Order:** 23 • **Weight:** 15
- **Method:** `nxc ldap` query for computers' `pwdLastSet`; 30-day threshold.
- **Findings:** Stale Machine Passwords (medium), nxc Not Found (info), Query Timed Out (info), Query Failed (info).

#### `check_pre2k.py` — Pre-Windows 2000 Computer Passwords
- **Category:** Account Hygiene • **Order:** 24 • **Weight:** 15
- **Method:** Runs `nxc ldap <dc> -M pre2k`. The NetExec module enumerates computer accounts and tries `password = sAMAccountName.lower()` (the legacy default).
- **Findings:** High severity for vulnerable accounts.

#### `check_optional_features.py` — AD Recycle Bin / PAM
- **Category:** Domain Hygiene • **Order:** 16 • **Weight:** 10
- **Method:** Substring match on `cn` of `msDS-OptionalFeature` objects.
- **Findings:** AD Recycle Bin Not Enabled (medium, -10 override), PAM Not Enabled (low).

#### `check_replication.py` — Replication Health
- **Category:** Domain Hygiene • **Order:** 17 • **Weight:** 10
- **Findings:** Excessive Site Link Replication Intervals (medium, -10 override), Multi-site topology (info), Empty sites (low).

#### `check_legacy_frs_sysvol.py` — DFSR / FRS migration
- **Category:** Domain Hygiene • **Order:** 71 • **Weight:** 10
- **Method:** Reads DFSR migration state (0=FRS, 1=Prepared, 2=Redirected, 3=Eliminated).
- **Findings:** FRS in use (high, -10 override), DFSR Redirected with FRS still present (low, -3 override).

#### `check_audit_policy.py` — Advanced Audit Policy
- **Category:** Domain Hardening • **Order:** 23 • **Weight:** 10
- **Method:** LDAP enumeration of `groupPolicyContainer` for `gPCFileSysPath` → SMB `getFile()` of `<path>\Machine\Microsoft\Windows NT\Audit\audit.csv` → CSV parse → compare to baseline.
- **Findings:** SMB Not Available, No GPOs, No audit.csv (medium), Baseline Satisfied (info), per-policy misconfigured/missing (medium).
- **Notes:** Handles UTF-16 LE BOM (Windows default), UTF-8 fallback; case-insensitive filename match.

### Tier-C scoring (weight ≤ 8)

#### `check_gpo.py` — GPO Hygiene
- **Category:** Domain Hygiene • **Order:** 10 • **Weight:** 8
- **Findings:** Disabled GPOs (medium), Unlinked GPOs (medium), Empty GPOs (low), Excessive count >100 (low).
- **Notes:** "Empty" requires both `gPCMachineExtensionNames` and `gPCUserExtensionNames` absent AND version=0.

### Unweighted (info-only, weight=0)

| Module | Order | Purpose |
|--------|-------|---------|
| `check_bloodhound.py` | 99 | Prompts the operator to choose between Legacy BloodHound (`bloodhound-python`) and BloodHound Community Edition (`bloodhound-ce-python`); non-interactive sessions default to Legacy. The prompt suspends the spinner via `connector.spinner.suspended()` so the question isn't overwritten. Both ingestors install via `uv tool install`. Resolves IP→FQDN via SRV DNS lookup when needed. Outputs ZIP only (no scored findings). |
| `check_protected_admin_users.py` | 60 | Detects ghost admins (disabled but adminCount=1), stale admins, orphaned adminCount. |
| `check_passwords_in_descriptions.py` | 61 | Description-field credential scan. ✅ Provides `details_redacted`. |
| `check_protected_users_group.py` | 61 | Tier-0 / Tier-1 members not in Protected Users. |
| `check_rbcd_domain_dcs.py` | 72 | Reads `msDS-AllowedToActOnBehalfOfOtherIdentity` on domain NC and DCs. Critical if set. |
| `check_rc4_encryption.py` | 66 | Flags accounts with RC4/DES bits in `msDS-SupportedEncryptionTypes`. Per-tier severity (DCs > admins > services > users). |
| `check_shadow_credentials.py` | 65 | `msDS-KeyCredentialLink` enumeration (Shadow Credentials attack — Whisker / pyWhisker). |
| `check_sid_history.py` | 64 | Flags any `sIDHistory`. Critical if privileged SID detected. |
| `check_orphaned_subnets.py` | 70 | AD subnets without site assignments. |
| `check_service_accounts.py` | 18 | gMSA adoption status; SPN-on-user accounts; service accounts with adminCount=1. |
| `check_laps_coverage.py` | 52 | Standalone coverage percentage check. |
| `check_adminsdholder_acl.py` | — | AdminSDHolder ACL inspection. |

---

## 6. Verification Module Pattern (`verifications/verify_*.py`)

### 6.1 The contract

Every verification module declares module-level attributes that are auto-loaded by `lib/report.py`:

```python
MATCH_KEYS = ["lowercase substring", "...", ...]   # required

TOOLS = [                                            # required if you want any verification UI
    {
        "name":         "NetExec",                  # tool label for the card header
        "icon":         "netexec",                  # one of: netexec, impacket, ps, cmd, aduc
        "description":  "What this command does",
        "command":      "nxc smb {dc_ip} -u {user} -p {pass} ...",
        "confirmation": "What output indicates the issue exists",
    },
    ...
]

REMEDIATION = {                                      # optional but recommended
    "title": "How to fix it",
    "steps": [
        "Step 1: ...",
        "Step 2: ...",
    ],
}

REFERENCES = [                                       # optional
    {"title": "Microsoft KB...", "url": "https://...", "tag": "vendor"},
    {"title": "SpecterOps research", "url": "https://...", "tag": "research"},
]
```

### 6.2 Discovery & matching

`lib/report.py:_build_verification_db()` is called once at report module import time:

1. `pkgutil.iter_modules` over `verifications/`
2. `importlib.import_module` each (silently skipping any that fail to import — warning to stderr)
3. For each module with `TOOLS`: insert one entry per `MATCH_KEYS` value into a flat dict.

`_get_verification(finding)` then does:

```python
title = finding["title"].lower()
for key, data in VERIFICATION_DB.items():
    if key in title:
        return data    # FIRST MATCH WINS
return None
```

**Implications:**

- The order of `MATCH_KEYS` matters only relative to *other modules' keys* — within one module, all keys map to the same data.
- A short, generic key like `"laps"` will match any finding with "laps" in the title — so place narrower modules' keys carefully.
- If two modules contribute the same key, the second to be imported (which is alphabetical filename order for `pkgutil`) wins.

### 6.3 Tool icon types

Defined in `_tool_icon_html()` — currently: `netexec` (dark blue grid), `impacket` (dark grey stack), `ps` (PowerShell blue "PS"), `cmd` (black chevron), `aduc` (gold "A"). Unknown types fall back to `cmd`.

---

## 7. Verification Module Catalog (Condensed)

Grouped by topic. Each entry: keys → primary tool(s) → core remediation.

### Account / Authentication

| Module | Keys (excerpt) | Tools |
|--------|----------------|-------|
| `verify_account_lockout` | `account lockout` | NetExec, `net accounts /domain`, GPMC, Get-ADDefaultDomainPasswordPolicy |
| `verify_password_complexity` | `password complexity` | NetExec, `net accounts`, GPMC |
| `verify_password_age` | `passwords older than`, `password not changed` | PS filter, NetExec, ADUC |
| `verify_password_never_expires` | `non-expiring`, `passwords never expire` | Get-ADUser PasswordNeverExpires, ADUC |
| `verify_minimum_password_age` | `minimum password age` | Get-ADDefaultDomainPasswordPolicy |
| `verify_minimum_password_length` | `minimum password length` | NetExec --pass-pol, MinPasswordLength |
| `verify_inactive` | `inactive` | LastLogonDate filter, NetExec --users |
| `verify_never_logged_on` | `never logged on` | lastLogonTimestamp null filter |
| `verify_default_credential` | `rid 500` | NetExec SMB credential test, smbclient |
| `verify_credentials_in_descriptions` | `passwords in descriptions:` | description grep, nxc user-desc module |

### Kerberos

| Module | Keys (excerpt) | Tools |
|--------|----------------|-------|
| `verify_kerberoast` | `kerberoast` | Impacket GetUserSPNs, NetExec --kerberoasting |
| `verify_as_rep` | `as-rep` | Impacket GetNPUsers, NetExec asreproast |
| `verify_des_encryption` | `des encryption` | KerberosEncryptionType filter, getTGT with DES |
| `verify_rc4` | `rc4`, `arcfour`, `rc4-hmac` | msDS-SupportedEncryptionTypes bitwise check |
| `verify_constrained_delegation` | `accounts with constrained delegation`, `constrained delegation targeting`, `constrained delegation configured` | Impacket findDelegation, msDS-AllowedToDelegateTo filter |
| `verify_unconstrained_delegation` | `computer accounts with unconstrained` | nxc --trusted-for-delegation, findDelegation |
| `verify_user_unconstrained_delegation` | `user accounts with unconstrained` | nxc --trusted-for-delegation |
| `verify_rbcd_domain_dcs` | `rbcd on domain`, `resource-based constrained delegation`, `s4u2proxy rights on` | msDS-AllowedToActOnBehalfOfOtherIdentity check |
| `verify_nopac` | `nopac`, `cve-2021-42278`, `cve-2021-42287` | nxc nopac, hotfix history check |
| `verify_protected_users` | `protected users` | Get-ADGroupMember, nxc groupmembership |

### ADCS / PKI

| Module | Keys (excerpt) | Tools |
|--------|----------------|-------|
| `verify_esc` | `esc1:` … `esc9:`, `enrollee-supplied san`, `any-purpose`, `editf_attributesubjectaltname2`, `web enrollment endpoint`, etc. | Certipy `find -vulnerable`, nxc certipy-find module, certutil -catemplates |
| `verify_esc10` | `esc10` | StrongCertificateBindingEnforcement registry, certutil -getreg |
| `verify_esc11` | `esc11` | IF_ENFORCEENCRYPTICERTREQUEST flag, certutil -getreg |
| `verify_esc13` | `esc13` | msDS-OIDToGroupLink enumeration, certutil -dspolicy |
| `verify_esc15` | `esc15` | Schema V1 templates with client auth EKU |
| `verify_shadow_credential` | `shadow credential` | Certipy find, msDS-KeyCredentialLink filter, bloodyAD |

### Privileged Groups & ACLs

| Module | Keys (excerpt) | Tools |
|--------|----------------|-------|
| `verify_acl_permissions` | `acl / permissions`, `dcsync`, `ds-replication`, `esc4/5/7`, `rbcd configured`, `protected users group` | PS ACL inspection, nxc daclread, secretsdump (DCSync) |
| `verify_adminsdholder` | `adminsdholder` | Impacket dacledit, BloodHound, ADUC Security tab |
| `verify_enterprise_admins` | `enterprise admins` | Get-ADGroupMember -Recursive |
| `verify_schema_admins` | `schema admins` | Get-ADGroupMember -Recursive |
| `verify_ghost_admins` | `ghost admin`, `stale protected admin`, `orphaned admincount`, `disabled account(s) with admincount` | adminCount=1 + disabled filter, BloodHound |
| `verify_orphaned_admincount` | `orphaned admincount` | adminCount=1 not in any priv group |

### Network / Infrastructure

| Module | Keys (excerpt) | Tools |
|--------|----------------|-------|
| `verify_smb_signing` | `smb signing` | nxc SMB sweep --gen-relay-list, ntlmrelayx, Get-SmbServerConfiguration |
| `verify_smbv1` | `smbv1`, `smb1`, `smb version 1`, `eternalblue` | nxc SMB sweep, Set-SmbServerConfiguration, nmap smb-protocols |
| `verify_ldap_signing` | `ldap signing` | LDAPServerIntegrity, LdapEnforceChannelBinding registry checks |
| `verify_ntlmv1_wdigest` | `ntlmv1 and wdigest` | LmCompatibilityLevel, UseLogonCredential registry |
| `verify_llmnr_netbios` | `llmnr and netbios` | EnableMulticast, TcpipNetbiosOptions, Responder -A |
| `verify_dns_infrastructure` | `dns infrastructure`, `adidns`, `dns wildcard`, `dynamic dns`, `dns poisoning` | DNS Server Module, Impacket dnstool |
| `verify_replication` | `replication`, `replsum`, `replication failure`, `replication lag` | repadmin, Get-ADReplicationPartnerMetadata, dcdiag |
| `verify_site_link_replication` | `site link replication` | Get-ADReplicationSiteLink, dssite.msc |
| `verify_subnets_not_assigned` / `verify_orphaned_subnets` | `subnets not assigned to a site`, etc. | siteObject null filter, dssite.msc |

### Domain / Forest

| Module | Keys (excerpt) | Tools |
|--------|----------------|-------|
| `verify_domain_trusts` | `domain trust`, `bidirectional trust`, `forest trust`, `tgt delegation`, `sid filtering`, `external bidirectional trust`, `mit kerberos realm`, etc. | Get-ADTrust, netdom trust /quarantine, Impacket getTrust |
| `verify_fsmo` | `fsmo role distribution` | Get-ADForest + Get-ADDomain, netdom query fsmo |
| `verify_misc_hardening` | `misc hardening`, `machine account quota`, `krbtgt password`, `domain functional level`, `forest functional level`, etc. | Multi-faceted PS batch check |
| `verify_machine_account_quota` | `machine account quota` | ms-DS-MachineAccountQuota read, nxc MAQ module |
| `verify_audit_policy` | `audit policy`, `audit logging`, `advanced audit`, `event logging`, `auditpol` | auditpol on DC, Get-GPO/Get-GPOReport |
| `verify_gpo_hygiene` | `disabled group policy`, `empty group policy`, `excessive gpo`, `unlinked group policy objects` | GpoStatus / ExtensionData filters |
| `verify_unlinked_gpo` | `unlinked group policy` | XML report `<LinksTo>` parsing |
| `verify_gpp` | `gpp` | nxc gpp_password module, SYSVOL grep cpassword |
| `verify_laps` | `laps` | nxc LAPS module, ms-Mcs-AdmPwd, LAPSDumper |
| `verify_pre2k` | `pre-windows 2000`, `pre2k` | nxc pre2k module, PASSWD_NOTREQD bit check |
| `verify_pre_windows_2000` | `pre-windows 2000`, `pre windows 2000`, `pre-win2k` | Get-ADGroupMember, nxc anonymous LDAP |
| `verify_deprecated_os` | `deprecated`, `end-of-life`, `windows xp/7/2003/2008`, `eol operating system` | Computer OS enumeration, nxc --gen-relay-list |
| `verify_duplicate_spn` | `duplicate service principal names`, `duplicate spn` | setspn -X -F, PS SPN grouping |
| `verify_sid_history` | `sid history`, `sidhistory` | sIDHistory enumeration, nxc get-sid-history |
| `verify_foreign_security_principals` | `foreign security principal`, `foreignsecurityprincipal`, `cross-domain group member` | FSP enumeration with SID translation |
| `verify_computer_password_age` | `stale machine password`, `computer accounts with stale` | Reset-ComputerMachinePassword, netdom |
| `verify_service_accounts_gmsa` | `no gmsa adoption` | Get-ADServiceAccount, Add-KdsRootKey |
| `verify_rodc_password_replication` | `permissive password replication`, `rodc password replication` | msDS-RevealOnDemandGroup, ADUC RODC tab |

### Scoring / Output

`verify_*.py` modules **don't affect scoring** — they just enrich the report. A finding without any matching MATCH_KEY simply omits the verification UI; the scoring still runs on `severity` + `deduction`.

---

## 8. Configuration Files

### 8.1 `scoring.toml`

Three sections:

- **`[severity_weights]`** — defaults: critical=20, high=15, medium=8, low=5, info=0.
- **`[overrides]`** — exact-title overrides. Currently active (April 2026):
  - `User Accounts with Unconstrained Delegation = 25`
  - `Computer Accounts with Unconstrained Delegation = 20`
  - `DCSync Rights Detected on Domain Object = 25`
  - `Resource-Based Constrained Delegation (RBCD) Configured = 10`
  - `SYSVOL Replication: FRS in use — migration to DFSR not started = 10`
  - `SYSVOL Replication: DFSR Redirected — FRS still present = 3`
  - `AD Recycle Bin Not Enabled = 10`
  - `Excessive Site Link Replication Intervals = 10`
  - `User Accounts Used as Service Accounts (No gMSA Adoption) = 10`
- **Initial score** — `initial_score = 100` (configurable but rarely changed).

A local override file `scoring.local.toml` is gitignored — operators can tune per-engagement without polluting the repo.

### 8.2 `pyproject.toml` / `requirements.txt`

Python ≥3.10. Optional dev extras include `ruff`, `mypy`, `pytest`. Hard runtime deps:

- `ldap3 >= 2.10.0rc1` — required for LDAPS channel binding (`TLS_CHANNEL_BINDING`)
- `impacket` — SMB and Kerberos
- `python-docx >= 1.1.2` — DOCX report
- `Pillow >= 10.0.0` — DOCX images
- `dnspython` — used by `check_bloodhound.py` for SRV lookups

### 8.3 `.gitignore` (relevant entries)

`Reports/`, `Logs/`, `*.pfx`, `*.ccache`, `scoring.local.toml`, `CLAUDE.md`.

---

## 9. End-to-End Trace

What happens when a user runs `python adscan.py -d corp.local -dc-ip 10.10.10.5 -u alice -p Pass --unredacted`:

1. **`parse_args()`** builds the namespace.
2. **`configure_logging(False, None)`** — INFO console, no file.
3. **`ScoringConfig.load(None)`** → reads `scoring.toml` from project root.
4. **Auth method = "Password"**, prompt skipped because `-p` was supplied.
5. **`scan_timestamp = "20260422_143200"`** (example).
6. **`AuditLogger.start()`** → `Logs/adscan_20260422_143200.log` opened with header.
7. **`DebugLogger.start()`** → `Logs/adscan_debug_20260422_143200.log` opened.
8. **`ADConnector(...)`** built; `dbg` attached to `connector.debug_log`.
9. **`spinner("Connecting...") → connector.connect()`**:
   - `_probe_dc_requirements()` — 2 probes (~1 s each).
   - `_connect_ldap(use_ssl=False, ...)` — port 389 with NTLM.
   - `_connect_ldap(use_ssl=True, ...)` — port 636 with NTLM (signing/CBT applied if probed).
   - `_connect_smb()` — port 445.
10. **`load_checks()`** — imports all `checks/check_*.py` with `run_check`, sorted by `CHECK_ORDER`.
11. **For each check** (e.g. `check_password_policy.py`):
    - `dbg.log_check_start("Domain Password Policy")`
    - `spinner` shows after 2 s with elapsed time
    - `result = check.run_check(connector, verbose=False)`:
      - Calls `connector.ldap_search(...)` → connector logs each LDAP query via `dbg.log_ldap()`.
      - Returns `[finding_dict, finding_dict, ...]`.
    - `dbg.log_check_end("Domain Password Policy", result)`.
    - `audit.record_check("Domain Password Policy", result)`.
    - `findings.extend(result)` after annotating with `category` / `check_category` and recomputing `deduction` via `scoring.deduction_for(finding)`.
12. **All checks complete.** `connector.disconnect()`.
13. **`~/.nxc` archive** zipped to `Reports/Artifacts/nxc_20260422_143200.zip`.
14. **`compute_scores(findings, scoring, checks_run)`**:
    - For each `checks_run` entry: add weight to `possible` and `earned` per category.
    - For each finding: subtract `deduction` from `earned` per category.
    - Compute per-category and overall ratios.
15. **Report variants:** `[("", True), ("_operator", False)]` because `--unredacted` was supplied.
16. **For each variant × format:** `generate_report(...)` builds the HTML using `_finding_card()` which calls `_get_details(finding, redact)` (returns `details_redacted` if `redact=True` and the key exists, else `details`).
17. **Final score logged.** `audit.finish(score, report_path)` writes the summary footer. `dbg.finish()`.

---

## 10. Non-Obvious Design Decisions Summary

Anchor points for someone modifying the codebase:

1. **Connector probes the DC before binding.** This costs 1-2 s but prevents misleading "00002028" errors on hardened DCs.
2. **`ldap_search` returns dicts, not Entry objects.** Every check assumes this — don't switch back without updating all 40 modules.
3. **`pkgutil.iter_modules` auto-discovers checks AND verifications.** New modules drop in without registration. The cost is import-time errors are silent (warning to stderr only).
4. **First-match-wins matching** in `VERIFICATION_DB`. Order of MATCH_KEYS in modules is significant when keys could overlap (e.g. `"laps"` matches everything containing "laps").
5. **Ratio-based scoring, not deduction-from-100.** A clean check earns its full weight; a failing check loses earned but still contributes to possible. Categories with no checks run get 100 (not 0).
6. **`details` vs `details_redacted` is a critical contract.** Any check producing credential material in `details` must also produce `details_redacted`. The report's redact path falls back to `details` if the redacted key is missing — silently leaking credentials. Three checks currently exercise this contract: `check_gpp_cpassword.py`, `check_passwords_in_descriptions.py`, and `check_privileged_accounts.py`. New checks that surface credential strings must include the matching `details_redacted`.
7. **External tools install via `uv tool install`**, not pip. Keeps tool dependencies isolated. Tools are best-effort — checks emit info findings if the tool is missing.
8. **DebugLogger redacts credentials at the boundary.** `_PASSWORD_FLAGS` is the single point of failure — adding a tool with a different password flag spelling will leak passwords to the debug log.
9. **AuditLogger never logs credentials**, only auth method labels.
10. **Scoring overrides in `scoring.toml` are not optional tuning** — several active overrides (UD, DCSync, RBCD, FRS, Recycle Bin) intentionally diverge from severity-tier defaults. Disabling scoring.toml will under- or over-count those findings.
11. **HTML output is fully escaped via `html.escape`.** Any new code that inserts user-supplied strings into HTML must also escape.
12. **Spinner is TTY-only.** Piped output stays clean. The 2-second delay prevents flicker on fast operations.
13. **Check exception isolation is layered:**
    - Inside the check: the contract says catch and return info-finding.
    - In `adscan.py:main()`: a try/except wraps `check.run_check()` and logs to audit + debug, never re-raising.
14. **CHECK_ORDER values aren't all sequential.** Some checks (e.g. `check_foreign_security_principals.py = 67`) use higher numbers to run later. CHECK_ORDER 99 is reserved for `check_bloodhound.py` to ensure it runs last.
15. **Connector decoration in `main()`** — `artifacts_dir`, `scan_timestamp`, `debug_log`, and (during each check) `spinner` are attached after construction. Lets `ADConnector` stay focused on protocol/auth without knowing about output paths, logging, or terminal output.
16. **Kerberos against a DC supplied as an IP.** GSSAPI builds the SPN as `ldap/<host>` straight from `connector.dc_host`. When `dc_host` is an IP the SPN doesn't match anything AD has registered. `_ensure_kerberos_target` does an SRV lookup, monkey-patches `socket.getaddrinfo` so the FQDN routes back to the original IP, and rewrites `connector.dc_host` to the FQDN. Both ldap3 and impacket get the right SPN; TCP still goes to the right address.
17. **krb5.conf synthesis.** On a host that has no `/etc/krb5.conf` or no `default_realm`, GSSAPI fails with "Configuration file does not specify default realm" before any bind is attempted. `_ensure_krb5_config` writes a temp config using `domain.upper()` as the realm and `dc_host` as the KDC and points `KRB5_CONFIG` at it. Operator hosts without an AD-aware krb5.conf can run `--kerberos` scans without touching `/etc/krb5.conf`.
18. **`--dns-server` propagates two ways.** In-process: the `_install_dns_resolver` monkey-patch sends ldap3/impacket lookups through dnspython against the chosen resolver. Out-of-process: each check that runs a subprocess (`nxc`, `certipy-ad`, `bloodhound-python`, `bloodhound-ce-python`) appends the appropriate per-tool nameserver flag. Different tools use different flag spellings — `nxc` uses `--dns-server`, certipy uses `-ns`.
19. **LDAP timeout is a stall detector, not a wall clock.** `--timeout` flows into the ldap3 `Connection(receive_timeout=...)` kwarg, which is reset every time the server sends data. Legitimately slow but progressing searches in large environments continue; only true silence triggers the timeout. The DNS wildcard query in `check_dns_infrastructure.py` was the canonical case that motivated this: the original filter `(dc=*)` returned every DNS record in the zone, and a wall-clock cap would have killed both that broken query and many legitimate ones. The filter is now properly escaped (`dc=\\2A`); the receive-timeout backstop catches future broad queries without false positives.
20. **BloodHound engine selector.** `check_bloodhound.py` prompts the operator at the BloodHound step to choose between Legacy BloodHound and BloodHound Community Edition. The prompt wraps `input()` in `connector.spinner.suspended()` so the spinner stops drawing during the question. Non-interactive sessions (no TTY) silently default to Legacy.

---

## 11. Where to Look When You Need To...

| Task | Start here |
|------|------------|
| Add a new check | `checks/check_template.py` doesn't exist — copy `check_optional_features.py` (smallest example). Define `CHECK_NAME/ORDER/CATEGORY/WEIGHT` and `run_check`. |
| Add a verification module | Copy any existing `verifications/verify_*.py`. Define `MATCH_KEYS`, `TOOLS`, optional `REMEDIATION` / `REFERENCES`. |
| Add a new external tool | Add `ToolSpec` to `TOOL_REGISTRY` in `lib/tools.py`. Use `ensure_tool(slug)` from your check. |
| Override a finding's deduction | Add to `[overrides]` in `scoring.toml` (exact title match) or `scoring.local.toml` (per-engagement). |
| Change report styling | `lib/report.py:generate_report` — CSS is embedded inline. |
| Add a new severity tier | Update `SEVERITY_COLORS`, `SEV_ORDER` in `lib/report.py`; `_BUILTIN_SEVERITY_WEIGHTS` in `lib/scoring.py`; `_SEV_ORDER` in `lib/audit_log.py`. |
| Debug a check that's silently failing | Tail `Logs/adscan_debug_*.log` — every LDAP query, subprocess call, and exception is recorded with redaction. |
| Investigate scoring | Audit log shows per-check deductions; HTML report shows per-category breakdown; CSV report has per-finding deduction columns. |
| Re-enable LDAP-only ADCS checks | Uncomment the `_run_ldap_checks` call in `check_adcs.py:run_check` (the function body is preserved). |
