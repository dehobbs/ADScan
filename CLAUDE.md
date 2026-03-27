# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

ADScan is a modular Active Directory vulnerability scanner that connects to domain controllers via LDAP/LDAPS/SMB, runs security checks, and produces HTML/JSON/CSV/DOCX reports with a risk score. Python 3.10+, GPL-3.0-only.

## Commands

```bash
# Install (editable, with dev extras)
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Install external CLI tools (certipy-ad, netexec) into isolated venvs
python adscan.py --setup-tools        # requires uv on PATH
# Or manually:
uv tool install certipy-ad            # ADCS scanner (v5.0.4+, Python 3.12+)
uv tool install netexec               # SMB signing/SMBv1 detection (nxc)

# Run the scanner
python adscan.py -d corp.local --dc-ip 10.10.10.5 -u alice -p 'P@ssw0rd!'

# List available checks
python adscan.py --list-checks

# Lint
ruff check .

# Type check
mypy adscan.py lib/ checks/

# Tests (no tests/ directory exists yet — testpaths configured as "tests" in pyproject.toml)
pytest --cov=lib --cov=checks --cov-report=term-missing
```

## Architecture

### Entry point

`adscan.py` — CLI arg parsing, check auto-discovery, orchestration loop, report generation. Connects via `ADConnector`, runs each loaded check, computes scores, writes output.

### Core libraries (`lib/`)

- **`connector.py`** — `ADConnector` class: manages LDAP/LDAPS/SMB connections with password, NTLM hash, or Kerberos ccache auth. Probes DC for signing/channel-binding requirements before binding. All check modules receive this as their first argument. Key methods: `ldap_search()`, `smb_available()`, `get_smb_shares()`, `resolve_sid()`.
- **`tools.py`** — External CLI tool manager. `TOOL_REGISTRY` maps slugs to `ToolSpec` dataclasses. `ensure_tool(slug)` checks PATH, then auto-installs via `uv tool install` into an isolated venv. `setup_all_tools()` installs all registered tools (used by `--setup-tools`). Tools: `certipy-ad` (ADCS checks), `netexec`/`nxc` (SMB checks).
- **`scoring.py`** — `ScoringConfig` loads `scoring.toml` (TOML config for severity weights and per-finding overrides). `compute_scores()` implements ratio-based scoring: earned/possible per category, not simple deduction from 100.
- **`report.py`** — Generates self-contained HTML report (with embedded CSS/JS, light/dark mode), plus JSON, CSV, and DOCX exports. Auto-discovers verification modules for remediation cards.
- **`audit_log.py`** / **`debug_log.py`** — Structured audit trail and LDAP query debug log written to `Logs/`.

### Check modules (`checks/`)

Auto-discovered at runtime: any `checks/check_*.py` with a `run_check(connector, verbose)` function is loaded and executed. Each module defines:
- `CHECK_NAME` (str), `CHECK_ORDER` (int), `CHECK_CATEGORY` (list[str]), `CHECK_WEIGHT` (int)
- `run_check(connector, verbose=False) -> list[dict]` — returns finding dicts or empty list

Finding dict schema: `title`, `severity`, `deduction`, `description`, `recommendation`, `details` (list, optional).

Checks that need external CLI tools use `from lib.tools import ensure_tool` to resolve the exe path (auto-installing via uv if needed).

### Verification modules (`verifications/`)

`verify_*.py` files provide manual verification tool commands and remediation steps. Matched to findings by `MATCH_KEYS` (lowercase substring match against finding titles). Auto-discovered by `report.py`.

### Scoring (`scoring.toml`)

Ratio-based model: each check has a `CHECK_WEIGHT` (max points at stake). Clean checks earn full weight; findings reduce earned points. Deduction priority: `[overrides]` (exact title match) > `[severity_weights]` > hardcoded `finding["deduction"]`.

## Adding a New Check

1. Create `checks/check_<name>.py` with `CHECK_NAME`, `CHECK_ORDER`, `CHECK_CATEGORY`, `CHECK_WEIGHT`, and `run_check(connector, verbose=False)`
2. Optionally create `verifications/verify_<name>.py` with `MATCH_KEYS`, `TOOLS`, `REMEDIATION`
3. Optionally add title overrides to `scoring.toml` if the default severity-tier deduction is wrong for your finding
4. If the check needs an external CLI tool, add a `ToolSpec` entry to `TOOL_REGISTRY` in `lib/tools.py` and use `ensure_tool()` to resolve the exe path

The check is auto-discovered on next run — no registration needed.

## Key Conventions

- Check modules must never `raise` out of `run_check()` or call `sys.exit()` — catch exceptions and return info-severity findings with deduction 0
- External CLI tools (certipy-ad, nxc) are installed in isolated venvs via `uv tool install`, not into ADScan's own environment — use `lib.tools.ensure_tool()` to resolve paths
- `ldap_search()` returns dicts (converted from ldap3 Entry objects via `_entry_to_dict`), not raw ldap3 entries
- `--checks` and `--skip` CLI flags filter by slug (module name minus `check_` prefix, words from `CHECK_NAME`, and `CHECK_CATEGORY` values)
- Ruff config: line-length 100, select E/F/W/I, E501 ignored
- Reports output to `Reports/`, logs to `Logs/`, artifacts to `Reports/Artifacts/` — all gitignored
- Local scoring overrides go in `scoring.local.toml` (gitignored)
