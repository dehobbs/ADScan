# Changelog

All notable changes to ADScan are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
ADScan uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] — 2026-03-17

First stable release. ADScan is a modular, Python-based Active Directory
vulnerability scanner that connects to domain controllers via LDAP, LDAPS,
and SMB, runs a battery of security checks, and produces a self-contained
HTML dashboard report with a risk score.

### Added

**Core scanner**
- `adscan.py` — entry point with argparse-based CLI, auto-discovery of
  `checks/check_*.py` modules sorted by `CHECK_ORDER`, connection management
  via `ADConnector`, and report dispatch
- `lib/connector.py` — `ADConnector` class managing LDAP, LDAPS, and SMB
  connections with password and NTLM pass-the-hash authentication
- `lib/report.py` — self-contained HTML report generator with light/dark
  mode toggle, severity chips, collapsible finding cards, and risk-score
  grade display; plus `generate_json_report()` and `generate_csv_report()`
  for machine-readable exports
- `lib/audit_log.py` — structured audit trail written alongside reports
- `lib/debug_log.py` — low-level LDAP query debug log

**Authentication**
- Password authentication via `-p` / `--password`
- NTLM pass-the-hash via `--hash` (accepts `LM:NT` or NT-only format)
- Interactive password prompt via `getpass` when neither `-p` nor `--hash`
  is supplied — avoids credential exposure in shell history

**Protocol support**
- LDAP (port 389), LDAPS (port 636), SMB (port 445)
- `--protocol` flag to select one or all protocols (default: `all`)

**Output formats**
- `--format html` — self-contained HTML dashboard (default)
- `--format json` — machine-readable JSON with full finding detail,
  scan metadata, and summary statistics
- `--format csv` — flat CSV suitable for import into Excel or SIEM tools
- `--format all` — writes all three formats simultaneously
- `-o` / `--output` — custom output path stem

**CLI flags**
- `-d` / `--domain` — target domain FQDN (required)
- `--dc-ip` — domain controller IP or hostname (required)
- `-u` / `--username` — username (required)
- `--timeout` — connection timeout in seconds (default: 30)
- `-v` / `--verbose` — verbose console output
- `--scoring-config` — path to a custom `scoring.toml` (default: `scoring.toml`
  next to `adscan.py`)

**Configurable risk scoring**
- Risk score starts at 100 and deducts per finding down to a floor of 0
- Letter grade A–F assigned at report generation
- `scoring.toml` — optional TOML configuration file for overriding severity
  weights and per-finding deduction values without editing check code
- `lib/scoring.py` — `ScoringConfig` class with three-tier resolution:
  (1) exact `[overrides]` title match, (2) `[severity_weights]` tier,
  (3) check module hardcoded default; fully backwards-compatible when
  `scoring.toml` is absent or unparseable
- `tomllib` (stdlib, Python 3.11+) used with `tomli` backport fallback for
  Python 3.9 / 3.10

**Security checks (38 modules)**

| Module | Category | What it checks |
|--------|----------|----------------|
| `check_password_policy.py` | Password Policy | Lockout threshold, observation window, minimum length, complexity, max age, reversible encryption |
| `check_kerberos.py` | Kerberos | AS-REP roasting (no pre-auth), Kerberoastable SPNs, encryption types |
| `check_rc4_encryption.py` | Kerberos | RC4 / DES Kerberos encryption still permitted |
| `check_unconstrained_delegation.py` | Delegation | Unconstrained Kerberos delegation on non-DC accounts |
| `check_constrained_delegation.py` | Delegation | Constrained delegation configuration |
| `check_dangerous_constrained_delegation.py` | Delegation | Constrained delegation to sensitive services |
| `check_rbcd_domain_dcs.py` | Delegation | Resource-based constrained delegation on domain controllers |
| `check_privileged_accounts.py` | Privileged Accounts | Privileged account hygiene and configuration |
| `check_protected_admin_users.py` | Privileged Accounts | AdminSDHolder / SDProp protected accounts (`adminCount=1`) |
| `check_protected_users_group.py` | Privileged Accounts | Tier-0 and Tier-1 privileged accounts not in Protected Users security group |
| `check_adminsdholder_acl.py` | Privileged Accounts | Dangerous ACEs on the AdminSDHolder object |
| `check_acl_permissions.py` | Privileged Accounts | Dangerous discretionary ACLs on AD objects |
| `check_account_hygiene.py` | Account Hygiene | Stale, disabled, or never-logged-on accounts |
| `check_shadow_credentials.py` | Account Hygiene | Shadow credentials (`msDS-KeyCredentialLink`) on accounts |
| `check_sid_history.py` | Account Hygiene | SID history abuse potential |
| `check_foreign_security_principals.py` | Account Hygiene | Foreign security principals from external domains |
| `check_pre_windows_2000.py` | Account Hygiene | Pre-Windows 2000 compatible access group membership |
| `check_service_accounts.py` | Account Hygiene | Service account password age and configuration |
| `check_passwords_in_descriptions.py` | Account Hygiene | Cleartext passwords stored in account description fields |
| `check_laps.py` | LAPS | LAPS deployment and configuration |
| `check_laps_coverage.py` | LAPS | Computer accounts not covered by LAPS |
| `check_gpo.py` | GPO | GPO link and permission issues |
| `check_gpp_cpassword.py` | GPO | GPP cPassword (MS14-025) credential exposure |
| `check_audit_policy.py` | Audit Policy | Domain audit policy configuration |
| `check_smb.py` | SMB | SMB signing enforcement and dialect support |
| `check_legacy_protocols.py` | Legacy Protocols | NTLMv1, LDAP signing, LDAP channel binding |
| `check_protocol_security.py` | Legacy Protocols | Protocol security configuration |
| `check_legacy_frs_sysvol.py` | Legacy Protocols | Legacy FRS SYSVOL replication (should be DFS-R) |
| `check_deprecated_os.py` | Infrastructure | Domain-joined systems running end-of-life operating systems |
| `check_domain_controllers.py` | Infrastructure | Domain controller configuration and security |
| `check_replication.py` | Infrastructure | AD replication health and failures |
| `check_dns_infrastructure.py` | Infrastructure | DNS infrastructure security |
| `check_domain_trusts.py` | Infrastructure | Domain trust configuration and SID filtering |
| `check_orphaned_subnets.py` | Infrastructure | AD sites and services orphaned subnets |
| `check_adcs.py` | Certificate Services | ADCS certificate template vulnerabilities (ESC1–ESC8) |
| `check_misc_hardening.py` | Miscellaneous | Miscellaneous domain hardening settings |
| `check_optional_features.py` | Miscellaneous | AD optional feature status (Recycle Bin, PAM) |
| `check_rc4_encryption.py` | Kerberos | RC4 encryption permitted in the domain |

**Project documentation and metadata**
- `LICENSE` — GNU General Public License v3
- `README.md` — installation, usage, all CLI flags, examples, and disclaimer
- `CONTRIBUTING.md` — contributor guide: check interface spec, `run_check`
  function signature, finding schema, `ADConnector` public API, severity
  guidelines, `CHECK_ORDER` allocation table, scoring config integration,
  common helper patterns, and a complete worked example
- `requirements.txt` — `ldap3`, `impacket`, `pyOpenSSL`
- Repository topics: `python`, `windows`, `security`, `ldap`,
  `active-directory`, `penetration-testing`, `red-team`, `vulnerability-scanner`

### Fixed

- CLI flags in README corrected to match actual argparse arguments:
  `--dc` → `--dc-ip`, `--user` → `--username`; `--dc-ip` added to synopsis
- `import traceback` moved from inside exception handler to top-level imports
  (PEP 8 compliance)
- Connection timeout properly threaded through `ADConnector.__init__` and
  passed to both `ldap3.Server(connect_timeout=)` and
  `SMBConnection(timeout=)` constructors

---

## [Unreleased]

_Nothing yet._

---

[1.0.0]: https://github.com/dehobbs/ADScan/releases/tag/v1.0.0
[Unreleased]: https://github.com/dehobbs/ADScan/compare/v1.0.0...HEAD
