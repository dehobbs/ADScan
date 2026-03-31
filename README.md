# ADScan

**Active Directory Vulnerability Scanner** is a modular, Python-based tool
that connects to domain controllers via LDAP, LDAPS, and/or SMB, runs a
comprehensive battery of security checks, and produces a self-contained
HTML dashboard report with a risk score and letter grade.

---

## Features

- **Multi-protocol**: LDAP, LDAPS, SMB (user-selectable; defaults to all three)
- **Flexible auth**: password, pass-the-hash (NTLM `LM:NT` or `NT`), Kerberos ccache, or interactive prompt
- **40+ security checks** covering critical AD attack surfaces across eight categories
- **BloodHound integration**: automatic AD graph data collection saved to `Reports/Artifacts/`
- **Risk score**: ratio-based scoring per category, overall score maps to letter grade A–F
- **HTML report**: self-contained, light/dark mode, severity filter chips, collapsible finding cards with remediation guidance
- **Multiple export formats**: HTML, JSON, CSV, DOCX
- **Modular**: drop a new `check_*.py` in `checks/` and it is auto-discovered at runtime
- **Scoring customisation**: tune deductions per finding via `scoring.toml` without touching check code

---

## Prerequisites

Before installing ADScan, ensure the following are available on your system:

| Prerequisite | Version | Purpose |
|-------------|---------|---------|
| Python | 3.10+ | Core runtime |
| Git | any | Required to install pre2k from GitHub |
| [uv](https://docs.astral.sh/uv/) | any | Installs external CLI tools into isolated venvs |

> **Certipy** (ADCS checks) requires **Python 3.12+** in its own isolated venv. uv
> handles this automatically — it is not a requirement for ADScan itself.

**Install uv** if you do not have it:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

---

## Installation

### 1. Clone and install

```bash
git clone https://github.com/dehobbs/ADScan.git
cd ADScan

# Option A — uv (recommended)
uv venv && source .venv/bin/activate
uv pip install -e .

# Option B — pip
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

> **Kali / externally-managed Python**: always create a virtual environment first
> to avoid the "externally managed environment" pip error.

### 2. Install external CLI tools

Some checks invoke external tools as subprocesses. Each tool is installed into
its **own isolated virtual environment** via `uv tool install` so its
dependencies never conflict with ADScan's packages.

**One-command setup** (installs all tools at once):

```bash
python adscan.py --setup-tools
```

Or install individually:

```bash
uv tool install certipy-ad                                        # ADCS/PKI scanner (Python 3.12+ venv)

# NetExec — recommended install via pipx (or apt on Kali/ParrotSec):
apt install netexec                                               # Kali / ParrotSec / BlackArch
# or:
pipx install git+https://github.com/Pennyw0rth/NetExec           # other systems

uv tool install git+https://github.com/garrettfoster13/pre2k.git  # Pre-Windows 2000 account tester
uv tool install bloodhound                                        # BloodHound AD ingestor
```

> Tools are **optional**. If a tool is missing when a check runs, ADScan will
> attempt to auto-install it via `uv tool install`. If `uv` is not on PATH,
> the check is skipped gracefully with an informational finding.

### 3. Optional Python extras

```bash
pip install -e ".[kerberos]"  # gssapi bindings for Kerberos over LDAP
pip install -e ".[dev]"       # pytest, ruff, mypy for development
```

### 4. Verify the install

```bash
python adscan.py --list-checks    # should print all 40+ checks
python adscan.py --setup-tools    # installs / verifies all external tools
```

---

## Quick Start

```bash
# Password authentication
python adscan.py -d corp.local --dc-ip 10.10.10.5 -u alice -p 'P@ssw0rd!'

# Interactive password prompt (no -p flag — password is not echoed)
python adscan.py -d corp.local --dc-ip 10.10.10.5 -u alice

# Pass-the-hash
python adscan.py -d corp.local --dc-ip 10.10.10.5 -u alice \
  --hash aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c

# Kerberos ticket reuse (KRB5CCNAME set in environment)
export KRB5CCNAME=/tmp/alice.ccache
python adscan.py -d corp.local --dc-ip 10.10.10.5 -u alice --kerberos

# All output formats
python adscan.py -d corp.local --dc-ip 10.10.10.5 -u alice -p 'P@ssw0rd!' --format all

# Run only Kerberos-related checks
python adscan.py -d corp.local --dc-ip 10.10.10.5 -u alice -p 'P@ssw0rd!' --checks kerberos
```

---

## CLI Reference

```
python adscan.py -d <domain> --dc-ip <dc_ip> -u <user> -p <pass> [options]
```

### Target & Authentication

| Flag | Description | Default |
|------|-------------|---------|
| `-d / --domain` | Target domain FQDN (e.g. `corp.local`) | required |
| `--dc-ip` | Domain controller IP or hostname | required |
| `-u / --username` | Username for authentication | required |
| `-p / --password` | Password (omit to be prompted securely) | — |
| `--hash LM:NT` | NTLM hash; `LM:NT` or NT-only. Mutually exclusive with `-p` and `--kerberos` | — |
| `--kerberos` | Use Kerberos ticket from `KRB5CCNAME` env var | — |
| `--ccache PATH` | Path to Kerberos ccache file (implies `--kerberos`) | — |
| `--protocol` | `ldap` \| `ldaps` \| `smb` \| `all` | `all` |
| `--timeout SEC` | Connection timeout in seconds | `30` |

### Output

| Flag | Description | Default |
|------|-------------|---------|
| `-o / --output` | Report path stem (extension added automatically) | `Reports/adscan_report_<timestamp>` |
| `--output-dir DIR` | Directory for all report files | `Reports/` |
| `--format` | `html` \| `json` \| `csv` \| `docx` \| `all` | `html` |
| `--log-file PATH` | Write full DEBUG log to a file in addition to console | — |
| `-v / --verbose` | Show DEBUG-level detail on the console | off |

### Check Control

| Flag | Description |
|------|-------------|
| `--checks SLUG[,…]` | Run only the specified checks (comma-separated slugs) |
| `--skip SLUG[,…]` | Exclude specific checks |
| `--list-checks` | Print all available checks with slugs, categories, and weights, then exit |

### Utilities

| Flag | Description |
|------|-------------|
| `--setup-tools` | Install all external CLI tools via `uv tool install` and exit |
| `--scoring-config PATH` | Use a custom TOML scoring config instead of `scoring.toml` |

---

## Authentication Methods

### Password

```bash
python adscan.py -d corp.local --dc-ip 10.10.10.5 -u alice -p 'P@ssw0rd!'
# Or prompt securely:
python adscan.py -d corp.local --dc-ip 10.10.10.5 -u alice
```

### Pass-the-Hash (NTLM)

```bash
python adscan.py -d corp.local --dc-ip 10.10.10.5 -u alice \
  --hash aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c
# NT hash only (blank LM):
python adscan.py -d corp.local --dc-ip 10.10.10.5 -u alice \
  --hash 8846f7eaee8fb117ad06bdd830b7586c
```

### Kerberos

Kerberos ticket reuse is useful when NTLM is disabled or in assumed-breach scenarios.

```bash
# Obtain a TGT with impacket
getTGT.py corp.local/alice:'P@ssw0rd!' -dc-ip 10.10.10.5
export KRB5CCNAME=$(pwd)/alice.ccache

# Use the ticket
python adscan.py -d corp.local --dc-ip 10.10.10.5 -u alice --kerberos

# Or supply the ccache path explicitly
python adscan.py -d corp.local --dc-ip 10.10.10.5 -u alice --ccache /tmp/alice.ccache
```

> Kerberos over LDAP requires the `gssapi` package (`pip install -e ".[kerberos]"`)
> and a valid `/etc/krb5.conf`. Kerberos over SMB is handled natively by impacket.

---

## Security Checks

Checks are auto-discovered from `checks/check_*.py`. Run `--list-checks` to
see all available checks with slugs for use with `--checks` and `--skip`.

### Account Hygiene

| Check | What it tests |
|-------|--------------|
| Domain Password Policy | Minimum length, complexity, lockout, max age |
| Account Hygiene | Stale, never-logged-on, and PASSWD_NOTREQD accounts |
| Computer Account Password Age | Machine passwords not rotated in > 30 days |
| Pre-Windows 2000 Computer Accounts | Computer accounts with predictable default passwords (CVE prerequisite) |
| Passwords in Descriptions | Cleartext credentials stored in AD description fields |
| SID History | Accounts with SID history that could allow privilege escalation |
| Shadow Credentials | msDS-KeyCredentialLink attribute abuse |

### Kerberos

| Check | What it tests |
|-------|--------------|
| Kerberos Attack Surface | AS-REP roasting, Kerberoasting, DES encryption, pre-auth |
| Unconstrained Delegation | User and computer accounts with unconstrained delegation |
| Constrained Delegation | S4U2Self/S4U2Proxy delegation with protocol transition |
| RC4 / Legacy Kerberos Encryption | RC4 and DES encryption permitted on accounts and DCs |
| RBCD on Domain Object / DCs | Resource-based constrained delegation misconfiguration |
| NoPac (CVE-2021-42278/42287) | PAC validation bypass — checks all DCs via nxc nopac module |

### Privileged Accounts

| Check | What it tests |
|-------|--------------|
| Privileged Accounts | krbtgt age, built-in admin, DA count, stale privileged accounts |
| LAPS Deployment | Legacy and Windows LAPS schema and coverage |
| LAPS Coverage | Per-OU LAPS coverage gaps |
| ACL / Permissions | DCSync rights, GenericAll/Write/Owner over high-value objects |
| AdminSDHolder ACL | Non-standard ACEs on the AdminSDHolder object |
| Service Accounts | User accounts used as service accounts lacking gMSA adoption |
| Protected Admin Users | High-privilege accounts missing Protected Users group membership |
| Protected Users Group Membership | Protected Users group population |

### Protocol Security

| Check | What it tests |
|-------|--------------|
| SMB Signing Enforcement | SMB signing enforcement and SMBv1 detection across all hosts |
| Legacy Protocols | NTLM, WDigest, LLMNR, NetBIOS-NS configuration |
| Protocol Security | LDAP signing and channel binding enforcement |

### Domain Hygiene

| Check | What it tests |
|-------|--------------|
| Domain Controllers | DC count, OS versions, FSMO roles, AD recycle bin |
| Domain Trusts | Trust type, direction, SID filtering, transitivity |
| Group Policy Objects | Unlinked GPOs, empty GPOs, GPO permissions |
| GPP / cpassword (MS14-025) | Cleartext passwords in SYSVOL Group Policy Preferences |
| Optional Features | AD Recycle Bin, PAM feature status |
| Replication Health | Site link intervals, replication failures |
| Miscellaneous Hardening | Machine account quota, null sessions, guest account |
| Legacy FRS SYSVOL | FRS vs DFSR replication status |
| Pre-Windows 2000 Compatible Access | Group membership (Everyone, Anonymous, Authenticated Users) |
| BloodHound Data Collection | Full AD graph snapshot — ZIP saved to `Reports/Artifacts/` |

### ADCS / PKI

| Check | What it tests |
|-------|--------------|
| ADCS / PKI Vulnerabilities | ESC1–ESC16 certificate template and CA misconfigurations |

### Network Hygiene

| Check | What it tests |
|-------|--------------|
| DNS & Infrastructure | Wildcard DNS records, AD-integrated DNS hygiene |
| Orphaned AD Subnets | Subnets defined in Sites & Services with no site assigned |

### Groups Hygiene

| Check | What it tests |
|-------|--------------|
| Foreign Security Principals in Privileged Groups | Cross-forest principals in DA/EA/BA/Schema Admins |

### Audit & Hardening

| Check | What it tests |
|-------|--------------|
| Advanced Audit Policy | Presence and coverage of advanced audit subcategories |

---

## Check Filtering

```bash
# List all checks and their slugs
python adscan.py --list-checks

# Run only Kerberos checks
python adscan.py -d corp.local --dc-ip 10.10.10.5 -u alice -p 'P@ss' --checks kerberos

# Run ADCS and delegation checks only
python adscan.py -d corp.local --dc-ip 10.10.10.5 -u alice -p 'P@ss' --checks adcs,delegation

# Skip SMB (firewalled) and DNS
python adscan.py -d corp.local --dc-ip 10.10.10.5 -u alice -p 'P@ss' --skip smb,dns

# Skip BloodHound collection (time-sensitive engagement)
python adscan.py -d corp.local --dc-ip 10.10.10.5 -u alice -p 'P@ss' --skip bloodhound
```

Slugs are matched against the module filename (minus `check_` prefix), words
in `CHECK_NAME`, and `CHECK_CATEGORY` values — so `kerberos`, `delegation`,
and `roasting` all match relevant checks.

---

## BloodHound Integration

When the `bloodhound` tool is installed, ADScan automatically collects a full
AD graph snapshot during the scan using `bloodhound-python`. The resulting
ZIP archive is saved to `Reports/Artifacts/` alongside other scan artifacts.

The collection runs last (after all security checks) and uses the same
credentials supplied to ADScan. When `--dc-ip` is an IP address, ADScan
automatically resolves the DC FQDN via a DNS SRV lookup
(`_ldap._tcp.dc._msdcs.<domain>`) so `bloodhound-python` receives the
hostname it requires.

Import the ZIP into the BloodHound application to visualise attack paths,
shortest paths to Domain Admin, and Kerberos delegation chains.

To skip BloodHound collection:

```bash
python adscan.py ... --skip bloodhound
```

---

## Output & Reports

Reports are written to `Reports/` by default.

| Format | Flag | Description |
|--------|------|-------------|
| HTML | `--format html` (default) | Self-contained dashboard — embedded CSS/JS, light/dark mode, severity filters |
| JSON | `--format json` | Machine-readable findings list |
| CSV | `--format csv` | Flat finding rows for spreadsheet analysis |
| DOCX | `--format docx` | Word document with findings and command output evidence |
| All | `--format all` | Produces all four formats in one run |

Supporting artifacts (nxc output, BloodHound ZIP, Certipy JSON) are written
to `Reports/Artifacts/`.

---

## Scoring

ADScan uses a **ratio-based** model, not a simple deduction from 100:

- Each check declares a **weight** (maximum points it can contribute)
- A clean check earns its full weight; findings reduce earned points by their deduction
- **Category score** = earned / possible × 100 (per category)
- **Overall score** = total earned / total possible × 100

| Score | Grade |
|-------|-------|
| 90–100 | A |
| 75–89  | B |
| 60–74  | C |
| 40–59  | D |
| 0–39   | F |

### Default severity deductions

| Severity | Deduction |
|----------|-----------|
| Critical | 20 pts |
| High     | 15 pts |
| Medium   | 8 pts  |
| Low      | 5 pts  |
| Info     | 0 pts  |

### Customising scoring

Edit `scoring.toml` or create a `scoring.local.toml` (gitignored) for
engagement-specific overrides:

```toml
[severity_weights]
critical = 25
high     = 15
medium   = 5
low      = 2
info     = 0

[overrides]
# Raise impact
"User Accounts with Unconstrained Delegation" = 25
# Suppress from score (still appears in report)
"Lockout Observation Window Too Short"        = 0
```

```bash
# Use a custom scoring file
python adscan.py ... --scoring-config engagement_scoring.toml
```

---

## External Tools

ADScan uses several external CLI tools for checks that require network
enumeration or specialised analysis. Each is installed in its own isolated
Python virtual environment via `uv tool install`.

| Slug | Command | Package | Checks That Use It |
|------|---------|---------|-------------------|
| `certipy` | `certipy` | `certipy-ad` (PyPI) | ADCS / PKI (ESC1–ESC16) |
| `nxc` | `nxc` | `netexec` — see [install guide](https://www.netexec.wiki/getting-started/installation/installation-on-unix) | SMB signing, SMBv1, NoPac |
| `pre2k` | `pre2k` | GitHub: `garrettfoster13/pre2k` | Pre-Windows 2000 computer accounts |
| `bloodhound` | `bloodhound-python` | `bloodhound` (PyPI) | BloodHound data collection |

Install all tools at once:

```bash
python adscan.py --setup-tools
```

> **NetExec note:** The recommended install is `apt install netexec` (Kali/ParrotSec) or
> `pipx install git+https://github.com/Pennyw0rth/NetExec` (other systems). If `nxc` is
> already on PATH, ADScan will use it directly — no uv required.

> For all other tools, `uv` must be on PATH for `--setup-tools` auto-install. If uv is
> not available, install the tool manually and ensure its executable is on PATH.

---

## Project Structure

```
ADScan/
├── adscan.py               # CLI entry point and orchestration loop
├── scoring.toml            # Default severity weights and per-finding overrides
├── scoring.local.toml      # Local overrides — gitignored, safe for engagement use
├── requirements.txt        # Pinned dependencies
├── pyproject.toml          # Package metadata and tool config
├── lib/
│   ├── connector.py        # ADConnector — LDAP/LDAPS/SMB connection manager
│   ├── tools.py            # External CLI tool manager (uv-based isolation)
│   ├── scoring.py          # Ratio-based scoring engine
│   ├── report.py           # HTML / JSON / CSV / DOCX report generation
│   ├── audit_log.py        # Structured audit trail
│   └── debug_log.py        # LDAP query debug log
├── checks/                 # Security check modules (auto-discovered)
├── verifications/          # Manual verification and remediation guidance
├── Reports/                # Generated reports (gitignored)
│   └── Artifacts/          # Tool output files, BloodHound ZIP
└── Logs/                   # Audit and debug logs (gitignored)
```

---

## Adding a New Check

1. Create `checks/check_<name>.py` with `CHECK_NAME`, `CHECK_ORDER`,
   `CHECK_CATEGORY`, `CHECK_WEIGHT`, and `run_check(connector, verbose=False)`
2. Optionally create `verifications/verify_<name>.py` with `MATCH_KEYS`,
   `TOOLS`, `REMEDIATION`, and `REFERENCES`
3. If the check needs an external tool, add a `ToolSpec` to `TOOL_REGISTRY`
   in `lib/tools.py` and call `ensure_tool()` in the check

No registration is needed — files are auto-discovered on the next run.
See `CONTRIBUTING.md` for the full contribution guide.

---

## Disclaimer

ADScan is intended for **authorised security assessments only**. Always obtain
written permission before scanning an Active Directory environment.
Unauthorised use may violate computer crime laws.
