# ADScan
**Active Directory Vulnerability Scanner** — a modular, Python-based tool that connects to domain controllers via LDAP, LDAPS, and/or SMB, runs a comprehensive battery of security checks, and produces a self-contained HTML dashboard report with a risk score.

---

## Features

- **Multi-protocol**: LDAP, LDAPS, SMB (user-selectable; defaults to all three)
- **Flexible auth**: password, pass-the-hash (NTLM `LM:NT` or `NT`), Kerberos ccache, or interactive prompt
- **Risk score**: starts at 100, deducted per finding (floor 0), letter grade A–F
- **HTML report**: fully self-contained, light/dark mode toggle, severity chips, collapsible finding cards
- **JSON / CSV output**: machine-readable exports alongside the HTML report
- **Modular**: drop a new `check_*.py` file in `checks/` — it's auto-discovered at runtime
- **36 security checks** covering the most critical AD attack surfaces

---

## Installation

```bash
git clone https://github.com/dehobbs/ADScan.git
cd ADScan
pip install -r requirements.txt
```

### Requirements

| Package | Purpose |
|---------|---------|
| `ldap3` | LDAP / LDAPS connectivity |
| `impacket` | SMB connectivity, pass-the-hash, Kerberos auth |
| `pyOpenSSL` | LDAPS certificate handling |
| `gssapi` | Kerberos GSSAPI bindings for LDAP (optional — only needed for `--kerberos`) |

---

## Usage

```
python adscan.py -d <domain> --dc-ip <dc_ip> -u <username> -p <password> [options]
python adscan.py -d <domain> --dc-ip <dc_ip> -u <username> --hash <LM:NT or NT> [options]
python adscan.py -d <domain> --dc-ip <dc_ip> -u <username>              # prompts for password
python adscan.py -d <domain> --dc-ip <dc_ip> -u <username> --kerberos   # use KRB5CCNAME
python adscan.py -d <domain> --dc-ip <dc_ip> -u <username> --ccache /tmp/user.ccache
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-d / --domain` | Target domain FQDN (e.g. `corp.local`) | required |
| `--dc-ip` | Domain controller IP or hostname | required |
| `-u / --username` | Username | required |
| `-p / --password` | Password (omit to be prompted securely) | — |
| `--hash` | NTLM hash (`LM:NT` or `NT`) | — |
| `--kerberos` | Authenticate using a Kerberos ticket; reads ccache from `KRB5CCNAME` env var | — |
| `--ccache PATH` | Path to a Kerberos ccache file (implies `--kerberos`; overrides `KRB5CCNAME`) | — |
| `--protocol` | `ldap` \| `ldaps` \| `smb` \| `all` | `all` |
| `--timeout` | Connection timeout in seconds | `30` |
| `--format` | `html` \| `json` \| `csv` \| `all` | `html` |
| `--log-file PATH` | Write all log output (including DEBUG detail) to a file in addition to the console | off |
| `-o / --output` | Output report path stem | `Reports/adscan_report_<timestamp>` |
| `-v / --verbose` | Show DEBUG-level detail on the console (finding details, affected objects) | off |

> **Interactive password prompt**: if neither `-p`, `--hash`, nor `--kerberos` is supplied, ADScan prompts for a password without echoing it to the terminal.

---

### Kerberos / assumed-breach authentication

ADScan supports Kerberos ticket reuse via a ccache file — the standard Linux credential store written by `kinit`, `getTGT.py`, and similar tools.  This is useful when:

- The target environment has **NTLM disabled** (common in hardened AD configurations).
- You are operating in an **assumed-breach** scenario and already hold a valid TGT or service ticket.
- You want to avoid transmitting cleartext passwords or NT hashes over the wire.

**Workflow using `KRB5CCNAME`**:

```bash
# Obtain a TGT with impacket
getTGT.py corp.local/alice:'P@ssw0rd!' -dc-ip 10.10.10.5
export KRB5CCNAME=$alice.ccache

# ADScan picks it up automatically
python adscan.py -d corp.local --dc-ip 10.10.10.5 -u alice --kerberos
```

**Using an explicit ccache path** (no environment variable needed):

```bash
python adscan.py -d corp.local --dc-ip 10.10.10.5 -u alice --ccache /tmp/alice.ccache
```

> **Note**: Kerberos authentication over LDAP requires the `gssapi` Python package
> (`pip install gssapi`) and a working `/etc/krb5.conf` pointing at your KDC.
> For SMB, impacket handles Kerberos natively with no extra dependencies beyond
> what is already in `requirements.txt`.

---

### Examples

```bash
# Password auth, all protocols
python adscan.py -d corp.local -u alice -p 'P@ssw0rd!' --dc-ip 10.10.10.5

# Interactive password prompt (no -p flag)
python adscan.py -d corp.local -u alice --dc-ip 10.10.10.5

# Pass-the-hash (NT only)
python adscan.py -d corp.local -u alice --hash aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c

# Kerberos ticket reuse (KRB5CCNAME set in the environment)
export KRB5CCNAME=/tmp/alice.ccache
python adscan.py -d corp.local -u alice --dc-ip 10.10.10.5 --kerberos

# Kerberos with an explicit ccache path
python adscan.py -d corp.local -u alice --dc-ip 10.10.10.5 --ccache /tmp/alice.ccache

# LDAPS only, custom output
python adscan.py -d corp.local -u alice -p 'Secret1' --protocol ldaps -o results/scan.html

# All output formats (HTML + JSON + CSV)
python adscan.py -d corp.local -u alice -p 'Secret1' --dc-ip 10.10.10.5 --format all

# Custom timeout
python adscan.py -d corp.local -u alice -p 'Secret1' --dc-ip 10.10.10.5 --timeout 60

# Write a persistent log file for post-engagement review
python adscan.py -d corp.local -u alice -p 'Secret1' --dc-ip 10.10.10.5 --log-file scan.log

# Verbose console output + full debug log file
python adscan.py -d corp.local -u alice -p 'Secret1' --dc-ip 10.10.10.5 -v --log-file debug.log
```

---

## Check Filtering

ADScan supports running targeted subsets of checks — useful for time-constrained engagements or when you only want to assess a specific attack surface.

### List available checks

```bash
python adscan.py --list-checks
```

Prints a formatted table of every check module with its slug, category, and display name:

```
ORDER  SLUG                                CATEGORY                  CHECK NAME
----------------------------------------------------------------------------------------------------
1      password_policy                     Account Hygiene           Domain Password Policy
2      account_hygiene                     Account Hygiene           Account Hygiene
3      kerberos                            Kerberos                  Kerberos Attack Surface
...
```

Slugs are matched against the module filename, the words in `CHECK_NAME`, and the `CHECK_CATEGORY` value — so `kerberos`, `attack`, and `surface` all match the Kerberos check.

### --checks: run only specific checks

```bash
# Run only Kerberos and delegation checks
python adscan.py -d corp.local --dc-ip 10.10.10.5 -u alice -p 'P@ss' --checks kerberos,delegation

# Run only ADCS-related checks
python adscan.py -d corp.local --dc-ip 10.10.10.5 -u alice -p 'P@ss' --checks adcs
```

### --skip: exclude specific checks

```bash
# Skip GPP and SMB checks (e.g. SMB is firewalled)
python adscan.py -d corp.local --dc-ip 10.10.10.5 -u alice -p 'P@ss' --skip gpp,smb

# Skip DNS and replication checks
python adscan.py -d corp.local --dc-ip 10.10.10.5 -u alice -p 'P@ss' --skip dns,replication
```

`--checks` and `--skip` can be combined: `--checks` restricts the candidate set first, then `--skip` removes from it.

---

## Scoring

ADScan starts each scan at a score of **100** and deducts points per finding based on its severity. The final score maps to a letter grade:

| Score | Grade |
|-------|-------|
| 90–100 | A |
| 75–89 | B |
| 60–74 | C |
| 40–59 | D |
| 0–39 | F |

### Default severity deductions

| Severity | Default Deduction |
|----------|-------------------|
| Critical | 20 pts |
| High | 15 pts |
| Medium | 8 pts |
| Low | 5 pts |
| Info | 0 pts |

### Customising the score with scoring.toml

Copy or edit `scoring.toml` (included in the repo) to tune deductions for your engagement without touching any check code.

**Change the severity curve** (affects all findings of that tier):

```toml
[severity_weights]
critical = 25
high     = 15
medium   = 5
low      = 2
info     = 0
```

**Override a single finding** (exact title match, takes precedence over severity weights):

```toml
[overrides]
# Raise impact — unconstrained delegation is critical in your environment
"User Accounts with Unconstrained Delegation" = 25

# Lower impact — compensating control is already in place
"Kerberoastable Service Accounts" = 3

# Suppress from score entirely (finding still appears in the report)
"Lockout Observation Window Too Short" = 0
```

Pass a custom config at runtime with `--scoring-config`:

```bash
python adscan.py -d corp.local --dc-ip 10.10.10.5 -u alice -p 'P@ss' --scoring-config my_scoring.toml
```

---

## Disclaimer

ADScan is intended for authorised security assessments only. Always obtain written permission before scanning an Active Directory environment. Unauthorised use may violate computer crime laws.
