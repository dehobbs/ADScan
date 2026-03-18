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
export KRB5CCNAME=$(pwd)/alice.ccache

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

## Disclaimer

ADScan is intended for authorised security assessments only. Always obtain written permission before scanning an Active Directory environment. Unauthorised use may violate computer crime laws.
