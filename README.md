# ADScan

**Active Directory Vulnerability Scanner** — a modular, Python-based tool that connects to domain controllers via LDAP, LDAPS, and/or SMB, runs a comprehensive battery of security checks, and produces a self-contained HTML dashboard report with a risk score.

---

## Features

- **Multi-protocol**: LDAP, LDAPS, SMB (user-selectable; defaults to all three)
- **Flexible auth**: password, pass-the-hash (NTLM `LM:NT` or `NT`), or interactive prompt
- **Risk score**: starts at 100, deducted per finding (floor 0), letter grade A–F
- **HTML report**: fully self-contained, light/dark mode toggle, severity chips, collapsible finding cards
- **JSON / CSV output**: machine-readable exports alongside the HTML report
- **Modular**: drop a new `check_*.py` file in `checks/` — it's auto-discovered at runtime
- **21 check categories** covering the most critical AD attack surfaces

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
| `impacket` | SMB connectivity, pass-the-hash |
| `pyOpenSSL` | LDAPS certificate handling |

---

## Usage

```
python adscan.py -d <domain> --dc-ip <dc_ip> -u <username> -p <password> [options]
python adscan.py -d <domain> --dc-ip <dc_ip> -u <username> --hash <LM:NT or NT> [options]
python adscan.py -d <domain> --dc-ip <dc_ip> -u <username>              # prompts for password
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-d / --domain` | Target domain FQDN (e.g. `corp.local`) | required |
| `--dc-ip` | Domain controller IP or hostname | required |
| `-u / --username` | Username | required |
| `-p / --password` | Password (omit to be prompted securely) | — |
| `--hash` | NTLM hash (`LM:NT` or `NT`) | — |
| `--protocol` | `ldap` \| `ldaps` \| `smb` \| `all` | `all` |
| `--timeout` | Connection timeout in seconds | `30` |
| `--format` | `html` \| `json` \| `csv` \| `all` | `html` |
| `--log-file PATH` | Write all log output (including DEBUG detail) to a file in addition to the console | off |
| `-o / --output` | Output report path stem | `Reports/adscan_report_<timestamp>` |
| `-v / --verbose` | Show DEBUG-level detail on the console (finding details, affected objects) | off |

> **Interactive password prompt**: if neither `-p` nor `--hash` is supplied, ADScan will prompt for a password without echoing it to the terminal. This avoids storing credentials in shell history.

### Examples

```bash
# Password auth, all protocols
python adscan.py -d corp.local -u alice -p 'P@ssw0rd!' --dc-ip 10.10.10.5

# Interactive password prompt (no -p flag)
python adscan.py -d corp.local -u alice --dc-ip 10.10.10.5

# Pass-the-hash (NT only)
python adscan.py -d corp.local -u alice --hash aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c

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
