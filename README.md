# ADScan

**Active Directory Vulnerability Scanner** — a modular, Python-based tool that connects to domain controllers via LDAP, LDAPS, and/or SMB, runs a comprehensive battery of security checks, and produces a self-contained HTML dashboard report with a risk score.

---

## Features

- **Multi-protocol**: LDAP, LDAPS, SMB (user-selectable; defaults to all three)
- **Flexible auth**: password or pass-the-hash (NTLM `LM:NT` or `NT` only)
- **Risk score**: starts at 100, deducted per finding (floor 0), letter grade A–F
- **HTML report**: fully self-contained, light/dark mode toggle, severity chips, collapsible finding cards
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
python adscan.py -d <domain> -u <username> -p <password> [options]
python adscan.py -d <domain> -u <username> --hash <LM:NT or NT> [options]
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-d / --domain` | Target domain FQDN (e.g. `corp.local`) | required |
| `-u / --user` | Username | required |
| `-p / --password` | Password | — |
| `--hash` | NTLM hash (`LM:NT` or `NT`) | — |
| `--dc` | Domain controller IP/hostname | auto-resolved |
| `--protocol` | `ldap` \| `ldaps` \| `smb` \| `all` | `all` |
| `-o / --output` | Output HTML file path | `adscan_report.html` |
| `-v / --verbose` | Verbose console output | off |

### Examples

```bash
# Password auth, all protocols
python adscan.py -d corp.local -u alice -p 'P@ssw0rd!' --dc 10.10.10.5

# Pass-the-hash (NT only)
python adscan.py -d corp.local -u alice --hash aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c

# LDAPS only, custom output
python adscan.py -d corp.local -u alice -p 'Secret1' --protocol ldaps -o results/scan.html
```

---

---

## Disclaimer

ADScan is intended for authorised security assessments only. Always obtain written permission before scanning an Active Directory environment. Unauthorised use may violate computer crime laws.
