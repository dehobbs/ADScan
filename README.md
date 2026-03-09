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
git clone https://github.com/BrocktonPointSolutions/ADScan.git
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

## Check Modules

All checks live in `checks/check_*.py` and are loaded automatically.

| # | Module | Category | Key Checks | Max Deduction |
|---|--------|----------|------------|--------------|
| 1 | `check_password_policy.py` | Password Policy | Min length, complexity, lockout, reversible encryption, max age | 30 |
| 2 | `check_unconstrained_delegation.py` | Delegation | Unconstrained delegation on non-DC computers/users | 20 |
| 3 | `check_constrained_delegation.py` | Delegation | Constrained delegation (S4U2Proxy), protocol transition | 15 |
| 4 | `check_privileged_accounts.py` | Privileged Accounts | DA/EA/SA membership, stale members, non-expiring passwords, descriptions, built-in Admin, krbtgt age | 40 |
| 5 | `check_kerberos.py` | Kerberos | Kerberoastable accounts, AS-REP roasting, DES-only, high-value combos | 45 |
| 6 | `check_adcs.py` | ADCS / PKI | ESC1–ESC3, ESC6, ESC8–ESC11, ESC13, ESC15–ESC16, weak key sizes, enrollee ACLs | 80 |
| 7 | `check_domain_trusts.py` | Domain Trusts | Bidirectional trusts without SID filtering, forest trusts, external trusts | 30 |
| 8 | `check_account_hygiene.py` | Account Hygiene | Stale users/computers, never-logged-in, PASSWD_NOTREQD, reversible encryption, old passwords, duplicate SPNs | 45 |
| 9 | `check_protocol_security.py` | Protocol Security | LDAP signing/channel binding, DC OS versions, domain/forest functional level, NTLMv1/WDigest guidance | 30 |
| 10 | `check_gpo.py` | Group Policy | Disabled, orphaned, unlinked, empty GPOs; excessive GPO count | 20 |
| 11 | `check_laps.py` | LAPS | Legacy LAPS & Windows LAPS schema detection, computers without LAPS passwords, LAPS coverage % | 25 |
| 12 | `check_dns_infrastructure.py` | DNS & Infrastructure | Wildcard DNS records, LLMNR/NetBIOS-NS guidance, AD Sites & Services subnets | 20 |
| 13 | `check_domain_controllers.py` | Domain Controllers | Single-DC detection, legacy OS on DCs, FSMO roles, RODC password replication, DC owners | 30 |
| 14 | `check_acl_permissions.py` | ACL / Permissions | ESC4, ESC5, ESC7, DCSync rights, Protected Users group, RBCD delegation ACLs | 70 |
| 15 | `check_optional_features.py` | Optional Features | AD Recycle Bin, Privileged Access Management (PAM) | 15 |
| 16 | `check_replication.py` | Replication Health | Site count, site link intervals, nTDSDSA objects, empty sites | 15 |
| 17 | `check_service_accounts.py` | Service Accounts | gMSA adoption, user accounts as service accounts, service accounts with adminCount=1 | 25 |
| 18 | `check_misc_hardening.py` | Miscellaneous Hardening | Machine account quota, tombstone lifetime, Guest account, Schema/EA membership, audit guidance | 46 |
| 19 | `check_deprecated_os.py` | Deprecated OS | EOL workstations (XP/Vista/7/8/8.1), EOL servers (2003/2008/2008R2), near-EOL (2012/2012R2) | 55 |
| 20 | `check_legacy_protocols.py` | Legacy Protocols | SMBv1 detection, SMB signing guidance, null session guidance, NTLMv1/WDigest guidance | 25 |

---

## Scoring

| Score | Grade | Meaning |
|-------|-------|---------|
| 90–100 | **A** | Excellent — minimal findings |
| 75–89 | **B** | Good — some improvements needed |
| 60–74 | **C** | Fair — notable security gaps |
| 40–59 | **D** | Poor — significant vulnerabilities present |
| 0–39 | **F** | Critical — immediate remediation required |

Deductions are applied per finding. The score cannot go below 0.

---

## Adding a New Check

1. Create `checks/check_<name>.py`
2. Define the required interface:

```python
CHECK_NAME = "Human Readable Name"   # displayed in report
CHECK_ORDER = 99                     # run order (lower = earlier)

def run_check(connector, verbose=False):
    findings = []
    # Use connector.ldap_search() for all LDAP queries
    findings.append({
        "title": "Finding title",
        "severity": "critical|high|medium|low|info",
        "deduction": 10,        # points deducted from score
        "description": "...",
        "recommendation": "...",
        "details": ["list", "of", "affected", "objects"],
    })
    return findings
```

3. Run `adscan.py` — the check is auto-discovered. No registration required.

### Connector API

```python
# LDAP search
results = connector.ldap_search(
    base_dn,            # e.g. connector.base_dn
    ldap_filter,        # e.g. "(objectClass=user)"
    attributes,         # list of attribute names
    scope="SUBTREE",    # SUBTREE | ONELEVEL | BASE
)
# Returns list of dicts, or [] on error / no results

# Useful properties
connector.base_dn          # e.g. "DC=corp,DC=local"
connector.smb_conn         # impacket SMB connection (may be None)
```

---

## Report

The HTML report (`adscan_report.html` by default) is fully self-contained — no CDN or internet connection required. It includes:

- **Score gauge** with letter grade and colour coding
- **Severity summary** chips (Critical / High / Medium / Low / Info)
- **Collapsible finding cards** — each with title, severity badge, deduction, description, recommendation, and affected-object list
- **Light / dark mode toggle** (preference persisted via `localStorage`)

---

## Architecture

```
ADScan/
├── adscan.py              # CLI entry point, orchestrates checks and report
├── requirements.txt
├── lib/
│   ├── __init__.py
│   ├── connector.py       # LDAP / LDAPS / SMB connection management
│   └── report.py          # HTML report generation
└── checks/
    ├── __init__.py        # Auto-discovery loader
    ├── check_password_policy.py
    ├── check_unconstrained_delegation.py
    ├── check_constrained_delegation.py
    ├── check_privileged_accounts.py
    ├── check_kerberos.py
    ├── check_adcs.py
    ├── check_domain_trusts.py
    ├── check_account_hygiene.py
    ├── check_protocol_security.py
    ├── check_gpo.py
    ├── check_laps.py
    ├── check_dns_infrastructure.py
    ├── check_domain_controllers.py
    ├── check_acl_permissions.py
    ├── check_optional_features.py
    ├── check_replication.py
    ├── check_service_accounts.py
    ├── check_misc_hardening.py
    ├── check_deprecated_os.py
    └── check_legacy_protocols.py
```

---

## Disclaimer

ADScan is intended for authorised security assessments only. Always obtain written permission before scanning an Active Directory environment. Unauthorised use may violate computer crime laws.
