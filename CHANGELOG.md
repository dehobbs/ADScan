# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

_Nothing yet._

## [1.3.3] — 2026-06-18

### Added

- **Generic check preflight hook**: a check module may now define an optional
  `preflight(connector)` function. `adscan.run_preflight()` invokes every loaded
  check's hook (in `CHECK_ORDER`) before the scan loop, so interactive setup
  happens up front and the scan then runs unattended. A hook that raises is
  logged and skipped so it cannot abort the scan. Covered by unit tests.

### Changed

- **BloodHound engine prompt moved to the start of the run.** The Legacy vs
  Community Edition question is now asked up front via `check_bloodhound`'s
  `preflight()` hook instead of mid-scan when the collection step is reached.
  The operator answers once and can walk away; data collection still runs last
  (`CHECK_ORDER 99`) — only the prompt moved. The prompt is skipped entirely
  when BloodHound is excluded via `--checks`/`--skip`, and non-interactive
  sessions still default to Legacy.

## [1.3.2] — 2026-06-09

### Added

- New check **Fine-Grained Password Policies (PSO)**
  (`check_fine_grained_password_policy.py`): enumerates every
  `msDS-PasswordSettings` object and flags any PSO whose settings are weaker than
  recommended (lockout, length, complexity, expiry, reversible encryption). A
  weak PSO linked to a privileged principal is escalated to at least High. The
  Default Domain Password Policy check does not see PSO-based exemptions. Ships a
  verification/remediation module and unit tests.
- New check **Print Spooler Service on Domain Controllers**
  (`check_print_spooler.py`): uses the NetExec `spooler` module to detect the
  Print Spooler (MS-RPRN) running on each DC — the PrinterBug / SpoolSample
  coercion primitive that chains into ESC8 / RBCD / unconstrained-delegation
  relay. Enumerates DCs via LDAP, forwards ADScan's DNS overrides to `nxc`, and
  ships a verification/remediation module and unit tests.
- New check **WebClient (WebDAV) Coercion Surface**
  (`check_webclient_webdav.py`): sweeps domain computers with the NetExec
  `webdav` module to find hosts running the WebClient service — the HTTP
  coercion primitive whose unsigned authentication can be relayed to AD CS Web
  Enrollment (ESC8) or LDAP (RBCD). Enumerates computers via LDAP (same two-phase
  pattern as the SMB signing check), flags enabled hosts as High, and ships a
  verification/remediation module and unit tests.
- **First unit test suite** (`tests/`, with a root `conftest.py`) covering the
  three checks above.

## [1.3.1] — 2026-05-29

### Security

- **Plaintext-password leak in the redacted customer report — fixed.** The "Passwords Found in Privileged Account Description Fields" finding in `check_privileged_accounts.py` was populating `details` with `<sam>: <description>` strings where the description body is the leaked credential, but it never set a matching `details_redacted`. `lib/report.py:_get_details(redact=True)` fell through to the unredacted list, so plaintext passwords appeared in the default (non-`--unredacted`) report. The finding now provides both `details` (operator) and `details_redacted` (customer). All other checks that handle credential material were audited; only this one was leaking.

### Changed

- **`--timeout` moved from the Output argparse group to the Target group.** It is a connection-level setting like `--protocol`, `--dns-server`, and `--dns-tcp`, so its `--help` listing now appears alongside those flags instead of next to report-path and log-file options. Functional behaviour is unchanged.

### Docs

- **CLI Reference completeness pass.** Four flags that existed in `adscan.py` but were missing from the README's CLI Reference tables are now listed: `--dns-server` / `-ns`, `--dns-tcp`, `--unredacted`, and `-V` / `--version`. The `--timeout` row was also tightened to mention its dual role as the LDAP receive-timeout used by the stall detector.
- **`docs/REFERENCE.md` refreshed** to cover the krb5.conf synthesis helper, the Kerberos FQDN/SPN routing helper, the `_install_dns_resolver` DNS-patch hook, the `receive_timeout` stall detector, the `_bootstrap_uv` setup helper, the spinner `pause`/`resume`/`suspended` API, and the BloodHound engine selector.

## [1.3.0] — 2026-05-29

### Added

- **`--dns-server` CLI flag** (short alias `-ns`) routes every DNS lookup ADScan triggers — in-process ldap3 and impacket hostname binds, SRV lookups for the DC FQDN — through a resolver of your choice. The flag is also forwarded to every external tool ADScan runs (`nxc`, `certipy-ad`, `bloodhound-python`, `bloodhound-ce-python`). Typical value: the DC's own IP.
- **`--dns-tcp` CLI flag** forces DNS queries over TCP/53 for environments where UDP/53 is blocked or unreliable. Applies to in-process dnspython lookups and is forwarded to the same set of external tools.
- **`--version` / `-V` flag** prints the ADScan version and exits. A module-level `__version__` constant is the single source of truth; the startup banner reads the same value so they cannot drift.
- **Per-check elapsed-time logging.** When a check takes 5 seconds or more, its wall-clock duration is printed on the following line. Makes long stalls visible at the moment they happen.

### Changed

- **LDAP stall detector.** Every `ldap3.Connection(...)` instance now sets `receive_timeout=self.timeout`. This is a socket-level wait that resets whenever the server sends data, so legitimately slow but progressing searches continue while a server that has gone silent gets caught quickly. Unlike a wall-clock cap, this does not interrupt large paged searches that are making steady progress.

### Fixed

- **DNS Infrastructure check stall.** The wildcard DNS search filter was `(dc=*)`, which the directory interprets as "any node that has a `dc` attribute set" — i.e. every DNS record in the DomainDnsZones partition. The check then post-filtered in Python for `dc == "*"`, so on large enterprise zones the LDAP layer streamed tens of thousands of records back only to throw 99.99% of them away (and could take 10+ minutes). The filter is now properly escaped as `(dc=\2A)` so the server returns only the literal-wildcard records.

## [1.2.0] — 2026-05-04

### Added

- **One-line install via pipx.** `pipx install git+https://github.com/dehobbs/ADScan.git && adscan --setup-tools` installs ADScan into an isolated pipx venv and provisions every external CLI tool into its own isolated venv. `--setup-tools` bootstraps `uv` itself when it is not already on `PATH`, so the operator host needs only `python3` and `pipx` to begin with.
- **BloodHound engine selector.** When the BloodHound step starts, the operator is prompted to choose between Legacy BloodHound (`bloodhound-python`) and BloodHound Community Edition (`bloodhound-ce-python`). Both ingestors install via `uv tool install`. Non-interactive sessions default to Legacy. The spinner suspends itself for the duration of the prompt so the question is never overwritten.
- **NetExec `adcs` module phase** added to the ADCS check. Runs alongside Certipy; Certipy retains priority for any ESC class it reports, NetExec fills in the gaps. The legacy LDAP-only ADCS checks are muted by default.
- **Comprehensive developer reference** at `docs/REFERENCE.md`.

### Changed

- **Pre-Windows 2000 computer-accounts check rewritten** to use the NetExec `pre2k` LDAP module instead of the standalone `pre2k` binary. The standalone tool was removed from `TOOL_REGISTRY` in `lib/tools.py`.
- **Spinner is suspended for interactive prompts.** Any check that needs to prompt the operator (e.g. the BloodHound engine selector) reads `connector.spinner` and wraps its `input()` call in `sp.suspended()` so the spinner clears its line and stops drawing until the user has chosen.

### Fixed

- **Kerberos against arbitrary lab DCs.** ADScan now synthesizes a usable `krb5.conf` on the fly when the host system has none or omits a `default_realm`. When `--dc-ip` is an IP, the DC FQDN is resolved via SRV and `socket.getaddrinfo` is monkey-patched so the FQDN routes to the original IP. GSSAPI builds the correct service principal name (`ldap/<fqdn>`, `cifs/<fqdn>`) instead of failing with `KDC_ERR_S_PRINCIPAL_UNKNOWN`. Both ldap3 and impacket TCP connections still go to the right address.
- **Verification key disambiguation** between `verify_pre2k.py` and `verify_pre_windows_2000.py` so each check's findings route to the correct verification module regardless of import order.

[Unreleased]: https://github.com/dehobbs/ADScan/compare/v1.3.2...HEAD
[1.3.2]: https://github.com/dehobbs/ADScan/releases/tag/v1.3.2
[1.3.1]: https://github.com/dehobbs/ADScan/releases/tag/v1.3.1
[1.3.0]: https://github.com/dehobbs/ADScan/releases/tag/v1.3.0
[1.2.0]: https://github.com/dehobbs/ADScan/releases/tag/v1.2.0
