""" checks/check_smb_signing.py -- SMB Signing Enforcement & SMBv1 Detection

Two-phase approach:

Phase 1 -- LDAP computer export (ldapsearch)
    ldapsearch -x -H ldap://<dc> -D "<user>@<domain>" -w "<pass>"
              -b "<base_dn>" "(objectClass=computer)" dNSHostName cn
    Parses dNSHostName (preferred) or cn attributes to build a target list
    and writes one hostname per line to:
        Reports/Artifacts/computers.txt

Phase 2 -- SMB sweep (NetExec)
    nxc smb Reports/Artifacts/computers.txt -u <user> -p <pass> [-H <hash>]
    Parses each output line for:
        (signing:False)  -> hosts that do NOT require SMB message signing
        (SMBv1:True)     -> hosts that still support the deprecated SMBv1 protocol

Findings (from Phase 2 output):
    SMB Signing:
        Any signing:False  -> HIGH finding, -15 points
        All signing:True   -> INFO / PASS finding, 0 points
    SMBv1:
        Any SMBv1:True     -> HIGH finding, -15 points
        All SMBv1:False    -> INFO / PASS finding, 0 points

Prerequisites:
    ldapsearch  (usually provided by the ldap-utils / openldap-clients package)
    nxc         (pip install netexec  or  pipx install netexec)

    If either tool is missing the check emits an informational finding
    (no deduction) with install instructions rather than raising an error.
"""

import os
import re
import shutil
import subprocess

CHECK_NAME     = "SMB Signing Enforcement"
CHECK_ORDER    = 22          # runs right after Legacy Protocols (21)
CHECK_CATEGORY = ["Protocol Security"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ldapsearch_available():
    return shutil.which("ldapsearch") is not None


def _nxc_available():
    return shutil.which("nxc") is not None


def _domain_to_base_dn(domain):
    """Convert 'corp.example.com' -> 'DC=corp,DC=example,DC=com'."""
    if not domain:
        return ""
    return ",".join(f"DC={part}" for part in domain.split("."))


def _run_cmd(cmd, timeout=120):
    """Run a subprocess command, return (returncode, stdout, stderr)."""
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return result.returncode, result.stdout, result.stderr


def _build_ldapsearch_cmd(connector):
    """
    Build the ldapsearch command list for querying computer objects.

    ldapsearch -x -H ldap://<dc> -D "<user>@<domain>" -w "<pass>"
               -b "<base_dn>" "(objectClass=computer)" dNSHostName cn
    """
    dc_host  = getattr(connector, "dc_host",  None) or getattr(connector, "server", None)
    domain   = getattr(connector, "domain",   "")
    username = getattr(connector, "username", None) or ""
    password = getattr(connector, "password", None) or ""

    base_dn = _domain_to_base_dn(domain)

    # Build bind DN: if username already contains '@' or '\' use as-is,
    # otherwise append @domain so ldapsearch gets a valid UPN.
    if domain and "@" not in username and "\\" not in username:
        bind_dn = f"{username}@{domain}"
    else:
        bind_dn = username

    cmd = [
        "ldapsearch",
        "-x",                          # simple auth (not SASL)
        "-H", f"ldap://{dc_host}",     # LDAP URI
        "-D", bind_dn,                 # bind DN / UPN
        "-w", password,                # password
        "-b", base_dn,                 # search base
        "(objectClass=computer)",      # filter
        "dNSHostName", "cn",           # requested attributes
    ]
    return cmd


def _parse_ldapsearch_computers(ldap_output):
    """
    Parse ldapsearch LDIF output and return a list of unique hostnames.

    Preference order per entry:
      1. dNSHostName  (fully-qualified, e.g. 'WS01.corp.example.com')
      2. cn           (short name, e.g. 'WS01')

    Lines of interest look like:
      dNSHostName: WS01.corp.example.com
      cn: WS01
    """
    targets = []
    seen    = set()

    # Split into LDIF entries (blank line separates entries)
    entries = re.split(r'\n\n+', ldap_output)

    dns_re = re.compile(r'^dNSHostName:\s+(\S+)', re.IGNORECASE | re.MULTILINE)
    cn_re  = re.compile(r'^cn:\s+(\S+)',          re.IGNORECASE | re.MULTILINE)

    for entry in entries:
        host = None
        m = dns_re.search(entry)
        if m:
            host = m.group(1).strip()
        else:
            m2 = cn_re.search(entry)
            if m2:
                host = m2.group(1).strip()

        if host and host not in seen:
            seen.add(host)
            targets.append(host)

    return targets


def _build_nxc_smb_auth_args(connector):
    """Return the nxc SMB authentication arguments as a list."""
    username = getattr(connector, "username", None)
    password = getattr(connector, "password", None)
    nt_hash  = getattr(connector, "nt_hash",  None)
    lm_hash  = getattr(connector, "lm_hash",  "") or ""
    domain   = getattr(connector, "domain",   "")

    args = ["-u", username or ""]
    if nt_hash:
        args += ["-H", f"{lm_hash}:{nt_hash}" if lm_hash else nt_hash]
    elif password:
        args += ["-p", password]
    else:
        args += ["-p", ""]
    if domain:
        args += ["-d", domain]
    return args


def _parse_smb_results(nxc_output):
    """
    Parse 'nxc smb' output and return three lists:
        (unsigned_hosts, signed_hosts, smbv1_hosts)

    NetExec SMB output format:
      SMB <ip> 445 <hostname> [*] Windows ... (name:<host>) (domain:<dom>)
                                              (signing:True/False) (SMBv1:True/False)

    A host is added to smbv1_hosts if SMBv1:True appears on its line,
    regardless of its signing status (the two findings are independent).
    """
    unsigned = []
    signed   = []
    smbv1    = []

    line_re = re.compile(
        r'^SMB\s+(\S+)\s+\d+\s+(\S+)'
        r'.*?\(signing:(True|False)\)'
        r'.*?\(SMBv1:(True|False)\)',
        re.IGNORECASE,
    )

    for line in nxc_output.splitlines():
        m = line_re.search(line)
        if m:
            ip          = m.group(1)
            hostname    = m.group(2)
            signing_val = m.group(3)
            smbv1_val   = m.group(4)
            label = f"{hostname} ({ip})" if hostname != ip else ip

            if signing_val.lower() == "false":
                unsigned.append(label)
            else:
                signed.append(label)

            if smbv1_val.lower() == "true":
                smbv1.append(label)

    return unsigned, signed, smbv1


# ---------------------------------------------------------------------------
# Main check entry point
# ---------------------------------------------------------------------------

def run_check(connector, verbose=False):
    findings = []

    # ---------------------------------------------------------------------- #
    # Pre-flight: check required tools                                        #
    # ---------------------------------------------------------------------- #
    if not _ldapsearch_available():
        findings.append({
            "title":       "SMB Signing Enforcement -- ldapsearch Not Found",
            "severity":    "info",
            "deduction":   0,
            "description": (
                "ldapsearch is required for Phase 1 (computer enumeration) "
                "but was not found on PATH. "
                "Install with: sudo apt install ldap-utils  "
                "(Debian/Ubuntu) or sudo yum install openldap-clients (RHEL/CentOS)."
            ),
            "recommendation": (
                "Install ldap-utils / openldap-clients and re-run ADScan."
            ),
            "details": [
                "ldapsearch not found on PATH.",
                "Debian/Ubuntu: sudo apt install ldap-utils",
                "RHEL/CentOS:   sudo yum install openldap-clients",
            ],
        })
        return findings

    if not _nxc_available():
        findings.append({
            "title":       "SMB Signing Enforcement -- NetExec Not Found",
            "severity":    "info",
            "deduction":   0,
            "description": (
                "NetExec (nxc) is required for Phase 2 (SMB sweep) "
                "but was not found on PATH. "
                "Install with: pip install netexec"
            ),
            "recommendation": (
                "Install NetExec and re-run ADScan to get automated "
                "per-host SMB signing and SMBv1 results."
            ),
            "details": [
                "nxc not found on PATH.",
                "Install with: pip install netexec",
                "Or: pipx install netexec",
            ],
        })
        return findings

    # ---------------------------------------------------------------------- #
    # Gather connection info from connector                                   #
    # ---------------------------------------------------------------------- #
    dc_host       = getattr(connector, "dc_host",      None) or getattr(connector, "server", None)
    artifacts_dir = getattr(connector, "artifacts_dir", "Reports/Artifacts")
    dbg           = getattr(connector, "debug_log",    None)

    if not dc_host:
        findings.append({
            "title":          "SMB Signing Enforcement -- No DC Host Available",
            "severity":       "info",
            "deduction":      0,
            "description":    "Could not determine the Domain Controller address from the connector.",
            "recommendation": "Ensure the connector is initialised with a valid dc_host.",
            "details":        ["dc_host not available on connector object."],
        })
        return findings

    os.makedirs(artifacts_dir, exist_ok=True)
    targets_file = os.path.join(artifacts_dir, "computers.txt")

    # ---------------------------------------------------------------------- #
    # Phase 1: Computer enumeration via ldapsearch                           #
    # ---------------------------------------------------------------------- #
    ldap_cmd = _build_ldapsearch_cmd(connector)

    if verbose:
        # Redact password in display
        display_cmd = list(ldap_cmd)
        try:
            pw_idx = display_cmd.index("-w")
            display_cmd[pw_idx + 1] = "***"
        except ValueError:
            pass
        print(f"  [SMB] Phase 1: enumerating computers via ldapsearch ...")
        print(f"  Command: {' '.join(display_cmd)}")

    try:
        rc1, out1, err1 = _run_cmd(ldap_cmd, timeout=120)
    except subprocess.TimeoutExpired:
        findings.append({
            "title":          "SMB Signing Enforcement -- LDAP Export Timed Out",
            "severity":       "medium",
            "deduction":      0,
            "description":    "ldapsearch computer enumeration timed out after 120 seconds.",
            "recommendation": "Check network connectivity to the Domain Controller.",
            "details":        ["ldapsearch timed out after 120 s."],
        })
        return findings
    except Exception as e:
        findings.append({
            "title":          "SMB Signing Enforcement -- LDAP Export Failed",
            "severity":       "info",
            "deduction":      0,
            "description":    f"ldapsearch raised an exception: {e}",
            "recommendation": "Verify ldapsearch is installed and credentials are valid.",
            "details":        [str(e)],
        })
        return findings

    if dbg:
        dbg.log_subprocess(
            cmd=ldap_cmd,
            cwd=None,
            returncode=rc1,
            stdout=out1,
            stderr=err1,
        )

    if verbose and out1:
        print(f"  [SMB] ldapsearch output (first 20 lines):")
        for line in out1.splitlines()[:20]:
            print(f"    {line}")

    targets = _parse_ldapsearch_computers(out1)

    if not targets:
        findings.append({
            "title":    "SMB Signing Enforcement -- No Computers Found via LDAP",
            "severity": "info",
            "deduction": 0,
            "description": (
                "ldapsearch returned no parseable computer entries. "
                "Check that credentials have LDAP read access and that "
                "the base DN is correct."
            ),
            "recommendation": "Verify LDAP credentials and domain connectivity.",
            "details": [f"ldapsearch exit code: {rc1}"] + out1.splitlines()[:10],
        })
        return findings

    # Write one hostname per line to computers.txt
    with open(targets_file, "w", encoding="utf-8") as fh:
        fh.write("\n".join(targets) + "\n")

    if verbose:
        print(f"  [SMB] Found {len(targets)} computer(s).")
        print(f"  Computer list saved to: {targets_file}")

    # ---------------------------------------------------------------------- #
    # Phase 2: SMB sweep via NetExec (signing + SMBv1)                      #
    # ---------------------------------------------------------------------- #
    smb_auth = _build_nxc_smb_auth_args(connector)
    smb_cmd  = ["nxc", "smb", targets_file] + smb_auth

    if verbose:
        print(f"  [SMB] Phase 2: sweeping {len(targets)} host(s) for signing and SMBv1 ...")
        print(f"  Command: {' '.join(smb_cmd)}")

    try:
        rc2, out2, err2 = _run_cmd(smb_cmd, timeout=300)
    except subprocess.TimeoutExpired:
        findings.append({
            "title":          "SMB Signing Enforcement -- SMB Sweep Timed Out",
            "severity":       "medium",
            "deduction":      0,
            "description":    "NetExec SMB sweep timed out after 300 seconds.",
            "recommendation": "Check network connectivity or reduce the number of targets.",
            "details":        ["nxc smb sweep timed out."],
        })
        return findings
    except Exception as e:
        findings.append({
            "title":          "SMB Signing Enforcement -- SMB Sweep Failed",
            "severity":       "info",
            "deduction":      0,
            "description":    f"nxc smb sweep raised an exception: {e}",
            "recommendation": "Verify nxc is installed and credentials are valid.",
            "details":        [str(e)],
        })
        return findings

    if dbg:
        dbg.log_subprocess(
            cmd=smb_cmd,
            cwd=None,
            returncode=rc2,
            stdout=out2,
            stderr=err2,
        )

    if verbose and out2:
        print(f"  [SMB] nxc smb output (first 30 lines):")
        for line in out2.splitlines()[:30]:
            print(f"    {line}")

    unsigned_hosts, signed_hosts, smbv1_hosts = _parse_smb_results(out2)

    total_scanned = len(unsigned_hosts) + len(signed_hosts)

    # ---------------------------------------------------------------------- #
    # Finding 1: SMB Signing                                                 #
    # ---------------------------------------------------------------------- #
    if unsigned_hosts:
        detail_lines = [
            f"Computer list: {targets_file}",
            f"Scanned: {total_scanned} host(s) | Unsigned: {len(unsigned_hosts)} | Signed: {len(signed_hosts)}",
            "",
            "Hosts with SMB signing NOT enforced (signing:False):",
        ] + [f"  {h}" for h in sorted(unsigned_hosts)]

        findings.append({
            "title": (
                f"SMB Signing Not Enforced: {len(unsigned_hosts)} host(s) vulnerable"
            ),
            "severity":  "high",
            "deduction": 15,
            "description": (
                f"{len(unsigned_hosts)} of {total_scanned} scanned host(s) do not require "
                "SMB message signing. Without signing, NTLM relay attacks "
                "(e.g. Responder + ntlmrelayx) can be used to authenticate to "
                "these systems as any user whose credentials are captured."
            ),
            "recommendation": (
                "Enable and require SMB signing on all systems via GPO: "
                "Computer Configuration > Windows Settings > Security Settings > "
                "Local Policies > Security Options > "
                "Microsoft network server: Digitally sign communications (always) = Enabled. "
                "Also set the client-side policy: "
                "Microsoft network client: Digitally sign communications (always) = Enabled."
            ),
            "affected_count": len(unsigned_hosts),
            "details": detail_lines,
        })

    elif total_scanned > 0:
        findings.append({
            "title":    "SMB Signing Enforced on All Scanned Hosts",
            "severity": "info",
            "deduction": 0,
            "description": (
                f"All {total_scanned} scanned host(s) require SMB message signing. "
                "NTLM relay attacks via SMB are not possible on these systems."
            ),
            "recommendation": "Continue enforcing SMB signing via GPO for all new systems.",
            "details": [
                f"Computer list: {targets_file}",
                f"Scanned: {total_scanned} host(s) | All have signing:True",
            ],
        })

    else:
        # nxc ran but produced no parseable SMB lines
        findings.append({
            "title":    "SMB Signing Enforcement -- No SMB Results Parsed",
            "severity": "info",
            "deduction": 0,
            "description": (
                "nxc smb completed but no SMB status lines were parsed. "
                "The hosts may be unreachable or the output format may have changed."
            ),
            "recommendation": (
                "Review the debug log for raw nxc smb output. "
                f"Computer list: {targets_file}"
            ),
            "details": (
                [f"nxc smb exit code: {rc2}"]
                + out2.splitlines()[:20]
            ),
        })

    # ---------------------------------------------------------------------- #
    # Finding 2: SMBv1                                                       #
    # ---------------------------------------------------------------------- #
    if smbv1_hosts:
        smbv1_detail_lines = [
            f"Computer list: {targets_file}",
            f"Scanned: {total_scanned} host(s) | SMBv1 enabled: {len(smbv1_hosts)}",
            "",
            "Hosts with SMBv1 enabled (SMBv1:True):",
        ] + [f"  {h}" for h in sorted(smbv1_hosts)]

        findings.append({
            "title": f"SMBv1 Enabled: {len(smbv1_hosts)} host(s) vulnerable",
            "severity":  "high",
            "deduction": 15,
            "description": (
                f"{len(smbv1_hosts)} of {total_scanned} scanned host(s) still support "
                "SMB version 1 (SMBv1). SMBv1 is a deprecated protocol with known "
                "critical vulnerabilities including EternalBlue (MS17-010) which was "
                "exploited by WannaCry and NotPetya ransomware. SMBv1 should be "
                "disabled on all systems."
            ),
            "recommendation": (
                "Disable SMBv1 via PowerShell: "
                "Set-SmbServerConfiguration -EnableSMB1Protocol $false. "
                "Also disable via GPO: "
                "Computer Configuration > Administrative Templates > "
                "MS Security Guide > Configure SMBv1 Server = Disabled. "
                "Verify with: Get-SmbServerConfiguration | Select EnableSMB1Protocol."
            ),
            "affected_count": len(smbv1_hosts),
            "details": smbv1_detail_lines,
        })

    elif total_scanned > 0:
        findings.append({
            "title":    "SMBv1 Disabled on All Scanned Hosts",
            "severity": "info",
            "deduction": 0,
            "description": (
                f"All {total_scanned} scanned host(s) have SMBv1 disabled. "
                "These systems are not vulnerable to EternalBlue and similar SMBv1 exploits."
            ),
            "recommendation": "Continue enforcing SMBv1 disabled via GPO for all new systems.",
            "details": [
                f"Computer list: {targets_file}",
                f"Scanned: {total_scanned} host(s) | All have SMBv1:False",
            ],
        })

    return findings
