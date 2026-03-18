r""" checks/check_audit_policy.py -- Advanced Audit Policy Check

Enumerates all GPOs in the domain via LDAP (objectClass=groupPolicyContainer),
then for each GPO reads the following file from SYSVOL via SMB:

    <gPCFileSysPath>\Machine\Microsoft\Windows NT\Audit\audit.csv

Each audit.csv is parsed and every configured subcategory is compared
against the Microsoft recommended Advanced Audit Policy baseline.

The check surfaces two types of issues:
  1. MISCONFIGURED  -- a baseline subcategory is present in a GPO but set to
                       a weaker value than recommended
  2. NOT CONFIGURED -- a required baseline subcategory is not found in any GPO

Findings:
    Any misconfigured or missing subcategories -> MEDIUM finding, -10 points
    All baseline subcategories correctly configured -> INFO / PASS, 0 points

Prerequisites:
    impacket  (pip install impacket)
    Active SMB connection to the DC (connector.smb_conn must be available)
    Active LDAP connection (connector.ldap_conn must be available)
"""

import io
import csv

CHECK_NAME     = "Advanced Audit Policy"
CHECK_ORDER    = 23
CHECK_CATEGORY = ["Domain Hardening"]


# ---------------------------------------------------------------------------
# Microsoft Advanced Audit Policy Baseline
# (Based on Microsoft Security Compliance Toolkit / CIS Benchmark Level 1)
#
# Values: 0=No Auditing, 1=Success, 2=Failure, 3=Success and Failure
# ---------------------------------------------------------------------------
AUDIT_BASELINE = {
    # Account Logon
    "Credential Validation":                    3,
    "Kerberos Authentication Service":          3,
    "Kerberos Service Ticket Operations":       3,
    # Account Management
    "Computer Account Management":              3,
    "Distribution Group Management":            1,
    "Other Account Management Events":          3,
    "Security Group Management":                3,
    "User Account Management":                  3,
    # Detailed Tracking
    "Process Creation":                         1,
    # DS Access
    "Directory Service Access":                 2,
    "Directory Service Changes":                1,
    # Logon/Logoff
    "Account Lockout":                          2,
    "Logoff":                                   1,
    "Logon":                                    3,
    "Other Logon/Logoff Events":                3,
    "Special Logon":                            1,
    # Object Access
    "Removable Storage":                        3,
    # Policy Change
    "Audit Policy Change":                      3,
    "Authentication Policy Change":             1,
    "Authorization Policy Change":              1,
    # Privilege Use
    "Sensitive Privilege Use":                  3,
    # System
    "IPsec Driver":                             3,
    "Other System Events":                      3,
    "Security State Change":                    3,
    "Security System Extension":                3,
    "System Integrity":                         3,
}

SETTING_LABELS = {
    0: "No Auditing",
    1: "Success",
    2: "Failure",
    3: "Success and Failure",
}

# audit.csv column indices (0-based)
# Format: Machine Name, Policy Target, Subcategory, Subcategory GUID,
#         Inclusion Setting, Exclusion Setting, Setting Value
COL_SUBCATEGORY   = 2
COL_SETTING_VALUE = 6


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_attr(entry, attr_name):
    """
    Safely extract a single string value from an ldap3 entry or plain dict.
    ldap3 entry objects expose attributes via entry.<name>.value or
    entry_attributes_as_dict; plain dicts use entry['attributes'][name].
    """
    # ldap3 Entry object
    if hasattr(entry, attr_name):
        val = getattr(entry, attr_name)
        if hasattr(val, 'value'):
            v = val.value
            if isinstance(v, list):
                return str(v[0]) if v else ""
            return str(v) if v is not None else ""
    # entry_attributes_as_dict
    if hasattr(entry, 'entry_attributes_as_dict'):
        d = entry.entry_attributes_as_dict
        val = d.get(attr_name, "")
        if isinstance(val, list):
            return str(val[0]) if val else ""
        return str(val) if val else ""
    # plain dict with 'attributes' key
    if isinstance(entry, dict):
        val = entry.get('attributes', {}).get(attr_name, "")
        if isinstance(val, list):
            return str(val[0]) if val else ""
        return str(val) if val else ""
    return ""


def _unc_to_share_and_path(unc_path):
    r"""
    Parse a Windows UNC path into (share_name, path_relative_to_share).

    Input examples:
      \\dc01\SYSVOL\corp.local\Policies\{GUID}
      //dc01/SYSVOL/corp.local/Policies/{GUID}

    Returns:
      ('SYSVOL', '\\corp.local\\Policies\\{GUID}')
      or (None, None) on failure.

    The returned rel_path always starts with a single backslash and uses
    single backslashes throughout, matching impacket SMBConnection expectations.
    """
    # Normalise: forward slashes -> backslashes, collapse runs
    p = unc_path.replace('/', '\\')
    # Remove leading backslashes
    p = p.lstrip('\\')
    # Split into at most 3 parts: server, share, rest
    parts = p.split('\\', 2)
    if len(parts) < 2:
        return None, None
    share    = parts[1]
    rel_path = ('\\' + parts[2].lstrip('\\')) if len(parts) == 3 and parts[2] else ''
    return share, rel_path


def _smb_read_file(smb_conn, share, smb_path):
    """
    Read a file from an SMB share using impacket SMBConnection.getFile().
    Returns (bytes, None) on success or (None, error_string) on failure.
    smb_path must use single backslashes and start with a backslash.
    """
    buf = []
    try:
        smb_conn.getFile(share, smb_path, lambda chunk: buf.append(chunk))
        return b''.join(buf), None
    except Exception as e:
        return None, str(e)


def _smb_list_dir(smb_conn, share, smb_path):
    """
    List a directory via SMB. Returns list of filenames or empty list.
    smb_path should end with \\* for listPath.
    """
    try:
        entries = smb_conn.listPath(share, smb_path)
        return [e.get_longname() for e in entries
                if e.get_longname() not in ('.', '..')]
    except Exception:
        return []


def _parse_audit_csv(raw_bytes):
    """
    Parse an audit.csv file.
    Windows writes audit.csv as UTF-16 LE with BOM; try that first, then UTF-8.
    Returns dict of {subcategory_name: setting_value_int}.
    """
    results = {}
    for encoding in ('utf-16', 'utf-8-sig', 'utf-8'):
        try:
            text   = raw_bytes.decode(encoding)
            reader = csv.reader(io.StringIO(text))
            for row in reader:
                if len(row) <= max(COL_SUBCATEGORY, COL_SETTING_VALUE):
                    continue
                subcategory = row[COL_SUBCATEGORY].strip()
                # Windows audit.csv prefixes every subcategory name with "Audit "
                # Strip it so names match the AUDIT_BASELINE keys
                # e.g. "Audit Logon" -> "Logon", "Audit Credential Validation" -> "Credential Validation"
                if subcategory.startswith('Audit '):
                    subcategory = subcategory[6:]
                value_str   = row[COL_SETTING_VALUE].strip()
                # Skip header rows
                if not subcategory or subcategory.lower() in (
                        'subcategory', 'policy target', 'machine name'):
                    continue
                try:
                    results[subcategory] = int(value_str)
                except ValueError:
                    pass
            if results:
                return results
        except (UnicodeDecodeError, csv.Error):
            continue
    return results


def _compare_to_baseline(configured):
    """
    Compare configured subcategories against AUDIT_BASELINE.
    Returns (misconfigured, missing):
      misconfigured -- list of (subcategory, required_val, actual_val)
      missing       -- list of subcategory names absent from all GPOs
    """
    misconfigured = []
    missing       = []
    for subcat, required in AUDIT_BASELINE.items():
        if subcat not in configured:
            missing.append(subcat)
            continue
        actual    = configured[subcat]
        satisfied = (
            actual == required if required == 3
            else actual in (1, 3) if required == 1
            else actual in (2, 3) if required == 2
            else actual >= required
        )
        if not satisfied:
            misconfigured.append((subcat, required, actual))
    return misconfigured, missing


# ---------------------------------------------------------------------------
# Main check entry point
# ---------------------------------------------------------------------------

def run_check(connector, verbose=False):
    findings  = []
    smb_conn  = getattr(connector, 'smb_conn',  None)
    dbg       = getattr(connector, 'debug_log', None)

    # ---------------------------------------------------------------------- #
    # Pre-flight                                                              #
    # ---------------------------------------------------------------------- #
    if not smb_conn:
        findings.append({
            'title':          'Advanced Audit Policy -- SMB Not Available',
            'severity':       'info',
            'deduction':      0,
            'description':    (
                'SMB connectivity is required to read GPO audit.csv files from SYSVOL '
                'but no active SMB connection was found on the connector. '
                'Ensure SMB is included in the connector protocols and the DC is '
                'reachable on port 445.'
            ),
            'recommendation': "Add 'smb' to the connector protocols list and re-run ADScan.",
            'details':        ['connector.smb_conn is None'],
        })
        return findings

    # ---------------------------------------------------------------------- #
    # Step 1: Enumerate GPOs via LDAP                                        #
    # ---------------------------------------------------------------------- #
    gpo_search_base = f"CN=Policies,CN=System,{connector.base_dn}"
    gpo_entries = connector.ldap_search(
        search_filter='(objectClass=groupPolicyContainer)',
        search_base=gpo_search_base,
        attributes=['cn', 'displayName', 'gPCFileSysPath'],
    )

    gpo_list = []   # [(display_name, unc_path), ...]
    if gpo_entries:
        for entry in gpo_entries:
            try:
                display_name = _get_attr(entry, 'displayName')
                cn           = _get_attr(entry, 'cn')
                fspath       = _get_attr(entry, 'gPCFileSysPath')
                name         = display_name or cn or 'Unknown GPO'
                if fspath:
                    gpo_list.append((name, fspath))
            except Exception:
                continue

    if verbose:
        print(f'  [Audit Policy] Found {len(gpo_list)} GPO(s) via LDAP.')
        for gname, gpath in gpo_list:
            print(f'    GPO: {gname!r}  path: {gpath}')

    if not gpo_list:
        findings.append({
            'title':          'Advanced Audit Policy -- No GPOs Found',
            'severity':       'info',
            'deduction':      0,
            'description':    'No GPO objects were returned by LDAP. Unable to assess Advanced Audit Policy configuration.',
            'recommendation': 'Verify LDAP connectivity and that the account has read access to CN=Policies,CN=System.',
            'details':        [f'Search base: {gpo_search_base}'],
        })
        return findings

    # ---------------------------------------------------------------------- #
    # Step 2: Read audit.csv from each GPO via SMB                          #
    # ---------------------------------------------------------------------- #
    merged_config   = {}   # {subcategory: setting_value}  (merged across all GPOs)
    gpos_with_audit = []   # GPO names that contained a parseable audit.csv
    gpos_scanned    = 0
    smb_errors      = []   # (gpo_name, path_attempted, error_msg)

    for gpo_name, unc_path in gpo_list:
        share, rel_path = _unc_to_share_and_path(unc_path)
        if not share:
            smb_errors.append((gpo_name, unc_path, 'Could not parse UNC path'))
            continue

        # Build the full SMB path to audit.csv
        # rel_path is e.g. \corp.local\Policies\{GUID}
        # We append the fixed audit subpath using single backslashes
        audit_rel = rel_path.rstrip('\\') + '\\Machine\\Microsoft\\Windows NT\\Audit\\audit.csv'

        if verbose:
            print(f'  [Audit Policy] GPO {gpo_name!r}')
            print(f'    share={share!r}  path={audit_rel!r}')

        raw, err = _smb_read_file(smb_conn, share, audit_rel)
        gpos_scanned += 1

        if dbg:
            dbg.log_smb(
                operation='READ',
                path=f'\\\\{connector.dc_host}\\{share}{audit_rel}',
                result=f'{len(raw)} bytes' if raw else f'not found: {err}',
            )

        if raw is None:
            if verbose:
                print(f'    -> Not found or unreadable: {err}')
            # Diagnostic: list the Audit directory if it exists
            if verbose:
                audit_dir = rel_path.rstrip('\\') + '\\Machine\\Microsoft\\Windows NT\\Audit\\*'
                dir_entries = _smb_list_dir(smb_conn, share, audit_dir)
                if dir_entries:
                    print(f'    -> Audit dir contents: {dir_entries}')
                else:
                    # Try listing one level up
                    nt_dir = rel_path.rstrip('\\') + '\\Machine\\Microsoft\\Windows NT\\*'
                    nt_entries = _smb_list_dir(smb_conn, share, nt_dir)
                    print(f'    -> Windows NT dir contents: {nt_entries}')
            smb_errors.append((gpo_name, audit_rel, err or 'File not found'))
            continue

        parsed = _parse_audit_csv(raw)
        if parsed:
            gpos_with_audit.append(gpo_name)
            merged_config.update(parsed)
            if verbose:
                print(f'    -> Parsed {len(parsed)} subcategory entries from audit.csv.')
        else:
            if verbose:
                print(f'    -> audit.csv found ({len(raw)} bytes) but could not be parsed.')
            smb_errors.append((gpo_name, audit_rel, f'Parse failed ({len(raw)} bytes, encoding issue?)'))

    if verbose:
        print(f'  [Audit Policy] Scanned: {gpos_scanned} GPO(s), '
              f'found audit.csv in: {len(gpos_with_audit)}, '
              f'errors: {len(smb_errors)}')

    # ---------------------------------------------------------------------- #
    # Step 3: Compare merged config against baseline                         #
    # ---------------------------------------------------------------------- #
    error_detail = []
    if smb_errors:
        error_detail = ['', 'SMB read attempts (errors/not found):']
        for gname, path, msg in smb_errors[:10]:
            error_detail.append(f'  {gname}: {path} -> {msg}')

    if not merged_config:
        findings.append({
            'title':    'Advanced Audit Policy -- No audit.csv Found in Any GPO',
            'severity': 'medium',
            'deduction': 10,
            'description': (
                f'Scanned {gpos_scanned} GPO(s) via SYSVOL but found no '
                'audit.csv files under Machine\\Microsoft\\Windows NT\\Audit\\. '
                'This means Advanced Audit Policy is not configured via Group Policy. '
                'Without advanced auditing, security-relevant events may not be logged, '
                'severely limiting incident detection and forensic capability.'
            ),
            'recommendation': (
                'Configure Advanced Audit Policy via a GPO: '
                'Computer Configuration > Windows Settings > Security Settings > '
                'Advanced Audit Policy Configuration. '
                'Apply the Microsoft Security Compliance Toolkit baseline as a minimum.'
            ),
            'affected_count': 0,
            'details': [
                f'GPOs scanned: {gpos_scanned}',
                f'GPOs with audit.csv: none',
            ] + error_detail,
        })
        return findings

    misconfigured, missing = _compare_to_baseline(merged_config)
    total_issues           = len(misconfigured) + len(missing)

    # ---------------------------------------------------------------------- #
    # Step 4: Build findings                                                 #
    # ---------------------------------------------------------------------- #
    if total_issues == 0:
        findings.append({
            'title':    'Advanced Audit Policy -- Baseline Satisfied',
            'severity': 'info',
            'deduction': 0,
            'description': (
                f'All {len(AUDIT_BASELINE)} Microsoft baseline Advanced Audit Policy '
                'subcategories are correctly configured across the domain GPOs.'
            ),
            'recommendation': 'Continue enforcing the audit policy baseline via GPO.',
            'affected_count': 0,
            'details': [
                f'GPOs scanned: {gpos_scanned}',
                f"GPOs with audit.csv: {', '.join(gpos_with_audit) or 'none'}",
                f'Subcategories verified: {len(AUDIT_BASELINE)}',
            ],
        })
        return findings

    detail_lines = [
        f'GPOs scanned: {gpos_scanned}',
        f"GPOs with audit.csv: {', '.join(gpos_with_audit) or 'none'}",
        f'Total issues: {total_issues} '
        f'({len(misconfigured)} misconfigured, {len(missing)} not configured)',
        '',
    ]

    if misconfigured:
        detail_lines.append('MISCONFIGURED (weaker than baseline):')
        for subcat, required, actual in sorted(misconfigured):
            req_label = SETTING_LABELS.get(required, str(required))
            act_label = SETTING_LABELS.get(actual,   str(actual))
            detail_lines.append(
                f'  {subcat}: configured={act_label!r}, required={req_label!r}'
            )
        detail_lines.append('')

    if missing:
        detail_lines.append('NOT CONFIGURED (not found in any GPO):')
        for subcat in sorted(missing):
            req_label = SETTING_LABELS.get(AUDIT_BASELINE[subcat], str(AUDIT_BASELINE[subcat]))
            detail_lines.append(f'  {subcat}: required={req_label!r}')

    findings.append({
        'title': (
            f'Advanced Audit Policy: {total_issues} subcategory issue(s) '
            f'({len(misconfigured)} misconfigured, {len(missing)} not configured)'
        ),
        'severity':  'medium',
        'deduction': 10,
        'description': (
            f'{total_issues} of {len(AUDIT_BASELINE)} Microsoft baseline Advanced Audit '
            'Policy subcategories are either misconfigured or absent from domain GPOs. '
            'Gaps in audit policy reduce visibility into security-relevant events '
            'and hinder incident response and forensic investigations.'
        ),
        'recommendation': (
            'Review and remediate the listed subcategories in your audit GPO: '
            'Computer Configuration > Windows Settings > Security Settings > '
            'Advanced Audit Policy Configuration. '
            'Reference: Microsoft Security Compliance Toolkit Advanced Audit Policy baseline. '
            "Run 'auditpol /get /category:*' on each DC to verify effective applied settings."
        ),
        'affected_count': total_issues,
        'details': detail_lines,
    })

    return findings
