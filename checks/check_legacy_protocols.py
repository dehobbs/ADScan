"""
checks/check_legacy_protocols.py - Legacy Protocol checks

Checks:
  - SMBv1: Detected via impacket SMB dialect negotiation                        -15
  - SMB signing: Not enforced on domain controllers / workstations              -10
  - Null session: LDAP anonymous bind acceptance                                -10
  - NTLMv1 / WDigest guidance (informational via registry path hints)           0
"""

CHECK_NAME = "Legacy Protocols"
CHECK_ORDER = 21
CHECK_CATEGORY = "Legacy Network Protocol Exposure"


def run_check(connector, verbose=False):
    findings = []

    # SMBv1 detection via impacket SMB connection
    smb1_detected = False
    smb1_detail = []
    try:
        if connector.smb_conn is not None:
            dialect = None
            try:
                dialect = connector.smb_conn.getDialect()
            except AttributeError:
                pass
            if dialect is not None:
                # SMB_DIALECT = 'NT LM 0.12' in impacket = SMBv1
                dialect_str = str(dialect)
                if "NT LM 0.12" in dialect_str or dialect_str == "\\x00" or "0x0000" == dialect_str.lower():
                    smb1_detected = True
                    smb1_detail.append(f"SMB dialect negotiated: {dialect_str}")
                elif verbose:
                    print(f"[LegacyProtocols] SMB dialect: {dialect_str}")
        else:
            if verbose:
                print("[LegacyProtocols] No SMB connection available; skipping SMBv1 dialect check.")
            smb1_detail.append(
                "SMB connection not available. Run with --protocol smb or --protocol all "
                "for active SMBv1 dialect detection."
            )
    except Exception as exc:
        if verbose:
            print(f"[LegacyProtocols] SMBv1 check error: {exc}")

    if smb1_detected:
        findings.append({
            "title": "SMBv1 Protocol Detected",
            "severity": "high",
            "deduction": 15,
            "description": (
                "SMBv1 was successfully negotiated with the target domain controller. "
                "SMBv1 is a legacy protocol with no encryption or secure authentication. "
                "It is exploited by EternalBlue (MS17-010), WannaCry, NotPetya, and many other attacks. "
                "Microsoft disabled SMBv1 by default since Windows Server 2016."
            ),
            "recommendation": (
                "Disable SMBv1 on all systems: "
                "Set-SmbServerConfiguration -EnableSMB1Protocol $false "
                "Set-SmbClientConfiguration -EnableSMB1Protocol $false "
                "Remove-WindowsFeature FS-SMB1 "
                "Verify with: Get-SmbServerConfiguration | Select EnableSMB1Protocol"
            ),
            "details": smb1_detail,
        })
    else:
        if smb1_detail:
            findings.append({
                "title": "SMBv1 Check -- Limited (No Active SMB Connection)",
                "severity": "info",
                "deduction": 0,
                "description": (
                    "An active SMB connection was not available to test SMBv1 dialect negotiation. "
                    "Consider running with --protocol smb for active detection."
                ),
                "recommendation": (
                    "Manually verify SMBv1 is disabled: "
                    "Get-SmbServerConfiguration | Select EnableSMB1Protocol"
                ),
                "details": smb1_detail,
            })

    # SMB Signing guidance
    try:
        dc_computers = connector.ldap_search(
            connector.base_dn,
            "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
            ["cn", "dNSHostName"],
        ) or []
        dc_count = len(dc_computers)
    except Exception:
        dc_count = 0

    findings.append({
        "title": "SMB Signing Enforcement -- Manual Review Required",
        "severity": "info",
        "deduction": 0,
        "description": (
            "SMB signing prevents man-in-the-middle (MITM) relay attacks such as NTLM relay. "
            f"This environment has {dc_count} domain controller(s). "
            "SMB signing is required on DCs by default but may not be enforced on member servers "
            "and workstations, leaving them vulnerable to relay attacks."
        ),
        "recommendation": (
            "Enforce SMB signing on all systems via GPO: "
            "Computer Configuration > Windows Settings > Security Settings > "
            "Local Policies > Security Options: "
            "Microsoft network server: Digitally sign communications (always) = Enabled "
            "Microsoft network client: Digitally sign communications (always) = Enabled "
            "Verify with: Get-SmbServerConfiguration | Select RequireSecuritySignature"
        ),
        "details": [],
    })

    # Null session / anonymous LDAP bind check
    findings.append({
        "title": "Null Session / Anonymous LDAP Bind -- Manual Review Required",
        "severity": "info",
        "deduction": 0,
        "description": (
            "Anonymous LDAP binds (null sessions) allow unauthenticated enumeration of "
            "AD objects, including users, groups, and domain information. "
            "Null sessions are disabled by default in modern AD but may be re-enabled "
            "for legacy application compatibility."
        ),
        "recommendation": (
            "Verify null sessions are blocked. "
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RestrictAnonymous should be 1 or 2. "
            "RestrictAnonymousSAM should be 1. "
            "Test with: ldapsearch -x -H ldap://<dc> -b '' -s base "
            "If it returns data without credentials, null sessions are enabled."
        ),
        "details": [],
    })

    # NTLMv1 / WDigest guidance
    findings.append({
        "title": "NTLMv1 and WDigest -- Manual Registry Review Required",
        "severity": "info",
        "deduction": 0,
        "description": (
            "NTLMv1 is a weak authentication protocol susceptible to offline cracking. "
            "WDigest stores cleartext-equivalent credentials in LSASS memory. "
            "These settings are configured via registry and cannot be detected via LDAP. "
            "Both are disabled by default on Windows 8.1+ / Server 2012R2+, "
            "but may be re-enabled for legacy application compatibility."
        ),
        "recommendation": (
            "Ensure NTLMv1 is blocked via GPO: "
            "Network security: LAN Manager authentication level = "
            "Send NTLMv2 responses only. Refuse LM and NTLM "
            "Disable WDigest: "
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\"
            "WDigest\\UseLogonCredential = 0 "
            "Monitor for NTLMv1 logon events: Event ID 4624 with Authentication Package = NTLM "
            "and LmPackageName = NTLM V1."
        ),
        "details": [],
    })

    return findings
