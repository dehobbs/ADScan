CHECK_NAME = "GPP / cpassword (MS14-025)"
CHECK_ORDER = 62
CHECK_CATEGORY = ["Domain Hygiene"]

import xml.etree.ElementTree as ET
import base64
import os

# MS14-025: Microsoft published this AES key in MSDN documentation
# Key: 4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b
# IV:  00000000000000000000000000000000  (all zeros)
GPP_AES_KEY = bytes.fromhex(
    "4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b"
)

# GPP XML files that can contain cpassword
GPP_FILES = [
    "Groups.xml",
    "Services.xml",
    "Scheduledtasks.xml",
    "DataSources.xml",
    "Printers.xml",
    "Drives.xml",
]


def _decrypt_cpassword(cpassword):
    """
    Decrypt a GPP cpassword using the publicly-known AES-256-CBC key.
    Returns the plaintext password string, or an error message.
    """
    try:
        from Crypto.Cipher import AES
        import struct

        # Pad the base64 string to a multiple of 4
        padding = 4 - (len(cpassword) % 4)
        if padding != 4:
            cpassword += "=" * padding

        ciphertext = base64.b64decode(cpassword)
        # AES-256-CBC, zero IV
        cipher = AES.new(GPP_AES_KEY, AES.MODE_CBC, b"\x00" * 16)
        decrypted = cipher.decrypt(ciphertext)
        # Remove PKCS7 padding
        pad_len = decrypted[-1]
        if isinstance(pad_len, int) and 1 <= pad_len <= 16:
            decrypted = decrypted[:-pad_len]
        return decrypted.decode("utf-16-le", errors="replace").strip()
    except ImportError:
        return "<pycryptodome not installed — install with: pip install pycryptodome>"
    except Exception as e:
        return f"<decryption error: {e}>"


def _find_cpasswords_in_xml(xml_content, source_path):
    """Parse a GPP XML file and extract all cpassword attributes."""
    hits = []
    try:
        root = ET.fromstring(xml_content)
        for elem in root.iter():
            cpass = elem.get("cpassword")
            if cpass and len(cpass) > 4:
                name = (
                    elem.get("name") or
                    elem.get("userName") or
                    elem.get("username") or
                    elem.get("serviceName") or
                    "unknown"
                )
                plaintext = _decrypt_cpassword(cpass)
                hits.append({
                    "file": source_path,
                    "element": elem.tag,
                    "name": name,
                    "cpassword": cpass[:20] + "...",
                    "plaintext": plaintext,
                })
    except ET.ParseError:
        pass
    return hits


def run_check(connector, verbose=False):
    findings = []
    all_hits = []

    try:
        # ------------------------------------------------------------------ #
        # Method 1: SMB walk of SYSVOL (requires impacket + SMB connection)   #
        # ------------------------------------------------------------------ #
        smb_searched = False
        try:
            smb_conn = getattr(connector, "smb_connection", None)
            if smb_conn:
                sysvol_path = f"\\\\{connector.dc_host}\\SYSVOL\\{connector.domain}\\Policies"
                # Walk SYSVOL via SMB and search for GPP XML files
                # This is a best-effort scan; errors are caught and noted
                try:
                    import impacket.smbconnection
                    shares = smb_conn.listPath("SYSVOL", "\\*")
                    smb_searched = True
                    # Recursive walk for GPP files
                    def _smb_walk(share, path):
                        try:
                            entries = smb_conn.listPath(share, path + "\\*")
                            for e in entries:
                                fname = e.get_longname()
                                if fname in (".", ".."):
                                    continue
                                full = path + "\\" + fname
                                if e.is_directory():
                                    _smb_walk(share, full)
                                elif fname in GPP_FILES:
                                    try:
                                        buf = []
                                        smb_conn.getFile(share, full, lambda d: buf.append(d))
                                        content = b"".join(buf).decode("utf-8", errors="replace")
                                        hits = _find_cpasswords_in_xml(content, full)
                                        all_hits.extend(hits)
                                    except Exception:
                                        pass
                        except Exception:
                            pass

                    _smb_walk("SYSVOL", "")
                except Exception:
                    smb_searched = False
        except Exception:
            smb_searched = False

        # ------------------------------------------------------------------ #
        # Method 2: LDAP-based GPO path enumeration (fallback / supplement)   #
        # ------------------------------------------------------------------ #
        if not smb_searched or not all_hits:
            # Query all GPOs to get their filesystem paths
            gpo_results = connector.ldap_search(
                search_filter="(objectClass=groupPolicyContainer)",
                search_base="CN=Policies,CN=System," + connector.base_dn,
                attributes=["cn", "displayName", "gPCFileSysPath"],
            )

            gpo_paths = []
            if gpo_results:
                for entry in gpo_results:
                    attrs = entry.get("attributes", {}) if isinstance(entry, dict) else {}
                    fspath = attrs.get("gPCFileSysPath", "")
                    if fspath:
                        gpo_paths.append(fspath)

            if gpo_paths and not smb_searched:
                # Attempt local filesystem access (useful if running from a domain-joined host)
                for gpo_path in gpo_paths:
                    for dirpath, _dirs, files in os.walk(gpo_path):
                        for fname in files:
                            if fname in GPP_FILES:
                                full_path = os.path.join(dirpath, fname)
                                try:
                                    with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                                        content = f.read()
                                    hits = _find_cpasswords_in_xml(content, full_path)
                                    all_hits.extend(hits)
                                except Exception:
                                    pass

        # ------------------------------------------------------------------ #
        # Build findings                                                       #
        # ------------------------------------------------------------------ #
        if all_hits:
            detail_lines = []
            for h in all_hits:
                detail_lines.append(
                    f"File: {h['file']} | Element: {h['element']} | "
                    f"Account: {h['name']} | Plaintext: {h['plaintext']}"
                )

            findings.append({
                "title": f"GPP cpassword (MS14-025): {len(all_hits)} credential(s) found in SYSVOL",
                "severity": "critical",
                "deduction": 20,
                "description": (
                    "Group Policy Preferences XML files containing cpassword attributes were found "
                    "in SYSVOL. Microsoft published the AES-256 decryption key in 2012 (MS14-025), "
                    "meaning any authenticated domain user can decrypt these passwords trivially. "
                    "This is a well-known attack used by tools like Get-GPPPassword and Metasploit."
                ),
                "recommendation": (
                    "1. Run Microsoft's Fix-It tool or manually delete all GPP XML files "
                    "containing cpassword from SYSVOL.\n"
                    "2. Change the passwords of any accounts whose credentials were exposed.\n"
                    "3. Use LAPS for local administrator passwords instead of GPP.\n"
                    "4. Apply MS14-025 patch if not already applied (KB2962486).\n"
                    "PowerShell: Get-ChildItem -Path \\\\<domain>\\SYSVOL -Recurse -Include "
                    "Groups.xml,Services.xml,Scheduledtasks.xml | "
                    "Select-String -Pattern 'cpassword'"
                ),
                "details": detail_lines,
            })
        else:
            findings.append({
                "title": "GPP / cpassword (MS14-025): No cpassword attributes found",
                "severity": "info",
                "deduction": 0,
                "description": (
                    "No Group Policy Preferences XML files containing cpassword attributes were "
                    "detected. Note: SYSVOL scanning requires SMB connectivity or local filesystem "
                    "access to the domain controller."
                ),
                "recommendation": (
                    "Periodically verify SYSVOL does not contain GPP XML files with cpassword. "
                    "Ensure MS14-025 patch (KB2962486) is applied."
                ),
                "details": [],
            })

    except Exception as e:
        findings.append({
            "title": "GPP / cpassword: Check encountered an error",
            "severity": "info",
            "deduction": 0,
            "description": f"The check could not complete: {e}",
            "recommendation": "Verify SMB/LDAP connectivity. Ensure pycryptodome is installed.",
            "details": [str(e)],
        })

    return findings
