CHECK_NAME = "RC4 / Legacy Kerberos Encryption"
CHECK_ORDER = 66
CHECK_CATEGORY = ["Kerberos"]

# msDS-SupportedEncryptionTypes bitmask values
ENC_DES_CBC_CRC        = 0x0001
ENC_DES_CBC_MD5        = 0x0002
ENC_RC4_HMAC           = 0x0004
ENC_AES128_CTS_HMAC    = 0x0008
ENC_AES256_CTS_HMAC    = 0x0010

# A value of 0 or NULL means the account uses the domain default (which may include RC4)
# A value of 0x1C means AES128 + AES256 + RC4 is supported
# We flag: any account with RC4 explicitly enabled (bit 0x4 set) or value=0 (domain default includes RC4)

# Scope of accounts to check
# DC UAC flag: SERVER_TRUST_ACCOUNT
UAC_SERVER_TRUST = 0x2000
UAC_DISABLED     = 0x0002


def _enc_type_names(val):
    names = []
    if val & ENC_DES_CBC_CRC:
        names.append("DES-CBC-CRC")
    if val & ENC_DES_CBC_MD5:
        names.append("DES-CBC-MD5")
    if val & ENC_RC4_HMAC:
        names.append("RC4-HMAC")
    if val & ENC_AES128_CTS_HMAC:
        names.append("AES128")
    if val & ENC_AES256_CTS_HMAC:
        names.append("AES256")
    if not names:
        names.append(f"unknown/default(0x{val:04x})")
    return ", ".join(names)


def run_check(connector, verbose=False):
    findings = []

    try:
        # Query all enabled user accounts, service accounts (SPN set), DCs, and admin accounts
        results = connector.ldap_search(
            search_filter=(
                "(&(objectClass=user)"
                "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
                ")"
            ),
            attributes=[
                "sAMAccountName",
                "distinguishedName",
                "userAccountControl",
                "msDS-SupportedEncryptionTypes",
                "servicePrincipalName",
                "adminCount",
            ],
        )

        if not results:
            findings.append({
                "title": "RC4 Encryption: No accounts found",
                "severity": "info",
                "deduction": 0,
                "description": "No enabled user accounts were found.",
                "recommendation": "No action required.",
                "details": [],
            })
            return findings

        rc4_dcs        = []
        rc4_admins     = []
        rc4_svc_accts  = []
        rc4_users      = []
        des_accounts   = []

        for entry in results:
            attrs = entry.get("attributes", {}) if isinstance(entry, dict) else {}
            sam = attrs.get("sAMAccountName", "unknown")
            dn = attrs.get("distinguishedName", "")
            uac = int(attrs.get("userAccountControl", 0) or 0)
            enc_raw = attrs.get("msDS-SupportedEncryptionTypes")
            spns = attrs.get("servicePrincipalName") or []
            if isinstance(spns, str):
                spns = [spns]
            admin_count = int(attrs.get("adminCount", 0) or 0)

            is_dc = bool(uac & UAC_SERVER_TRUST)

            # Determine effective encryption value
            if enc_raw is None or enc_raw == "" or enc_raw == 0:
                # 0 / unset = domain default, which typically includes RC4
                enc_val = 0
                permits_rc4 = True
                enc_label = "domain default (includes RC4)"
            else:
                try:
                    enc_val = int(enc_raw)
                except Exception:  # msDS-SupportedEncryptionTypes is non-integer; skip entry
                    continue  # nosec B112
                permits_rc4 = bool(enc_val & ENC_RC4_HMAC)
                has_des = bool(enc_val & (ENC_DES_CBC_CRC | ENC_DES_CBC_MD5))
                enc_label = _enc_type_names(enc_val)

                if has_des:
                    des_accounts.append(f"{sam} — enc: {enc_label} | DN: {dn}")

            if not permits_rc4:
                continue

            label = f"{sam} — enc: {enc_label} | DN: {dn}"

            if is_dc:
                rc4_dcs.append(label)
            elif admin_count:
                rc4_admins.append(label)
            elif spns:
                rc4_svc_accts.append(label)
            else:
                rc4_users.append(label)

        # --- DES accounts (critical) ---
        if des_accounts:
            findings.append({
                "title": f"DES Encryption Enabled: {len(des_accounts)} account(s)",
                "severity": "critical",
                "deduction": 15,
                "description": (
                    "These accounts explicitly permit DES encryption for Kerberos. "
                    "DES was deprecated in Windows Server 2008 R2 and is trivially broken. "
                    "Accounts permitting DES can be targeted by Kerberoast with DES tickets, "
                    "which crack orders of magnitude faster than RC4 or AES."
                ),
                "recommendation": (
                    "Remove DES encryption types from all accounts. "
                    "Set-ADUser <account> -KerberosEncryptionType AES256,AES128 "
                    "or via Group Policy: Computer Configuration > Windows Settings > "
                    "Security Settings > Local Policies > Security Options > "
                    "'Network security: Configure encryption types allowed for Kerberos'"
                ),
                "details": des_accounts,
            })

        # --- DCs permitting RC4 ---
        if rc4_dcs:
            findings.append({
                "title": f"RC4 Permitted on Domain Controllers: {len(rc4_dcs)} DC(s)",
                "severity": "high",
                "deduction": 10,
                "description": (
                    "Domain Controllers have msDS-SupportedEncryptionTypes set to include or "
                    "default to RC4-HMAC. Attackers can specifically request RC4 Kerberos tickets "
                    "for offline cracking (Kerberoast, AS-REP roast). RC4 is significantly weaker "
                    "than AES-128/256 and can be cracked with modern GPU rigs."
                ),
                "recommendation": (
                    "Configure DCs to require AES: "
                    "Set-ADComputer <DC> -KerberosEncryptionType AES256,AES128\n"
                    "Group Policy: Computer Configuration > Windows Settings > Security Settings > "
                    "Local Policies > Security Options > "
                    "'Network security: Configure encryption types allowed for Kerberos' = "
                    "AES128_HMAC_SHA1, AES256_HMAC_SHA1 only."
                ),
                "details": rc4_dcs,
            })

        # --- Admin accounts permitting RC4 ---
        if rc4_admins:
            findings.append({
                "title": f"RC4 Permitted on Admin Accounts: {len(rc4_admins)} account(s)",
                "severity": "high",
                "deduction": 8,
                "description": (
                    "Privileged accounts (adminCount=1) permit RC4-HMAC Kerberos encryption. "
                    "If these accounts have SPNs, they are Kerberoastable with RC4 tickets. "
                    "Even without SPNs, RC4 TGTs are weaker to offline attacks."
                ),
                "recommendation": (
                    "Set AES-only encryption on all admin accounts: "
                    "Set-ADUser <account> -KerberosEncryptionType AES256,AES128"
                ),
                "details": rc4_admins,
            })

        # --- Service accounts permitting RC4 ---
        if rc4_svc_accts:
            findings.append({
                "title": f"RC4 Permitted on Service Accounts: {len(rc4_svc_accts)} account(s)",
                "severity": "medium",
                "deduction": 8,
                "description": (
                    f"{len(rc4_svc_accts)} service accounts (accounts with SPNs) permit RC4-HMAC. "
                    "These are directly Kerberoastable with RC4 tickets, which are significantly "
                    "faster to crack offline than AES tickets. "
                    "Kerberoast with RC4 is a standard post-exploitation technique."
                ),
                "recommendation": (
                    "Set AES-only encryption on all service accounts. "
                    "Migrate service accounts to gMSAs where possible. "
                    "Set-ADUser <svc_account> -KerberosEncryptionType AES256,AES128"
                ),
                "details": rc4_svc_accts[:100],
            })

        if not findings:
            findings.append({
                "title": "RC4 Encryption: No accounts with RC4/DES issues found",
                "severity": "info",
                "deduction": 0,
                "description": (
                    "No enabled accounts were found with RC4 or DES encryption explicitly configured. "
                    "Note: accounts with msDS-SupportedEncryptionTypes=0 use the domain default "
                    "which may still include RC4 depending on domain functional level settings."
                ),
                "recommendation": (
                    "Review domain-wide Kerberos encryption policy via Group Policy to ensure "
                    "RC4 is disabled at the domain level."
                ),
                "details": [],
            })

    except Exception as e:
        findings.append({
            "title": "RC4 Encryption: Check encountered an error",
            "severity": "info",
            "deduction": 0,
            "description": f"The check could not complete: {e}",
            "recommendation": "Verify LDAP connectivity and permissions.",
            "details": [str(e)],
        })

    return findings
