"""
checks/check_kerberos.py - Kerberos Attack Surface Check

Detects common Kerberos misconfigurations that enable credential-theft attacks.

Sub-checks:
  1. Kerberoastable accounts   — user objects with servicePrincipalName set
     (attackers can request TGS tickets and crack them offline)
  2. AS-REP Roastable accounts — DONT_REQ_PREAUTH flag set on user accounts
     (KDC returns encrypted AS-REP without requiring pre-authentication)
  3. DES-only encryption       — msDS-SupportedEncryptionTypes with only DES set
     (DES is deprecated; RC4/AES should be used)
  4. High-value Kerberoast     — combination of adminCount=1 + SPN + PasswordNeverExpires
     (most critical: Kerberoastable AND privileged AND password never changes)

Risk Deductions:
  Critical (-20): High-value Kerberoastable (adminCount=1 + SPN + DONT_EXPIRE)
  High    (-15): Kerberoastable user accounts (SPN on user)
  High    (-15): AS-REP Roastable accounts
  Medium  (-8) : DES-only encryption accounts
"""

CHECK_NAME = "Kerberos Attack Surface"
CHECK_ORDER = 5
CHECK_CATEGORY = ["Kerberos"]

# UAC flags
_UAC_ACCOUNTDISABLE        = 0x2
_UAC_DONT_EXPIRE_PASSWD    = 0x10000
_UAC_DONT_REQ_PREAUTH      = 0x400000   # AS-REP Roasting
_UAC_USE_DES_KEY_ONLY      = 0x200000   # DES-only

# msDS-SupportedEncryptionTypes: DES flags
_ETYPE_DES_CBC_CRC  = 0x1
_ETYPE_DES_CBC_MD5  = 0x2
_ETYPE_RC4          = 0x4
_ETYPE_AES128       = 0x8
_ETYPE_AES256       = 0x10
_DES_ONLY_MASK      = _ETYPE_DES_CBC_CRC | _ETYPE_DES_CBC_MD5

_ATTRS = [
    "sAMAccountName",
    "distinguishedName",
    "servicePrincipalName",
    "userAccountControl",
    "adminCount",
    "pwdLastSet",
    "msDS-SupportedEncryptionTypes",
    "memberOf",
    "description",
]


def _uac(entry, flag):
    try:
        return bool(int(entry.get("userAccountControl")) & flag)
    except Exception:
        return False


def _is_disabled(entry):
    return _uac(entry, _UAC_ACCOUNTDISABLE)


def _get_sam(entry):
    try:
        return str(entry.get("sAMAccountName"))
    except Exception:
        return "?"


def _get_spns(entry):
    try:
        v = entry.get("servicePrincipalName")
        return list(v) if v else []
    except Exception:
        return []


def _is_admin_count(entry):
    try:
        return int(entry.get("adminCount")) == 1
    except Exception:
        return False


def _pwd_never_expires(entry):
    return _uac(entry, _UAC_DONT_EXPIRE_PASSWD)


def _is_des_only(entry):
    """Return True if the account only supports DES encryption types."""
    # Check USE_DES_KEY_ONLY UAC flag
    if _uac(entry, _UAC_USE_DES_KEY_ONLY):
        return True
    # Check msDS-SupportedEncryptionTypes
    try:
        etype = int(entry.get("msDS-SupportedEncryptionTypes"))
        if etype == 0:
            return False  # 0 means default (RC4), not DES-only
        des_bits = etype & _DES_ONLY_MASK
        non_des_bits = etype & (_ETYPE_RC4 | _ETYPE_AES128 | _ETYPE_AES256)
        return bool(des_bits) and not bool(non_des_bits)
    except Exception:
        return False


def run_check(connector, verbose=False):
    findings = []

    # -----------------------------------------------------------------------
    # 1 & 4. Kerberoastable accounts (SPN on user object)
    # -----------------------------------------------------------------------
    kerb_entries = connector.ldap_search(
        search_filter=(
            "(&"
            "(objectClass=user)"
            "(!(objectClass=computer))"
            "(servicePrincipalName=*)"
            "(!(sAMAccountName=krbtgt))"
            ")"
        ),
        attributes=_ATTRS,
    )

    kerberoastable = []
    high_value_kerb = []

    for entry in (kerb_entries or []):
        if _is_disabled(entry):
            continue
        sam = _get_sam(entry)
        spns = _get_spns(entry)
        is_admin = _is_admin_count(entry)
        no_expire = _pwd_never_expires(entry)

        spn_str = spns[0] if spns else "?"
        label = f"{sam} | SPN: {spn_str}"

        if is_admin and no_expire:
            high_value_kerb.append(label + " [adminCount=1, DONT_EXPIRE]")
        else:
            kerberoastable.append(label)

    if verbose:
        print(f"     Kerberoastable accounts          : {len(kerberoastable)}")
        print(f"     High-value Kerberoastable        : {len(high_value_kerb)}")

    # High-value combo: adminCount=1 + SPN + PasswordNeverExpires (most critical)
    if high_value_kerb:
        findings.append({
            "title": "High-Value Kerberoastable Accounts (adminCount=1 + SPN + DONT_EXPIRE)",
            "severity": "critical",
            "deduction": 20,
            "description": (
                f"{len(high_value_kerb)} privileged account(s) have a Service Principal Name "
                "AND the password never expires AND adminCount=1 (indicating current or "
                "former group membership in a privileged group). "
                "An attacker can request a TGS ticket for these accounts, crack it offline, "
                "and immediately gain privileged access with no time pressure due to "
                "non-expiring passwords. This is considered the highest-priority Kerberoast target."
            ),
            "recommendation": (
                "1. Remove SPNs from privileged user accounts — use dedicated gMSA service accounts instead. "
                "2. If SPNs must remain, set passwords to 25+ random characters and rotate every 30 days. "
                "3. Enable 'AES only' encryption on these accounts to make cracking harder. "
                "4. Consider marking these accounts as 'Protected Users' to enforce AES."
            ),
            "details": high_value_kerb,
        })

    # Standard Kerberoastable
    if kerberoastable:
        findings.append({
            "title": "Kerberoastable Service Accounts",
            "severity": "high",
            "deduction": 15,
            "description": (
                f"{len(kerberoastable)} user account(s) have a Service Principal Name (SPN) "
                "set, making them targets for Kerberoasting. An attacker can request a TGS "
                "ticket for any SPN as any authenticated domain user, then crack the ticket "
                "offline to recover the account's plaintext password."
            ),
            "recommendation": (
                "Migrate service accounts to Group Managed Service Accounts (gMSAs) which "
                "use automatically rotated 120-character passwords. "
                "For accounts that cannot be migrated: use 25+ character random passwords, "
                "rotate every 30 days, and enable AES-only Kerberos encryption."
            ),
            "details": kerberoastable,
        })

    # -----------------------------------------------------------------------
    # 2. AS-REP Roastable accounts
    # -----------------------------------------------------------------------
    asrep_entries = connector.ldap_search(
        search_filter=(
            "(&"
            "(objectClass=user)"
            "(!(objectClass=computer))"
            "(userAccountControl:1.2.840.113556.1.4.803:=4194304)"  # 0x400000
            ")"
        ),
        attributes=_ATTRS,
    )

    asrep_accounts = []
    for entry in (asrep_entries or []):
        if _is_disabled(entry):
            continue
        sam = _get_sam(entry)
        is_admin = _is_admin_count(entry)
        label = sam + (" [adminCount=1]" if is_admin else "")
        asrep_accounts.append(label)

    if verbose:
        print(f"     AS-REP Roastable accounts        : {len(asrep_accounts)}")

    if asrep_accounts:
        findings.append({
            "title": "AS-REP Roastable Accounts (DONT_REQ_PREAUTH)",
            "severity": "high",
            "deduction": 15,
            "description": (
                f"{len(asrep_accounts)} account(s) have Kerberos pre-authentication "
                "disabled (DONT_REQ_PREAUTH flag). The KDC will return an AS-REP encrypted "
                "with the user's password hash without requiring any prior authentication. "
                "Any unauthenticated user on the network can request and crack these tickets "
                "offline — no domain credentials required."
            ),
            "recommendation": (
                "Enable Kerberos pre-authentication on all user accounts (this is the default). "
                "The DONT_REQ_PREAUTH flag should only exist if required by a legacy application "
                "that genuinely cannot support pre-auth. Audit and remove it everywhere possible."
            ),
            "details": asrep_accounts,
        })

    # -----------------------------------------------------------------------
    # 3. DES-only encryption
    # -----------------------------------------------------------------------
    des_entries = connector.ldap_search(
        search_filter=(
            "(|"
            "(userAccountControl:1.2.840.113556.1.4.803:=2097152)"  # USE_DES_KEY_ONLY 0x200000
            ")"
        ),
        attributes=_ATTRS,
    )

    des_accounts = []
    for entry in (des_entries or []):
        if _is_disabled(entry):
            continue
        des_accounts.append(_get_sam(entry))

    # Also check via msDS-SupportedEncryptionTypes
    etype_entries = connector.ldap_search(
        search_filter=(
            "(&"
            "(objectClass=user)"
            "(msDS-SupportedEncryptionTypes=*)"
            ")"
        ),
        attributes=_ATTRS,
    )
    for entry in (etype_entries or []):
        sam = _get_sam(entry)
        if sam in des_accounts or _is_disabled(entry):
            continue
        if _is_des_only(entry):
            des_accounts.append(sam + " [via msDS-SupportedEncryptionTypes]")

    if verbose:
        print(f"     DES-only accounts                : {len(des_accounts)}")

    if des_accounts:
        findings.append({
            "title": "Accounts Using DES-Only Kerberos Encryption",
            "severity": "medium",
            "deduction": 8,
            "description": (
                f"{len(des_accounts)} account(s) are configured to use DES Kerberos "
                "encryption only. DES (56-bit) was deprecated in Windows Server 2008 R2 "
                "and is trivially crackable with modern hardware. Kerberos tickets "
                "encrypted with DES can be cracked in seconds to minutes."
            ),
            "recommendation": (
                "Remove the USE_DES_KEY_ONLY UAC flag from all accounts. "
                "Set msDS-SupportedEncryptionTypes to 0x18 (AES128+AES256) or 0x1C (RC4+AES). "
                "Ensure the domain functional level is Windows Server 2008 R2 or higher."
            ),
            "details": des_accounts,
        })

    return findings
