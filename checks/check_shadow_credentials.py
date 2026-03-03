CHECK_NAME = "Shadow Credentials"
CHECK_ORDER = 65
CHECK_CATEGORY = "Certificate-Based Persistence & Abuse"

import base64
import struct
from datetime import datetime, timezone

# msDS-KeyCredentialLink device ID is the first 16 bytes of the blob (Key Identifier)
# We flag entries that appear unexpected based on creation time and subject
# Key Credential Link entry structure (simplified):
#   Version: UINT32 (should be 0x200)
#   Identifier: GUID (16 bytes)
#   ...

# How many days before a KeyCredentialLink is considered suspicious if the domain
# does not appear to have Passwordless/WHFB actively deployed
RECENT_DAYS_THRESHOLD = 365  # Entries created > 1 year ago with no explanation are suspicious


def _parse_key_credential_date(raw_value):
    """
    Attempt to extract the creation date from a msDS-KeyCredentialLink blob.
    The blob is a binary structure; the creation time is stored as FILETIME in one of the entries.
    Returns a datetime or None.
    """
    try:
        if isinstance(raw_value, str):
            data = base64.b64decode(raw_value)
        elif isinstance(raw_value, (bytes, bytearray)):
            data = bytes(raw_value)
        else:
            return None

        # Parse the KeyCredentialLink SEQUENCE
        # Format: [Version UINT32][Count UINT32][ {EntryTag UINT16, EntryLen UINT16, EntryData} ... ]
        offset = 0
        if len(data) < 8:
            return None
        version = struct.unpack_from("<I", data, offset)[0]
        offset += 4
        count = struct.unpack_from("<I", data, offset)[0]
        offset += 4

        for _ in range(min(count, 20)):
            if offset + 4 > len(data):
                break
            tag = struct.unpack_from("<H", data, offset)[0]
            length = struct.unpack_from("<H", data, offset + 2)[0]
            offset += 4
            entry_data = data[offset: offset + length]
            offset += length

            # Tag 8 = KeyCreationTime (FILETIME)
            if tag == 8 and length == 8:
                filetime = struct.unpack_from("<Q", entry_data)[0]
                if filetime > 0:
                    # Convert Windows FILETIME to Python datetime
                    epoch_diff = 116444736000000000
                    timestamp = (filetime - epoch_diff) / 10_000_000
                    return datetime.fromtimestamp(timestamp, tz=timezone.utc)
        return None
    except Exception:
        return None


def _describe_entry(sam, raw_value, index):
    """Build a human-readable description of a KeyCredentialLink entry."""
    dt = _parse_key_credential_date(raw_value)
    date_str = dt.strftime("%Y-%m-%d %H:%M UTC") if dt else "unknown date"

    # Extract key identifier (first 16 bytes after version/count)
    try:
        if isinstance(raw_value, str):
            data = base64.b64decode(raw_value)
        else:
            data = bytes(raw_value)
        key_id_hex = data[8:24].hex() if len(data) >= 24 else "n/a"
    except Exception:
        key_id_hex = "n/a"

    return f"{sam} — key #{index + 1} | ID: {key_id_hex} | created: {date_str}"


def run_check(connector, verbose=False):
    findings = []

    try:
        # Query all user and computer objects that have msDS-KeyCredentialLink populated
        user_results = connector.ldap_search(
            search_filter=(
                "(&(objectClass=user)"
                "(msDS-KeyCredentialLink=*)"
                ")"
            ),
            attributes=[
                "sAMAccountName",
                "distinguishedName",
                "msDS-KeyCredentialLink",
                "adminCount",
                "userAccountControl",
            ],
        )

        computer_results = connector.ldap_search(
            search_filter=(
                "(&(objectClass=computer)"
                "(msDS-KeyCredentialLink=*)"
                ")"
            ),
            attributes=[
                "sAMAccountName",
                "distinguishedName",
                "msDS-KeyCredentialLink",
                "userAccountControl",
            ],
        )

        if not user_results:
            user_results = []
        if not computer_results:
            computer_results = []

        all_results = [("user", r) for r in user_results] + [("computer", r) for r in computer_results]

        if not all_results:
            findings.append({
                "title": "Shadow Credentials: No msDS-KeyCredentialLink entries found",
                "severity": "info",
                "deduction": 0,
                "description": (
                    "No user or computer accounts have msDS-KeyCredentialLink attributes populated. "
                    "This attribute is used for Windows Hello for Business and passwordless "
                    "authentication. Its absence is normal if WHFB is not deployed."
                ),
                "recommendation": (
                    "If Windows Hello for Business is deployed, some entries are expected. "
                    "Monitor for unexpected additions to this attribute, as it can be abused "
                    "for shadow credentials attacks (Whisker, pyWhisker)."
                ),
                "details": [],
            })
            return findings

        admin_hits = []
        dc_hits = []
        user_hits = []
        computer_hits = []

        for obj_type, entry in all_results:
            attrs = entry.get("attributes", {}) if isinstance(entry, dict) else {}
            sam = attrs.get("sAMAccountName", "unknown")
            dn = attrs.get("distinguishedName", "")
            key_links = attrs.get("msDS-KeyCredentialLink", [])
            if not isinstance(key_links, list):
                key_links = [key_links]
            admin_count = int(attrs.get("adminCount", 0) or 0)
            uac = int(attrs.get("userAccountControl", 0) or 0)
            is_dc = bool(uac & 0x2000)  # SERVER_TRUST_ACCOUNT

            for i, kl in enumerate(key_links):
                desc = _describe_entry(sam, kl, i)
                if is_dc:
                    dc_hits.append(f"[DC] {desc} | DN: {dn}")
                elif admin_count:
                    admin_hits.append(f"[ADMIN] {desc} | DN: {dn}")
                elif obj_type == "computer":
                    computer_hits.append(f"{desc} | DN: {dn}")
                else:
                    user_hits.append(f"{desc} | DN: {dn}")

        total = len(admin_hits) + len(dc_hits) + len(user_hits) + len(computer_hits)

        # Critical: DCs or admin accounts with unexpected key credentials
        if dc_hits or admin_hits:
            findings.append({
                "title": (
                    f"Shadow Credentials: {len(dc_hits + admin_hits)} high-value "
                    f"account(s) with msDS-KeyCredentialLink"
                ),
                "severity": "critical",
                "deduction": 20,
                "description": (
                    "Domain Controllers or administrator accounts have msDS-KeyCredentialLink "
                    "entries set. An attacker with write access to this attribute can inject a "
                    "certificate credential (shadow credential) that can be used to authenticate "
                    "as the account via PKINIT without knowing the password. On DCs this grants "
                    "DCSync capability. This technique is used by tools like Whisker and pyWhisker."
                ),
                "recommendation": (
                    "1. If Windows Hello for Business is NOT deployed, remove all unexpected entries:\n"
                    "   Set-ADComputer/User <account> -Clear msDS-KeyCredentialLink\n"
                    "2. If WHFB IS deployed, validate each entry against WHFB provisioning records.\n"
                    "3. Monitor for changes to msDS-KeyCredentialLink via AD audit logs.\n"
                    "4. Restrict write access to this attribute using fine-grained ACLs."
                ),
                "details": dc_hits + admin_hits,
            })

        # High: regular user/computer accounts
        if user_hits or computer_hits:
            all_standard = user_hits + computer_hits
            findings.append({
                "title": f"Shadow Credentials: {len(all_standard)} standard account(s) with msDS-KeyCredentialLink",
                "severity": "high",
                "deduction": 10,
                "description": (
                    f"{len(all_standard)} standard user or computer accounts have msDS-KeyCredentialLink entries. "
                    "While some may be legitimate WHFB registrations, unexpected entries can indicate "
                    "shadow credentials attacks. Any principal with write access to an account's "
                    "msDS-KeyCredentialLink can silently gain persistent authentication capability."
                ),
                "recommendation": (
                    "Validate each entry against WHFB deployment records. Remove any entries "
                    "not associated with a known device enrollment. "
                    "Set-ADUser <account> -Clear msDS-KeyCredentialLink"
                ),
                "details": all_standard[:100],
            })

    except Exception as e:
        findings.append({
            "title": "Shadow Credentials: Check encountered an error",
            "severity": "info",
            "deduction": 0,
            "description": f"The check could not complete: {e}",
            "recommendation": "Verify LDAP connectivity and permissions.",
            "details": [str(e)],
        })

    return findings
