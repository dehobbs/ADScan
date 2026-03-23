"""
lib/connector.py - ADScan Connection Manager

Manages LDAP, LDAPS, and SMB connections to a Domain Controller.
Supports password, NTLM hash (pass-the-hash), and Kerberos (ccache) auth.
"""
import os
import logging
import socket
import ssl
import struct
import hashlib
import binascii
from datetime import datetime

# Optional imports - graceful degradation if libraries are not installed
try:
    import ldap3
    from ldap3 import Server, Connection, ALL, NTLM, SIMPLE, SASL, GSSAPI, Tls, SUBTREE, BASE, LEVEL
    from ldap3.core.exceptions import LDAPException
    HAS_LDAP3 = True
except ImportError:
    HAS_LDAP3 = False

try:
    import impacket
    from impacket.smbconnection import SMBConnection
    from impacket.smb3structs import SMB2_DIALECT_30
    HAS_IMPACKET = True
except ImportError:
    HAS_IMPACKET = False


def _entry_to_dict(entry):
    """Convert an ldap3 Entry object to a plain dict with .get() support."""
    try:
        raw = entry.entry_attributes_as_dict
    except AttributeError:
        return entry if isinstance(entry, dict) else {}

    result = {}
    for attr_name, values in raw.items():
        if not isinstance(values, list):
            result[attr_name] = values
        elif len(values) == 0:
            result[attr_name] = None
        elif len(values) == 1:
            result[attr_name] = values[0]
        else:
            result[attr_name] = values

    dn = getattr(entry, 'entry_dn', None) or result.get('distinguishedName', '')
    result.setdefault('dn', dn)
    result.setdefault('distinguishedName', dn)
    return result


class ADConnector:
    """Manages connections to an Active Directory Domain Controller.

    Supported protocols:    ldap, ldaps, smb
    Supported auth methods: password, NTLM hash (pass-the-hash), Kerberos ccache
    """

    def __init__(
        self,
        domain,
        dc_host,
        username,
        password=None,
        ntlm_hash=None,
        use_kerberos=False,
        ccache_path=None,
        protocols=None,
        verbose=False,
        timeout=30,
    ):
        self.domain = domain
        self.dc_host = dc_host
        self.username = username
        self.password = password
        self.ntlm_hash = ntlm_hash
        self.use_kerberos = use_kerberos
        self.ccache_path = ccache_path
        self.protocols = protocols or ["ldap", "ldaps", "smb"]
        self.verbose = verbose
        self.timeout = timeout

        self.ldap_conn = None
        self.smb_conn = None
        self.debug_log = None
        self._log = logging.getLogger("adscan")

        self.base_dn = self._domain_to_dn(domain)

        if self.ntlm_hash:
            self.lm_hash, self.nt_hash = self._parse_ntlm_hash(ntlm_hash)
        else:
            self.lm_hash = ""
            self.nt_hash = ""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def connect(self):
        """Attempt connections for each configured protocol."""
        connected = False
        for proto in self.protocols:
            if proto in ("ldap", "ldaps"):
                if not HAS_LDAP3:
                    self._log.warning(" [WARN] ldap3 not installed - skipping %s. Run: pip install ldap3", proto.upper())
                    continue
                if self._connect_ldap(use_ssl=(proto == "ldaps")):
                    connected = True
            elif proto == "smb":
                if not HAS_IMPACKET:
                    self._log.warning(" [WARN] impacket not installed - skipping SMB. Run: pip install impacket")
                    continue
                if self._connect_smb():
                    connected = True
        return connected

    def disconnect(self):
        """Close all active connections."""
        if self.ldap_conn:
            try:
                self.ldap_conn.unbind()
            except Exception:  # unbind may fail if connection already dropped
                pass  # nosec B110
            self.ldap_conn = None
        if self.smb_conn:
            try:
                self.smb_conn.logoff()
            except Exception:  # logoff may fail if connection already dropped
                pass  # nosec B110
            self.smb_conn = None

    def ldap_search(
        self,
        search_base=None,
        search_filter=None,
        attributes=None,
        scope="SUBTREE",
        controls=None,
    ):
        """Perform an LDAP search. Returns list of entry dicts or empty list."""
        if not self.ldap_conn:
            self._log.warning("  [WARN] No LDAP connection available for search.")
            return []

        search_base   = search_base   or self.base_dn
        search_filter = search_filter or "(objectClass=*)"
        attrs         = attributes    or ["*"]

        _scope_map = {
            "SUBTREE":  ldap3.SUBTREE,
            "BASE":     ldap3.BASE,
            "ONELEVEL": ldap3.LEVEL,
        }
        ldap_scope = _scope_map.get(scope.upper(), ldap3.SUBTREE)

        try:
            kwargs = dict(
                search_base=search_base,
                search_filter=search_filter,
                search_scope=ldap_scope,
                attributes=attrs,
            )
            if controls:
                kwargs["controls"] = controls
            self.ldap_conn.search(**kwargs)
            entries = self.ldap_conn.entries

            dbg = getattr(self, "debug_log", None)
            if dbg:
                dbg.log_ldap(
                    search_filter=search_filter,
                    search_base=search_base,
                    attributes=attrs,
                    entry_count=len(entries),
                )
            return [_entry_to_dict(e) for e in entries]

        except Exception as e:
            self._log.warning("  [WARN] LDAP search failed: %s", e)
            dbg = getattr(self, "debug_log", None)
            if dbg:
                dbg.log_ldap(
                    search_filter=search_filter,
                    search_base=search_base,
                    attributes=attrs,
                    entry_count=0,
                    error=str(e),
                )
            return []

    def smb_available(self):
        """Return True if SMB connection is active."""
        return self.smb_conn is not None

    def get_smb_shares(self):
        """List SMB shares on the DC. Returns list of share names."""
        if not self.smb_conn:
            return []
        try:
            return [s["shi1_netname"][:-1] for s in self.smb_conn.listShares()]
        except Exception as e:
            self._log.warning("  [WARN] SMB listShares failed: %s", e)
            return []

    @property
    def log(self):
        """Return the shared 'adscan' logger for use by check modules."""
        return self._log

    def resolve_sid(self, sid_str):
        """Resolve a SID string to a sAMAccountName via an LDAP objectSid lookup.

        Active Directory supports filtering on ``objectSid`` using the standard
        string SID syntax, e.g. ``(objectSid=S-1-5-21-...-1104)``.

        Returns the sAMAccountName if found, or the original *sid_str* unchanged
        when the lookup fails or the SID has no matching object in the directory.

        Parameters
        ----------
        sid_str : str
            A string SID (e.g. ``S-1-5-21-...-1104``).

        Returns
        -------
        str
            Resolved account name (e.g. ``CORP\\\\john``) or original SID.
        """
        if not sid_str or not self.ldap_conn:
            return sid_str
        try:
            results = self.ldap_search(
                search_filter=f"(objectSid={sid_str})",
                attributes=["sAMAccountName", "distinguishedName"],
            )
            if results:
                sam = results[0].get("sAMAccountName")
                if sam:
                    return str(sam)
        except Exception as e:
            self._log.debug(" [DEBUG] resolve_sid(%s) failed: %s", sid_str, e)
        return sid_str

    # ------------------------------------------------------------------
    # Internal - connection helpers
    # ------------------------------------------------------------------

    def _resolve_ccache(self):
        """Return the ccache path to use, or None if Kerberos is not configured.

        Priority: explicit --ccache path > KRB5CCNAME env var.
        """
        if not self.use_kerberos:
            return None
        if self.ccache_path:
            return self.ccache_path
        return os.environ.get("KRB5CCNAME")

    def _connect_ldap(self, use_ssl=False):
        proto_label = "LDAPS" if use_ssl else "LDAP"
        port = 636 if use_ssl else 389
        self._log.info(" [*] Connecting via %s to %s:%s ...", proto_label, self.dc_host, port)

        try:
            tls = None
            if use_ssl:
                tls = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLS_CLIENT)
                tls.ssl_options = {"check_hostname": False}

            server = Server(
                self.dc_host,
                port=port,
                use_ssl=use_ssl,
                tls=tls,
                get_info=ALL,
                connect_timeout=self.timeout,
            )

            if self.use_kerberos:
                ccache = self._resolve_ccache()
                if not ccache:
                    self._log.warning(
                        " [!] %s connection FAILED: Kerberos requested but no ccache found"
                        " -- set KRB5CCNAME or use --ccache",
                        proto_label,
                    )
                    return False
                os.environ["KRB5CCNAME"] = ccache
                conn = Connection(
                    server,
                    authentication=SASL,
                    sasl_mechanism=GSSAPI,
                    auto_bind=True,
                )
            else:
                user = f"{self.domain}\\{self.username}"
                conn = Connection(
                    server,
                    user=user,
                    password=self.password if self.password else f"{self.lm_hash}:{self.nt_hash}",
                    authentication=NTLM,
                    auto_bind=True,
                )

            self.ldap_conn = conn
            self._log.info(" [*] Connected via %s to %s:%s - OK", proto_label, self.dc_host, port)
            return True

        except LDAPException as e:
            self._log.warning(" [!] %s connection to %s:%s FAILED: %s", proto_label, self.dc_host, port, e)
            return False
        except Exception as e:
            self._log.warning(" [!] %s connection to %s:%s FAILED: %s", proto_label, self.dc_host, port, e)
            return False

    def _connect_smb(self):
        self._log.info(" [*] Connecting via SMB to %s:445 ...", self.dc_host)
        try:
            smb = SMBConnection(self.dc_host, self.dc_host, sess_port=445, timeout=self.timeout)

            if self.use_kerberos:
                ccache = self._resolve_ccache()
                if not ccache:
                    self._log.warning(
                        " [!] SMB connection FAILED: Kerberos requested but no ccache found"
                        " -- set KRB5CCNAME or use --ccache"
                    )
                    return False
                os.environ["KRB5CCNAME"] = ccache
                smb.kerberosLogin(
                    self.username,
                    "",
                    self.domain,
                    "",
                    "",
                    useCache=True,
                )
            elif self.password:
                smb.login(self.username, self.password, self.domain)
            else:
                smb.login(
                    self.username,
                    "",
                    self.domain,
                    lmhash=self.lm_hash,
                    nthash=self.nt_hash,
                )

            self.smb_conn = smb
            self._log.info(" [*] Connected via SMB to %s:445 - OK", self.dc_host)
            return True

        except Exception as e:
            self._log.warning(" [!] SMB connection to %s:445 FAILED: %s", self.dc_host, e)
            return False

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _domain_to_dn(domain):
        """Convert domain FQDN to LDAP base DN (e.g. corp.local -> DC=corp,DC=local)."""
        parts = domain.split(".")
        return ",".join(f"DC={p}" for p in parts)

    @staticmethod
    def _parse_ntlm_hash(hash_str):
        """Parse NTLM hash string into (lm, nt) pair."""
        hash_str = hash_str.strip()
        if ":" in hash_str:
            parts = hash_str.split(":", 1)
            return parts[0], parts[1]
        return "aad3b435b51404eeaad3b435b51404ee", hash_str
