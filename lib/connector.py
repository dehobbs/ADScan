""" lib/connector.py - ADScan Connection Manager
Manages LDAP, LDAPS, and SMB connections to a Domain Controller.
Supports both password and NTLM hash authentication.
"""
import socket
import ssl
import struct
import hashlib
import binascii
from datetime import datetime

# Optional imports - graceful degradation if libraries are not installed
try:
    import ldap3
    from ldap3 import Server, Connection, ALL, NTLM, SIMPLE, Tls, SUBTREE, BASE, LEVEL
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


class ADConnector:
    """
    Manages connections to an Active Directory Domain Controller.

    Supported protocols: ldap, ldaps, smb
    Supported auth methods: password, NTLM hash (pass-the-hash)
    """

    def __init__(self, domain, dc_host, username, password=None, ntlm_hash=None,
                 protocols=None, verbose=False, timeout=30):
        self.domain = domain
        self.dc_host = dc_host
        self.username = username
        self.password = password
        self.ntlm_hash = ntlm_hash
        self.protocols = protocols or ["ldap", "ldaps", "smb"]
        self.verbose = verbose
        self.timeout = timeout

        # Active connections
        self.ldap_conn = None
        self.smb_conn = None
        self.debug_log = None  # Set by adscan.py to enable debug logging

        self.base_dn = self._domain_to_dn(domain)

        # Normalise NTLM hash
        if self.ntlm_hash:
            self.lm_hash, self.nt_hash = self._parse_ntlm_hash(ntlm_hash)
        else:
            self.lm_hash = ""
            self.nt_hash = ""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def connect(self):
        """Attempt connections for each configured protocol.
        Returns True if at least one connection succeeds."""
        connected = False
        for proto in self.protocols:
            if proto in ("ldap", "ldaps"):
                if not HAS_LDAP3:
                    print(f" [WARN] ldap3 not installed - skipping {proto.upper()}")
                    print("        pip install ldap3")
                    continue
                if self._connect_ldap(use_ssl=(proto == "ldaps")):
                    connected = True
            elif proto == "smb":
                if not HAS_IMPACKET:
                    print(f" [WARN] impacket not installed - skipping SMB")
                    print("        pip install impacket")
                    continue
                if self._connect_smb():
                    connected = True
        return connected

    def disconnect(self):
        """Close all active connections."""
        if self.ldap_conn:
            try:
                self.ldap_conn.unbind()
            except Exception:
                pass
            self.ldap_conn = None
        if self.smb_conn:
            try:
                self.smb_conn.logoff()
            except Exception:
                pass
            self.smb_conn = None

    def ldap_search(self, search_base, search_filter, attributes=None,
                    scope="SUBTREE", controls=None):
        """Perform an LDAP search. Returns list of entry objects or empty list.

        Args:
            search_base:   DN to search from (e.g. connector.base_dn or a sub-DN).
            search_filter: LDAP filter string (e.g. "(objectClass=user)").
            attributes:    List of attribute names to retrieve (default: all).
            scope:         Search scope: "SUBTREE" (default), "BASE", or "ONELEVEL".
            controls:      Optional list of ldap3 control tuples passed to search().
        """
        if not self.ldap_conn:
            if self.verbose:
                print(" [WARN] No LDAP connection available for search.")
            return []

        attrs = attributes or ["*"]

        # Map scope string to ldap3 constant
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

            # Debug logging hook -- records every LDAP query for troubleshooting
            dbg = getattr(self, "debug_log", None)
            if dbg:
                dbg.log_ldap(
                    search_filter=search_filter,
                    search_base=search_base,
                    attributes=attrs,
                    entry_count=len(entries),
                )
            return entries
        except Exception as e:
            if self.verbose:
                print(f" [WARN] LDAP search failed: {e}")
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
            if self.verbose:
                print(f" [WARN] SMB listShares failed: {e}")
            return []

    # ------------------------------------------------------------------
    # Internal - connection helpers
    # ------------------------------------------------------------------

    def _connect_ldap(self, use_ssl=False):
        proto_label = "LDAPS" if use_ssl else "LDAP"
        port = 636 if use_ssl else 389
        print(f" [*] Connecting via {proto_label} to {self.dc_host}:{port} ...", end=" ")
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
            user = f"{self.domain}\\{self.username}"
            conn = Connection(
                server,
                user=user,
                password=self.password if self.password else f"{self.lm_hash}:{self.nt_hash}",
                authentication=NTLM,
                auto_bind=True,
            )
            self.ldap_conn = conn
            print("OK")
            return True
        except LDAPException as e:
            print(f"FAILED ({e})")
            return False
        except Exception as e:
            print(f"FAILED ({e})")
            return False

    def _connect_smb(self):
        print(f" [*] Connecting via SMB to {self.dc_host}:445 ...", end=" ")
        try:
            smb = SMBConnection(self.dc_host, self.dc_host, sess_port=445, timeout=self.timeout)
            if self.password:
                smb.login(self.username, self.password, self.domain)
            else:
                smb.login(
                    self.username, "", self.domain,
                    lmhash=self.lm_hash, nthash=self.nt_hash,
                )
            self.smb_conn = smb
            print("OK")
            return True
        except Exception as e:
            print(f"FAILED ({e})")
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
        # Treat as NT-only hash
        return "aad3b435b51404eeaad3b435b51404ee", hash_str
