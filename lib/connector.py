"""
lib/connector.py - ADScan Connection Manager

Manages LDAP, LDAPS, and SMB connections to a Domain Controller.
Supports password, NTLM hash (pass-the-hash), and Kerberos (ccache) auth.
"""
import atexit
import os
import logging
import socket
import ssl
import struct
import hashlib
import binascii
import tempfile
from datetime import datetime

# Optional imports - graceful degradation if libraries are not installed
try:
    import ldap3
    from ldap3 import Server, Connection, ALL, NTLM, SIMPLE, SASL, GSSAPI, Tls, SUBTREE, BASE, LEVEL
    from ldap3.core.exceptions import LDAPException
    from ldap3.utils.conv import escape_filter_chars as _escape_filter
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


def _safe_unlink(path):
    """Best-effort file deletion; swallow errors (atexit must not raise)."""
    try:
        os.unlink(path)
    except OSError:
        pass


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
        """Attempt connections for each configured protocol.

        Before making authenticated connections, probes the DC to detect
        whether LDAP signing and/or LDAPS channel binding are enforced,
        then applies the appropriate ldap3 parameters automatically.
        """
        # When using Kerberos, make sure libkrb5 has a usable default realm.
        # If the system krb5.conf is missing or has no default_realm, we
        # synthesize one from the connector's domain + dc_host.
        self._ensure_krb5_config()

        connected = False

        # ── Probe DC security requirements (1-2 second overhead) ──────────
        needs_ldap  = any(p in ("ldap", "ldaps") for p in self.protocols)
        if needs_ldap and HAS_LDAP3:
            self._log.info(" [*] Probing DC for LDAP signing / channel binding requirements...")
            reqs = self._probe_dc_requirements()
        else:
            reqs = {
                "requires_signing":         False,
                "requires_channel_binding": False,
                "ldap_available":           False,
                "ldaps_available":          False,
            }

        for proto in self.protocols:
            if proto in ("ldap", "ldaps"):
                if not HAS_LDAP3:
                    self._log.warning(" [WARN] ldap3 not installed - skipping %s. Run: pip install ldap3", proto.upper())
                    continue
                if self._connect_ldap(
                    use_ssl=(proto == "ldaps"),
                    requires_signing=reqs["requires_signing"],
                    requires_channel_binding=reqs["requires_channel_binding"],
                ):
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
                search_filter=f"(objectSid={_escape_filter(str(sid_str))})",
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

    def _ensure_krb5_config(self):
        """Synthesize a temp krb5.conf when Kerberos is in use and the system
        config is missing or lacks default_realm.

        Reads the file pointed to by KRB5_CONFIG (or /etc/krb5.conf if unset).
        If it already declares a non-empty `default_realm` we leave the
        environment alone. Otherwise we write a minimal config using the
        connector's own domain (uppercased as the realm) and dc_host as the
        KDC, set KRB5_CONFIG to point at it, and register an atexit cleanup.
        """
        if not self.use_kerberos:
            return

        existing = os.environ.get("KRB5_CONFIG", "/etc/krb5.conf")
        try:
            with open(existing, "r", encoding="utf-8") as fh:
                for line in fh:
                    s = line.strip()
                    if s.startswith("#") or s.startswith(";"):
                        continue
                    if s.lower().startswith("default_realm") and "=" in s:
                        if s.split("=", 1)[1].strip():
                            self._log.debug(
                                "  [krb5] %s already specifies default_realm — leaving as-is",
                                existing,
                            )
                            return
        except (FileNotFoundError, PermissionError, OSError) as exc:
            self._log.debug("  [krb5] could not read %s: %s", existing, exc)

        if not self.domain or not self.dc_host:
            self._log.warning(
                " [WARN] --kerberos used but cannot synthesize krb5.conf "
                "(missing domain or dc_host). Bind will likely fail.",
            )
            return

        realm = self.domain.upper()
        kdc   = self.dc_host
        body  = (
            "[libdefaults]\n"
            f"    default_realm = {realm}\n"
            "    dns_lookup_realm = false\n"
            "    dns_lookup_kdc = false\n"
            "    rdns = false\n"
            "    udp_preference_limit = 1\n"
            "    forwardable = true\n"
            "\n"
            "[realms]\n"
            f"    {realm} = {{\n"
            f"        kdc = {kdc}\n"
            f"        admin_server = {kdc}\n"
            "    }\n"
            "\n"
            "[domain_realm]\n"
            f"    .{self.domain} = {realm}\n"
            f"    {self.domain} = {realm}\n"
        )

        fd, path = tempfile.mkstemp(prefix="adscan_krb5_", suffix=".conf")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(body)
        except Exception as exc:
            self._log.warning(" [WARN] failed to write synthesized krb5.conf: %s", exc)
            try:
                os.unlink(path)
            except OSError:
                pass
            return

        os.environ["KRB5_CONFIG"] = path
        atexit.register(_safe_unlink, path)
        self._log.info(
            "  [krb5] synthesized config -> %s (realm=%s, kdc=%s)",
            path, realm, kdc,
        )

    def _probe_dc_requirements(self):
        """Probe the DC to detect whether LDAP signing and/or LDAPS channel
        binding are enforced, before attempting a full authenticated bind.

        Returns a dict:
            {
                "requires_signing":          bool,  # plain LDAP signing enforced
                "requires_channel_binding":  bool,  # LDAPS CBT enforced
                "ldap_available":            bool,  # port 389 reachable
                "ldaps_available":           bool,  # port 636 reachable
            }

        Detection method:
            - Plain LDAP: anonymous simple bind -> result code 8
              (strongerAuthRequired) means signing is required.
            - LDAPS: NTLM bind without CBT -> extended error 80090346
              (SEC_E_BAD_BINDINGS) means channel binding is required.
        """
        result = {
            "requires_signing":         False,
            "requires_channel_binding": False,
            "ldap_available":           False,
            "ldaps_available":          False,
        }

        if not HAS_LDAP3:
            return result

        # ── Probe 1: plain LDAP signing requirement (port 389) ──────────────
        try:
            srv = Server(
                self.dc_host, port=389, use_ssl=False,
                get_info=ALL, connect_timeout=max(5, self.timeout // 3),
            )
            # Anonymous simple bind — DC will reject with result 8 if signing required
            probe = Connection(srv, authentication=SIMPLE, auto_bind=False)
            probe.open()
            probe.bind()
            result["ldap_available"] = True
            rc = probe.result.get("result", 0)
            desc = (probe.result.get("description") or "").lower()
            err  = (probe.result.get("message") or "").lower()
            # Result 8 = strongerAuthRequired; also check description text
            if rc == 8 or "strongerauthrequ" in desc or "stronger" in err:
                result["requires_signing"] = True
                self._log.info(
                    "  [probe] LDAP signing is REQUIRED on %s (result code %s)",
                    self.dc_host, rc,
                )
            else:
                self._log.info(
                    "  [probe] LDAP signing is NOT enforced on %s", self.dc_host
                )
            try:
                probe.unbind()
            except Exception:
                pass
        except Exception as e:
            self._log.debug("  [probe] LDAP signing probe failed: %s", e)

        # ── Probe 2: LDAPS channel binding requirement (port 636) ───────────
        try:
            tls = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLS)
            srv = Server(
                self.dc_host, port=636, use_ssl=True, tls=tls,
                get_info=ALL, connect_timeout=max(5, self.timeout // 3),
            )
            # NTLM bind without channel binding token — DC returns 80090346
            # (SEC_E_BAD_BINDINGS) in the extended error if CBT is enforced.
            user = f"{self.domain}\\{self.username}"
            pwd  = self.password if self.password else f"{self.lm_hash}:{self.nt_hash}"
            probe = Connection(
                srv, user=user, password=pwd,
                authentication=NTLM, auto_bind=False,
            )
            probe.open()
            probe.bind()
            result["ldaps_available"] = True
            rc  = probe.result.get("result", 0)
            msg = (probe.result.get("message") or "").lower()
            # 80090346 = SEC_E_BAD_BINDINGS — channel binding mismatch
            if rc != 0 and ("80090346" in msg or "bad bindings" in msg or "channel binding" in msg):
                result["requires_channel_binding"] = True
                self._log.info(
                    "  [probe] LDAPS channel binding is REQUIRED on %s", self.dc_host
                )
            elif rc == 0:
                self._log.info(
                    "  [probe] LDAPS channel binding is NOT enforced on %s", self.dc_host
                )
            try:
                probe.unbind()
            except Exception:
                pass
        except Exception as e:
            self._log.debug("  [probe] LDAPS channel binding probe failed: %s", e)

        return result

    def _connect_ldap(self, use_ssl=False, requires_signing=False, requires_channel_binding=False):
        proto_label = "LDAPS" if use_ssl else "LDAP"
        port = 636 if use_ssl else 389
        self._log.info(" [*] Connecting via %s to %s:%s ...", proto_label, self.dc_host, port)

        if requires_signing and not use_ssl:
            self._log.info("  [*] LDAP signing required — applying NTLM session encryption (ENCRYPT)")
        if requires_channel_binding and use_ssl:
            self._log.info("  [*] LDAPS channel binding required — attempting CBT-aware bind")

        try:
            tls = None
            if use_ssl:
                tls = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLS)

            server = Server(
                self.dc_host,
                port=port,
                use_ssl=use_ssl,
                tls=tls,
                get_info=ALL,
                connect_timeout=self.timeout,
            )

            if self.use_kerberos:
                # Kerberos (GSSAPI) inherently satisfies signing and channel binding.
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
                    auto_bind=False,
                )
                conn.open()
                conn.bind()
            else:
                user = f"{self.domain}\\{self.username}"
                pwd = self.password if self.password else f"{self.lm_hash}:{self.nt_hash}"
                conn_kwargs = dict(
                    user=user,
                    password=pwd,
                    authentication=NTLM,
                    auto_bind=False,
                )
                # When plain LDAP signing is enforced, ldap3.ENCRYPT (sign+seal) satisfies
                # the Windows "require integrity" policy (LDAP_SERVER_REQUIRE_SIGNING).
                if requires_signing and not use_ssl:
                    conn_kwargs["session_security"] = ldap3.ENCRYPT
                # When LDAPS channel binding is enforced (error 80090346), we need to pass
                # a TLS channel binding token. ldap3 >= 2.10.x exposes this as
                # ldap3.TLS_CHANNEL_BINDING. On older ldap3 (2.9.x) the attribute does not
                # exist; we catch that and emit a clear upgrade message.
                if requires_channel_binding and use_ssl:
                    _cbt = getattr(ldap3, "TLS_CHANNEL_BINDING", None)
                    if _cbt is not None:
                        conn_kwargs["channel_binding"] = _cbt
                    else:
                        self._log.warning(
                            " [!] LDAPS channel binding (80090346) is enforced but your ldap3"
                            " version does not support it. Upgrade with:"
                            " pip install 'ldap3>=2.10.0rc1'"
                        )
                conn = Connection(server, **conn_kwargs)
                conn.open()
                conn.bind()

            if not conn.bound:
                rc  = conn.result.get("result", -1) if conn.result else -1
                desc = conn.result.get("description", "unknown") if conn.result else "unknown"
                msg  = conn.result.get("message", "") if conn.result else ""
                self._log.warning(
                    " [!] %s bind to %s:%s failed: %s %s",
                    proto_label, self.dc_host, port, desc, msg,
                )
                # Special hint for 80090346 (channel binding required, ldap3 too old)
                if use_ssl and "80090346" in msg:
                    self._log.warning(
                        " [!] Hint: DC requires LDAPS channel binding. Upgrade ldap3:"
                        " pip install 'ldap3>=2.10.0rc1'"
                    )
                try:
                    conn.unbind()
                except Exception:
                    pass
                return False

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
