"""Read-only Active Directory LDAP connection management."""

import logging
import ipaddress
import socket
from collections.abc import Callable
from dataclasses import dataclass

from ldap3 import ALL, NTLM, AUTO_BIND_NO_TLS, Connection, Server
from ldap3.core.exceptions import LDAPException, LDAPSocketOpenError

from config.settings import ConnectionSettings

logger = logging.getLogger(__name__)


class ADConnectionError(RuntimeError):
    """Raised when an LDAP connection or directory query cannot complete."""


@dataclass(frozen=True, slots=True)
class ConnectionTestResult:
    """Credential-free result of an LDAP connection test."""

    success: bool
    server: str
    message: str
    base_dn: str | None = None
    error_type: str | None = None
    resolved_ip: str | None = None
    ldap_reachable: bool = False
    diagnostic: str | None = None

    def as_dict(self) -> dict[str, str | bool | None]:
        """Return a serialization-friendly result without credentials."""
        return {
            "success": self.success,
            "server": self.server,
            "message": self.message,
            "base_dn": self.base_dn,
            "error_type": self.error_type,
            "resolved_ip": self.resolved_ip,
            "ldap_reachable": self.ldap_reachable,
            "diagnostic": self.diagnostic,
        }

    def as_diagnostics(self) -> dict[str, str]:
        """Return a concise connection diagnostic summary for the UI."""
        return {
            "hostname": self.server,
            "resolved_ip": self.resolved_ip or "Not resolved",
            "ldap": "Reachable" if self.ldap_reachable else "Unreachable",
            "result": "Success" if self.success else "Failure",
        }


class LDAPConnectionManager:
    """Manage one authenticated, read-only LDAP session."""

    def __init__(self, settings: ConnectionSettings, timeout: float = 10.0) -> None:
        if timeout <= 0:
            raise ValueError("LDAP timeout must be greater than zero")
        self.settings = settings
        self.timeout = timeout
        self._connection: Connection | None = None

    @property
    def connection(self) -> Connection:
        """Return the bound connection or raise a clear backend error."""
        if self._connection is None or not self._connection.bound:
            raise ADConnectionError("LDAP connection is not established")
        return self._connection

    def connect(
        self,
        on_resolved: Callable[[str, str], None] | None = None,
    ) -> ConnectionTestResult:
        """Create and bind an AD connection using runtime-only credentials."""
        self.disconnect()
        hostname = self.settings.server
        try:
            resolved_ip = self._resolve_server_address()
        except socket.gaierror as exc:
            diagnostic = self._exception_detail(exc, self.settings.password)
            logger.warning(
                "Domain controller hostname resolution failed",
                extra={"server": hostname, "error_type": type(exc).__name__},
            )
            return ConnectionTestResult(
                False,
                hostname,
                "Unable to resolve domain controller hostname.\n"
                f"Hostname: {hostname}\n"
                "Check DNS configuration and ensure this system uses the AD DNS server.",
                error_type=type(exc).__name__,
                diagnostic=diagnostic,
            )

        is_hostname = not self._is_ip_address(hostname)
        if is_hostname:
            logger.info("%s resolved to %s", hostname, resolved_ip)
            if on_resolved:
                on_resolved(hostname, resolved_ip)

        try:
            server = Server(
                resolved_ip,
                port=self.settings.effective_port,
                use_ssl=self.settings.use_ssl,
                connect_timeout=self.timeout,
                get_info=ALL,
            )
            self._connection = Connection(
                server,
                user=f"{self.settings.domain}\\{self.settings.username}",
                password=self.settings.password,
                authentication=NTLM,
                auto_bind=AUTO_BIND_NO_TLS,
                receive_timeout=self.timeout,
                raise_exceptions=True,
            )
            logger.info(
                "LDAP bind succeeded",
                extra={"server": hostname, "resolved_ip": resolved_ip},
            )
            return ConnectionTestResult(
                True,
                hostname,
                "LDAP authentication succeeded",
                resolved_ip=resolved_ip,
                ldap_reachable=True,
            )
        except Exception as exc:
            self._connection = None
            diagnostic = self._exception_detail(exc, self.settings.password)
            logger.warning(
                "LDAP bind failed",
                extra={
                    "server": hostname,
                    "resolved_ip": resolved_ip,
                    "error_type": type(exc).__name__,
                },
            )
            if is_hostname:
                message = (
                    "Hostname resolved successfully, but LDAP connection failed.\n"
                    f"Resolved IP: {resolved_ip}\n"
                    f"Diagnostic: {diagnostic}"
                )
            else:
                message = self._safe_error_message(exc, self.settings.password)
            return ConnectionTestResult(
                False,
                hostname,
                message,
                error_type=type(exc).__name__,
                resolved_ip=resolved_ip,
                ldap_reachable=not isinstance(
                    exc, (TimeoutError, LDAPSocketOpenError, OSError, ConnectionError)
                ),
                diagnostic=diagnostic,
            )

    def _resolve_server_address(self) -> str:
        """Resolve hostnames through the system resolver, preserving literal IPs."""
        host = self.settings.server
        if self._is_ip_address(host):
            return host
        addresses = socket.getaddrinfo(
            host,
            self.settings.effective_port,
            type=socket.SOCK_STREAM,
        )
        if not addresses:
            raise socket.gaierror(socket.EAI_NONAME, "No addresses returned")
        ipv4 = next((item[4][0] for item in addresses if item[0] == socket.AF_INET), None)
        return ipv4 or addresses[0][4][0]

    @staticmethod
    def _is_ip_address(value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def test_connection(self) -> ConnectionTestResult:
        """Bind, discover the Base DN, and close the test connection."""
        result = self.connect()
        if not result.success:
            return result
        try:
            base_dn = self.get_base_dn()
            return ConnectionTestResult(
                True,
                self.settings.server,
                "LDAP authentication succeeded",
                base_dn=base_dn,
                resolved_ip=result.resolved_ip,
                ldap_reachable=True,
            )
        except Exception as exc:
            logger.warning(
                "LDAP Base DN discovery failed",
                extra={"server": self.settings.server, "error_type": type(exc).__name__},
            )
            return ConnectionTestResult(
                False,
                self.settings.server,
                "LDAP connected, but Base DN discovery failed.",
                error_type=type(exc).__name__,
                resolved_ip=result.resolved_ip,
                ldap_reachable=True,
                diagnostic=self._exception_detail(exc, self.settings.password),
            )
        finally:
            self.disconnect()

    def get_base_dn(self) -> str:
        """Read the directory naming context from the RootDSE."""
        connection = self.connection
        server_info = connection.server.info
        other = getattr(server_info, "other", {}) or {}
        naming_context = other.get("defaultNamingContext")
        if isinstance(naming_context, (list, tuple)):
            naming_context = naming_context[0] if naming_context else None
        if naming_context:
            return str(naming_context)

        if connection.search(
            search_base="",
            search_filter="(objectClass=*)",
            search_scope="BASE",
            attributes=["defaultNamingContext"],
        ):
            value = connection.entries[0].entry_attributes_as_dict.get("defaultNamingContext")
            if isinstance(value, (list, tuple)):
                value = value[0] if value else None
            if value:
                return str(value)
        raise ADConnectionError("The directory did not provide a default naming context")

    def disconnect(self) -> None:
        """Unbind and discard the in-memory connection reference."""
        if self._connection is not None:
            try:
                self._connection.unbind()
            except Exception:
                logger.debug("LDAP unbind failed", extra={"server": self.settings.server})
            finally:
                self._connection = None

    @staticmethod
    def _exception_detail(error: Exception, password: str = "") -> str:
        detail = str(error)
        if password:
            detail = detail.replace(password, "[redacted]")
        return f"{type(error).__name__}: {detail or 'No additional details'}"

    @staticmethod
    def _safe_error_message(error: Exception, password: str = "") -> str:
        """Map backend failures to useful messages without exposing secrets."""
        if isinstance(error, TimeoutError):
            return "LDAP connection timed out. Check the domain controller and network access."
        if isinstance(error, (LDAPSocketOpenError, OSError, ConnectionError)):
            return "The domain controller is unreachable. Check the hostname and network access."
        if isinstance(error, LDAPException):
            return "LDAP authentication failed. Check the domain and credentials."
        if isinstance(error, ValueError):
            detail = str(error)
            if password:
                detail = detail.replace(password, "[redacted]")
            if detail:
                return f"LDAP connection failed: {detail}"
        return "LDAP connection failed. Check the server, credentials, and network access."