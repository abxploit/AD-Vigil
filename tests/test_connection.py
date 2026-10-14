"""Mocked tests for the Active Directory LDAP connection manager."""

import socket
from unittest.mock import MagicMock, patch

from ldap3.core.exceptions import LDAPSocketOpenError

from config.settings import ConnectionSettings
from core.ldap_connection import LDAPConnectionManager


def _settings(server: str = "192.0.2.10") -> ConnectionSettings:
    return ConnectionSettings(server, "EXAMPLE", "analyst", "secret")


def _bound_connection(connection_class: MagicMock, server_class: MagicMock) -> MagicMock:
    server = server_class.return_value
    server.info.other = {"defaultNamingContext": ["DC=example,DC=local"]}
    connection = connection_class.return_value
    connection.bound = True
    connection.server = server
    return connection


@patch("core.ldap_connection.Connection")
@patch("core.ldap_connection.Server")
def test_successful_connection_discovers_base_dn(
    server_class: MagicMock, connection_class: MagicMock
) -> None:
    connection = _bound_connection(connection_class, server_class)
    result = LDAPConnectionManager(_settings(), timeout=3).test_connection()

    assert result.success is True
    assert result.base_dn == "DC=example,DC=local"
    assert result.as_dict()["error_type"] is None
    assert connection_class.call_args.kwargs["authentication"]
    assert connection_class.call_args.kwargs["password"] == "secret"
    assert "secret" not in str(result.as_dict())
    connection.unbind.assert_called_once()


@patch("core.ldap_connection.Connection", side_effect=RuntimeError("invalid credentials"))
@patch("core.ldap_connection.Server")
def test_invalid_credentials_return_sanitized_error(
    server_class: MagicMock, connection_class: MagicMock
) -> None:
    result = LDAPConnectionManager(_settings()).test_connection()

    assert result.success is False
    assert result.error_type == "RuntimeError"
    assert "invalid credentials" not in result.message
    assert "secret" not in str(result.as_dict())


@patch("core.ldap_connection.Connection", side_effect=TimeoutError)
@patch("core.ldap_connection.Server")
def test_timeout_returns_useful_error(server_class: MagicMock, connection_class: MagicMock) -> None:
    result = LDAPConnectionManager(_settings()).test_connection()

    assert result.success is False
    assert "timed out" in result.message


@patch("core.ldap_connection.Connection", side_effect=OSError("host unreachable"))
@patch("core.ldap_connection.Server")
def test_unreachable_server_returns_useful_error(
    server_class: MagicMock, connection_class: MagicMock
) -> None:
    result = LDAPConnectionManager(_settings()).test_connection()

    assert result.success is False
    assert "unreachable" in result.message


@patch("core.ldap_connection.Connection", side_effect=ValueError("invalid value: secret"))
@patch("core.ldap_connection.Server")
def test_value_error_detail_redacts_password(
    server_class: MagicMock, connection_class: MagicMock
) -> None:
    result = LDAPConnectionManager(_settings()).test_connection()

    assert result.success is False
    assert "invalid value" in result.message
    assert "secret" not in result.message


@patch("core.ldap_connection.Connection")
@patch("core.ldap_connection.Server")
def test_base_dn_can_be_discovered_from_rootdse(
    server_class: MagicMock, connection_class: MagicMock
) -> None:
    connection = _bound_connection(connection_class, server_class)
    connection.server.info.other = {}
    connection.search.return_value = True
    entry = MagicMock()
    entry.entry_attributes_as_dict = {"defaultNamingContext": ["DC=lab,DC=local"]}
    connection.entries = [entry]

    result = LDAPConnectionManager(_settings()).test_connection()

    assert result.success is True
    assert result.base_dn == "DC=lab,DC=local"
    connection.search.assert_called_once()


def test_ip_address_connects_directly_without_dns_resolution() -> None:
    with (
        patch("core.ldap_connection.Connection") as connection_class,
        patch("core.ldap_connection.Server") as server_class,
        patch("core.ldap_connection.socket.getaddrinfo") as resolver,
    ):
        _bound_connection(connection_class, server_class)
        result = LDAPConnectionManager(_settings("192.168.56.10")).connect()

    assert result.success is True
    assert result.server == "192.168.56.10"
    assert result.resolved_ip == "192.168.56.10"
    assert server_class.call_args.args[0] == "192.168.56.10"
    resolver.assert_not_called()


def test_hostname_resolves_and_connects_to_address_while_preserving_domain() -> None:
    host = "dc01.windomain.local"
    resolved_ip = "192.168.56.10"
    resolved_events: list[tuple[str, str]] = []
    with (
        patch("core.ldap_connection.Connection") as connection_class,
        patch("core.ldap_connection.Server") as server_class,
        patch("core.ldap_connection.socket.getaddrinfo") as resolver,
    ):
        _bound_connection(connection_class, server_class)
        resolver.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (resolved_ip, 389))
        ]
        settings = ConnectionSettings(host, "WINDOMAIN", "analyst", "secret")
        result = LDAPConnectionManager(settings).connect(
            lambda hostname, address: resolved_events.append((hostname, address))
        )

    assert result.success is True
    assert result.server == host
    assert result.resolved_ip == resolved_ip
    assert server_class.call_args.args[0] == resolved_ip
    assert connection_class.call_args.kwargs["user"] == "WINDOMAIN\\analyst"
    assert resolved_events == [(host, resolved_ip)]
    resolver.assert_called_once_with(host, 389, type=socket.SOCK_STREAM)


def test_dns_failure_reports_hostname_and_dns_guidance_without_ldap_attempt() -> None:
    host = "dc01.windomain.local"
    with (
        patch("core.ldap_connection.Connection") as connection_class,
        patch("core.ldap_connection.Server") as server_class,
        patch(
            "core.ldap_connection.socket.getaddrinfo",
            side_effect=socket.gaierror(socket.EAI_NONAME, "name not found"),
        ),
    ):
        result = LDAPConnectionManager(
            ConnectionSettings(host, "WINDOMAIN", "analyst", "secret")
        ).connect()

    assert result.success is False
    assert result.resolved_ip is None
    assert "Unable to resolve domain controller hostname." in result.message
    assert f"Hostname: {host}" in result.message
    assert "AD DNS server" in result.message
    assert result.as_diagnostics()["ldap"] == "Unreachable"
    server_class.assert_not_called()
    connection_class.assert_not_called()


def test_resolved_hostname_ldap_failure_includes_ip_and_actual_exception() -> None:
    host = "dc01.windomain.local"
    resolved_ip = "192.168.56.10"
    with (
        patch(
            "core.ldap_connection.Connection",
            side_effect=LDAPSocketOpenError("connection refused"),
        ),
        patch("core.ldap_connection.Server") as server_class,
        patch("core.ldap_connection.socket.getaddrinfo") as resolver,
    ):
        resolver.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (resolved_ip, 389))
        ]
        result = LDAPConnectionManager(
            ConnectionSettings(host, "WINDOMAIN", "analyst", "secret")
        ).connect()

    assert result.success is False
    assert server_class.call_args.args[0] == resolved_ip
    assert "Hostname resolved successfully, but LDAP connection failed." in result.message
    assert f"Resolved IP: {resolved_ip}" in result.message
    assert "LDAPSocketOpenError: connection refused" in result.message
    assert result.as_diagnostics()["ldap"] == "Unreachable"