import socket
import ssl
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from core.findings.rules.directory_security import analyze_protocol_security
from core.protocol_assessment import _ldaps_probe, _smb_negotiate, _tcp_probe, assess_protocols
from core.models import Severity


def _settings(use_ssl: bool = False, port: int | None = None) -> SimpleNamespace:
    return SimpleNamespace(use_ssl=use_ssl, effective_port=port or (636 if use_ssl else 389))


def test_tcp_probe_distinguishes_refused_timeout_and_reachable() -> None:
    sock = MagicMock()
    sock.__enter__.return_value = sock
    with patch("core.protocol_assessment.socket.create_connection", return_value=sock):
        assert _tcp_probe("192.0.2.1", 445, 1)["status"] == "Reachable"
    with patch("core.protocol_assessment.socket.create_connection", side_effect=ConnectionRefusedError):
        assert _tcp_probe("192.0.2.1", 445, 1)["status"] == "Connection refused"
    with patch("core.protocol_assessment.socket.create_connection", side_effect=socket.timeout):
        assert _tcp_probe("192.0.2.1", 445, 1)["status"] == "Timed out"


def test_ldaps_certificate_validation_failure_is_not_reported_as_secure() -> None:
    raw_socket = MagicMock()
    raw_socket.settimeout.return_value = None
    context = MagicMock()
    context.wrap_socket.side_effect = ssl.SSLCertVerificationError("hostname mismatch")
    with (
        patch("core.protocol_assessment.socket.create_connection", return_value=raw_socket),
        patch("core.protocol_assessment.ssl.create_default_context", return_value=context),
    ):
        result = _ldaps_probe("dc.example.test", "192.0.2.9", 636, 1)
    assert result["status"] == "Certificate validation failed"
    assert result["certificate_validation"] == "Failed"
    raw_socket.close.assert_called_once()


def test_ldaps_success_records_verified_certificate_and_negotiated_tls() -> None:
    raw_socket = MagicMock()
    raw_socket.settimeout.return_value = None
    tls_socket = MagicMock()
    tls_socket.__enter__.return_value = tls_socket
    tls_socket.getpeercert.return_value = {
        "subject": ((('commonName', 'dc.example.test'),),),
        "issuer": ((('commonName', 'Lab CA'),),),
        "notAfter": "Jan 01 00:00:00 2030 GMT",
    }
    tls_socket.version.return_value = "TLSv1.3"
    tls_socket.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    context = MagicMock()
    context.wrap_socket.return_value = tls_socket
    with (
        patch("core.protocol_assessment.socket.create_connection", return_value=raw_socket),
        patch("core.protocol_assessment.ssl.create_default_context", return_value=context),
    ):
        result = _ldaps_probe("dc.example.test", "192.0.2.9", 636, 1)
    assert result["status"] == "TLS verified"
    assert result["tls_version"] == "TLSv1.3"
    assert result["cipher"] == "TLS_AES_256_GCM_SHA384"
    context.wrap_socket.assert_called_once_with(raw_socket, server_hostname="dc.example.test")


def test_dns_unknown_does_not_attempt_protocol_connections() -> None:
    with patch("core.protocol_assessment._tcp_probe") as probe:
        result = assess_protocols("missing.example.test", None, _settings())
    probe.assert_not_called()
    assert result["protocol_assessment_status"] == "Partial"
    assert result["protocols"][0]["status"] == "Unresolved"


def test_custom_configured_tls_port_uses_certificate_validation() -> None:
    with (
        patch("core.protocol_assessment._ldaps_probe", return_value={"status": "TLS verified"}) as tls_probe,
        patch("core.protocol_assessment._tcp_probe", return_value={"status": "Connection refused", "error_type": "ConnectionRefusedError"}),
    ):
        result = assess_protocols(
            "dc.example.test", "192.0.2.9", _settings(use_ssl=True, port=1636), timeout=0.1
        )
    assert any(item["check"] == "Configured LDAP TLS" and item["port"] == 1636 for item in result["protocols"])
    tls_probe.assert_any_call("dc.example.test", "192.0.2.9", 1636, 0.1)


def test_protocol_results_keep_signing_and_channel_binding_unknown() -> None:
    with (
        patch("core.protocol_assessment._tcp_probe", return_value={"status": "Connection refused", "error_type": "ConnectionRefusedError"}),
        patch("core.protocol_assessment._ldaps_probe", return_value={"status": "Timed out", "error_type": "TimeoutError"}),
    ):
        result = assess_protocols("dc.example.test", "192.0.2.9", _settings(), timeout=0.1)
    by_check = {item["check"]: item for item in result["protocols"]}
    assert by_check["LDAP signing requirement"]["status"] == "Unknown"
    assert by_check["LDAP channel binding"]["status"] == "Unknown"
    assert by_check["SMB TCP/445"]["status"] == "Connection refused"
    assert by_check["SMB negotiation"]["status"].startswith("Not attempted")
    assert by_check["SMBv1"]["status"] == "Unknown"


def test_smb_negotiate_uses_no_session_credentials_and_cleans_up() -> None:
    connection = MagicMock()
    connection.dialect = 0x0311
    connection.server_security_mode = 0x0001
    connection.supports_encryption = True
    with patch("smbprotocol.connection.Connection", return_value=connection) as connection_type:
        result = _smb_negotiate("192.0.2.9", 0.5)

    assert result["status"] == "Negotiated"
    assert result["dialect"] == "SMB 3.1.1"
    assert result["signing_supported"] is True
    assert result["signing_required"] is False
    assert result["encryption_supported"] is True
    connection_type.assert_called_once()
    assert connection_type.call_args.kwargs["require_signing"] is False
    connection.connect.assert_called_once_with(timeout=0.5)
    connection.disconnect.assert_called_once()


def test_smb_negotiation_findings_use_server_response_only() -> None:
    protocols = [
        {"check": "Configured LDAP client transport", "status": "Plain LDAP configured", "port": 389},
        {"check": "SMB negotiation", "status": "Negotiated", "dialect": "SMB 3.1.1", "signing_supported": True, "signing_required": False, "encryption_supported": True, "target_ip": "192.0.2.9"},
        {"check": "LDAP signing requirement", "status": "Unknown"},
    ]
    findings = analyze_protocol_security({"protocols": protocols})
    assert [finding.title for finding in findings] == ["Configured LDAP connection is not TLS protected", "SMB signing is supported but not required"]
    assert all(finding.category == "Protocol Security" for finding in findings)
    assert findings[0].severity == Severity.INFO
    assert findings[1].severity == Severity.MEDIUM
    assert all(finding.evidence["evidence_source"] for finding in findings)


def test_cancellation_avoids_later_protocol_probes() -> None:
    from threading import Event
    event = Event()
    event.set()
    with patch("core.protocol_assessment._tcp_probe") as probe:
        result = assess_protocols("dc.example.test", "192.0.2.9", _settings(), cancellation_event=event)
    probe.assert_not_called()
    assert result["protocol_assessment_status"] == "Cancelled"