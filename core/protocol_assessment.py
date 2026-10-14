"""Bounded transport and protocol observations without user authentication."""

import ipaddress
import logging
import socket
import ssl
import uuid
from typing import Any

logger = logging.getLogger(__name__)

SMB_DIALECT_NAMES = {
    0x0202: "SMB 2.0.2", 0x0210: "SMB 2.1", 0x0300: "SMB 3.0",
    0x0302: "SMB 3.0.2", 0x0311: "SMB 3.1.1",
}


def _status_for_socket_error(error: OSError) -> str:
    if isinstance(error, (socket.timeout, TimeoutError)):
        return "Timed out"
    if isinstance(error, ConnectionRefusedError):
        return "Connection refused"
    return "Unreachable"


def _tcp_probe(host: str, port: int, timeout: float) -> dict[str, Any]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return {"status": "Reachable", "error_type": None}
    except OSError as exc:
        return {"status": _status_for_socket_error(exc), "error_type": type(exc).__name__}


def _ldaps_probe(hostname: str, address: str, port: int, timeout: float) -> dict[str, Any]:
    sock: socket.socket | None = None
    try:
        context = ssl.create_default_context()
        sock = socket.create_connection((address, port), timeout=timeout)
        sock.settimeout(timeout)
        with context.wrap_socket(sock, server_hostname=hostname) as tls_socket:
            sock = None
            certificate = tls_socket.getpeercert()
            return {
                "status": "TLS verified",
                "certificate_validation": "Valid under system trust and host-name checks",
                "tls_version": tls_socket.version(),
                "cipher": tls_socket.cipher()[0] if tls_socket.cipher() else None,
                "certificate_subject": certificate.get("subject", ()),
                "certificate_issuer": certificate.get("issuer", ()),
                "certificate_not_after": certificate.get("notAfter"),
                "error_type": None,
            }
    except ssl.SSLCertVerificationError as exc:
        return {
            "status": "Certificate validation failed",
            "certificate_validation": "Failed",
            "error_type": type(exc).__name__,
        }
    except (OSError, ssl.SSLError) as exc:
        return {
            "status": _status_for_socket_error(exc) if isinstance(exc, OSError) else "TLS handshake failed",
            "certificate_validation": "Unknown",
            "error_type": type(exc).__name__,
        }
    finally:
        if sock is not None:
            sock.close()


def _smb_negotiate(address: str, timeout: float) -> dict[str, Any]:
    connection = None
    try:
        from smbprotocol.connection import Capabilities, Connection, SecurityMode

        connection = Connection(uuid.uuid4(), address, 445, require_signing=False)
        connection.connect(timeout=timeout)
        server_security = int(connection.server_security_mode or 0)
        signing_enabled = bool(server_security & SecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED)
        signing_required = bool(server_security & SecurityMode.SMB2_NEGOTIATE_SIGNING_REQUIRED)
        encryption = connection.supports_encryption
        if encryption is None and connection.server_capabilities is not None:
            encryption = connection.server_capabilities.has_flag(Capabilities.SMB2_GLOBAL_CAP_ENCRYPTION)
        return {
            "status": "Negotiated",
            "dialect": SMB_DIALECT_NAMES.get(connection.dialect, f"Unknown dialect 0x{connection.dialect:04x}"),
            "dialect_value": connection.dialect,
            "signing_supported": signing_enabled or signing_required,
            "signing_required": signing_required,
            "encryption_supported": encryption,
            "encryption_negotiated": False,
            "evidence_source": "Unauthenticated SMB2/SMB3 NEGOTIATE response",
            "error_type": None,
        }
    except ImportError:
        return {"status": "Unsupported: smbprotocol is not installed", "error_type": "ImportError"}
    except (OSError, TimeoutError) as exc:
        return {"status": _status_for_socket_error(exc), "error_type": type(exc).__name__}
    except Exception as exc:
        logger.info("SMB negotiation did not complete", extra={"error_type": type(exc).__name__})
        return {"status": "Negotiation failed", "error_type": type(exc).__name__}
    finally:
        if connection is not None:
            try:
                connection.disconnect()
            except Exception:
                logger.debug("SMB negotiation cleanup failed")


def assess_protocols(
    hostname: str,
    resolved_ip: str | None,
    settings: Any,
    gpos: list[dict[str, Any]] | None = None,
    cancellation_event: Any = None,
    timeout: float = 3.0,
) -> dict[str, Any]:
    """Observe configured LDAP transport, LDAP TLS, and SMB negotiation only."""
    if timeout <= 0:
        raise ValueError("Protocol timeout must be greater than zero")
    target = resolved_ip or hostname
    records: list[dict[str, Any]] = []
    if not resolved_ip and not _is_ip(hostname):
        records.append({
            "check": "Domain controller DNS", "status": "Unresolved",
            "target_hostname": hostname, "target_ip": None,
            "evidence_source": "Existing LDAP connection result",
        })
        return {"protocols": records, "protocol_assessment_status": "Partial"}
    records.append({
        "check": "Domain controller DNS", "status": "Resolved" if not _is_ip(hostname) else "IP target",
        "target_hostname": hostname, "target_ip": target,
        "evidence_source": "Existing LDAP connection result",
    })
    actual_ssl = bool(getattr(settings, "use_ssl", False))
    actual_port = int(getattr(settings, "effective_port", 636 if actual_ssl else 389))
    records.append({
        "check": "Configured LDAP client transport",
        "status": "TLS configured" if actual_ssl else "Plain LDAP configured",
        "port": actual_port,
        "target_hostname": hostname,
        "target_ip": target,
        "evidence_source": "Client connection settings; does not describe server-side signing policy",
    })
    records.extend((
        {
            "check": "LDAP signing requirement", "status": "Unknown",
            "observed": None,
            "limitation": "A successful bind or TCP probe does not establish the server signing requirement; no test credentials were sent.",
            "evidence_source": "Not observable through the current client connection",
        },
        {
            "check": "LDAP channel binding", "status": "Unknown",
            "observed": None,
            "limitation": "Server channel-binding policy is not exposed by the current LDAP connection metadata.",
            "evidence_source": "Not observable through the current client connection",
        },
        {
            "check": "LDAP StartTLS", "status": "Not tested",
            "limitation": "No unauthenticated StartTLS extended request was made.",
            "evidence_source": "Not observed",
        },
    ))
    if cancellation_event is not None and cancellation_event.is_set():
        return {"protocols": records, "protocol_assessment_status": "Cancelled"}

    port_map = {389: "LDAP TCP/389", 636: "LDAPS TLS/636"}
    port_map[actual_port] = "Configured LDAP TLS" if actual_ssl else "Configured LDAP port"
    for port, label in port_map.items():
        if cancellation_event is not None and cancellation_event.is_set():
            return {"protocols": records, "protocol_assessment_status": "Partial"}
        if port == 636 or (actual_ssl and port == actual_port):
            outcome = _ldaps_probe(hostname, target, port, timeout)
            records.append({
                "check": label, "port": port, "target_hostname": hostname,
                "target_ip": target, "evidence_source": "Verified TLS handshake",
                **outcome,
            })
        else:
            records.append({
                "check": label, "port": port, "target_hostname": hostname,
                "target_ip": target, "evidence_source": "Unauthenticated TCP connection",
                **_tcp_probe(target, port, timeout),
            })

    if cancellation_event is not None and cancellation_event.is_set():
        return {"protocols": records, "protocol_assessment_status": "Partial"}
    smb_port = _tcp_probe(target, 445, timeout)
    records.append({
        "check": "SMB TCP/445", "port": 445, "target_hostname": hostname,
        "target_ip": target, "evidence_source": "Unauthenticated TCP connection", **smb_port,
    })
    if cancellation_event is not None and cancellation_event.is_set():
        return {"protocols": records, "protocol_assessment_status": "Partial"}
    if smb_port["status"] == "Reachable":
        records.append({
            "check": "SMB negotiation", "port": 445, "target_hostname": hostname,
            "target_ip": target, "evidence_source": "SMB2/SMB3 negotiate response",
            **_smb_negotiate(target, timeout),
        })
    else:
        records.append({
            "check": "SMB negotiation", "port": 445, "target_hostname": hostname,
            "target_ip": target, "status": "Not attempted: SMB TCP is not reachable",
            "evidence_source": "TCP check",
        })
    records.append({
        "check": "SMBv1", "status": "Unknown",
        "limitation": "No SMBv1-only negotiation or downgrade probe was attempted.",
        "evidence_source": "Not probed",
    })
    gpo_statuses = [str(gpo.get("content_status", "Not assessed")) for gpo in (gpos or [])]
    records.append({
        "check": "SYSVOL read under process identity",
        "status": _sysvol_status(gpo_statuses),
        "evidence_source": "Existing bounded GPO content reads",
        "limitation": "NETLOGON was not accessed; failed SYSVOL paths may not distinguish authentication, share, or file errors.",
    })
    records.append({
        "check": "NETLOGON share access", "status": "Not tested",
        "evidence_source": "No share session or file access attempted",
    })
    return {"protocols": records, "protocol_assessment_status": "Completed"}


def _sysvol_status(statuses: list[str]) -> str:
    if not statuses:
        return "Not assessed: no GPO content paths"
    if any(status == "Assessed successfully" for status in statuses):
        return "Read access observed for at least one GPO path"
    if all(status == "Inaccessible" for status in statuses):
        return "No GPO path was readable; reason may be unavailable"
    return "Partial or failed GPO content access"


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False