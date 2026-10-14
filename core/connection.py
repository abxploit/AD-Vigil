"""Backward-compatible imports for the LDAP connection manager."""

from core.ldap_connection import (
    ADConnectionError,
    ConnectionTestResult,
    LDAPConnectionManager,
)

ADConnectionManager = LDAPConnectionManager
ADConnection = LDAPConnectionManager

__all__ = ["ADConnection", "ADConnectionError", "ADConnectionManager", "ConnectionTestResult"]