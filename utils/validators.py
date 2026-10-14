"""Validation helpers for user-supplied connection values."""

import re

_HOST_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-]{0,252}[A-Za-z0-9]$")


def validate_host(value: str) -> str:
    """Validate and normalize a hostname or IPv4 address."""
    host = value.strip()
    if not host or not _HOST_PATTERN.fullmatch(host):
        raise ValueError("Enter a valid domain controller hostname or IPv4 address")
    return host


def validate_required(value: str, label: str) -> str:
    """Require a non-empty text value."""
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{label} is required")
    return normalized