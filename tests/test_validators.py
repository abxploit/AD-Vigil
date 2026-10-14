"""Tests for connection input validation."""

import pytest

from utils.validators import validate_host, validate_required


def test_validate_host_accepts_dns_name() -> None:
    assert validate_host(" dc01.example.local ") == "dc01.example.local"


def test_validate_host_rejects_empty_value() -> None:
    with pytest.raises(ValueError):
        validate_host(" ")


def test_validate_required_rejects_empty_value() -> None:
    with pytest.raises(ValueError, match="Username"):
        validate_required("", "Username")