import struct
from threading import Event
from unittest.mock import MagicMock

import pytest

from core.findings.rules.directory_security import analyze_ou_security
from core.models import Severity
from core.ou_assessment import discover_ous, parse_security_descriptor


def _sid_bytes(revision: int = 1, authority: int = 1, subauthorities: tuple[int, ...] = (0,)) -> bytes:
    return bytes((revision, len(subauthorities))) + authority.to_bytes(6, "big") + b"".join(
        struct.pack("<I", item) for item in subauthorities
    )


def _descriptor(aces: list[bytes], dacl_present: bool = True) -> bytes:
    header = bytearray(20)
    header[0] = 1
    control = 0x8000 | (0x0004 if dacl_present else 0)
    struct.pack_into("<H", header, 2, control)
    if not dacl_present:
        return bytes(header)
    struct.pack_into("<I", header, 16, 20)
    acl = struct.pack("<BBHHH", 2, 0, 8 + sum(map(len, aces)), len(aces), 0) + b"".join(aces)
    return bytes(header) + acl


def _ace(kind: int, flags: int, mask: int, sid: bytes) -> bytes:
    body = struct.pack("<I", mask) + sid
    return struct.pack("<BBH", kind, flags, len(body) + 4) + body


def test_security_descriptor_preserves_allow_deny_inheritance_and_sensitive_rights() -> None:
    everyone = _sid_bytes(authority=1, subauthorities=(0,))
    admins = _sid_bytes(authority=5, subauthorities=(32, 544))
    parsed = parse_security_descriptor(_descriptor([
        _ace(0, 0x02, 0x00040000 | 0x00080000 | 0x20, everyone),
        _ace(1, 0x10, 0x00040000, admins),
    ]))

    assert parsed["dacl_state"] == "Present"
    assert parsed["aces"][0]["type"] == "allow"
    assert parsed["aces"][0]["sid"] == "S-1-1-0"
    assert set(parsed["aces"][0]["rights"]) == {"write_dacl", "write_owner", "write_property"}
    assert parsed["aces"][0]["inheritance"] == ["container_inherit"]
    assert parsed["aces"][1]["type"] == "deny"
    assert parsed["aces"][1]["inherited"] is True


def test_security_descriptor_unknown_and_malformed_data_are_not_assumed_secure() -> None:
    assert parse_security_descriptor(_descriptor([], dacl_present=False))["dacl_state"] == "Null DACL"
    with pytest.raises(ValueError, match="truncated"):
        parse_security_descriptor(b"\x01\x00")


def test_ou_discovery_builds_hierarchy_and_respects_limit_and_cancellation() -> None:
    connection = MagicMock()
    entries = [
        {"type": "searchResEntry", "dn": "OU=Parent,DC=example,DC=local", "attributes": {
            "name": "Parent", "description": "Root", "gPOptions": 1,
            "gPLink": "[LDAP://CN={11111111-2222-3333-4444-555555555555},CN=Policies,CN=System,DC=example,DC=local;2]",
        }},
        {"type": "searchResEntry", "dn": "OU=Child,OU=Parent,DC=example,DC=local", "attributes": {"name": "Child", "gPOptions": 1}},
    ]
    connection.connection.extend.standard.paged_search.return_value = entries
    connection.connection.search.return_value = True
    connection.connection.entries = []
    result = discover_ous(connection, "DC=example,DC=local", inventories={
        "gpos": [{
            "distinguishedName": "CN={11111111-2222-3333-4444-555555555555},CN=Policies,CN=System,DC=example,DC=local",
            "objectGUID": "11111111-2222-3333-4444-555555555555",
            "displayName": "Server Baseline",
        }],
    }, max_ous=1)
    assert len(result["ous"]) == 1
    assert result["ou_discovery_status"] == "Limit reached"
    assert result["ous"][0]["parent_ou_dn"] == ""
    search_call = connection.connection.extend.standard.paged_search.call_args
    assert "nTSecurityDescriptor" in search_call.kwargs["attributes"]
    assert search_call.kwargs["paged_size"] == 500
    assert "controls" in search_call.kwargs
    connection.connection.search.assert_not_called()
    assert result["ous"][0]["direct_gpo_links"][0]["enforced"] is True
    assert result["ous"][0]["direct_gpo_links"][0]["gpo_name"] == "Server Baseline"
    assert result["ous"][0]["gPOptions"] == 1

    cancellation = Event()
    cancellation.set()
    partial = discover_ous(connection, "DC=example,DC=local", cancellation_event=cancellation)
    assert partial["ous"] == []
    assert partial["ou_discovery_status"] == "Partial"


def test_empty_ou_search_is_completed_but_descriptor_coverage_is_not_assessed() -> None:
    connection = MagicMock()
    connection.connection.extend.standard.paged_search.return_value = []
    result = discover_ous(connection, "DC=example,DC=test")

    assert result["ous"] == []
    assert result["ou_discovery_status"] == "Completed"
    assert result["ou_acl_status"] == "Not assessed"
    connection.connection.search.assert_not_called()


def test_dacl_control_failure_falls_back_to_ou_metadata_without_claiming_acl_coverage() -> None:
    connection = MagicMock()
    calls: list[dict] = []

    def search(**kwargs):
        calls.append(kwargs)
        if "controls" in kwargs:
            raise RuntimeError("DACL access denied")
        return [{
            "type": "searchResEntry", "dn": "OU=Servers,DC=example,DC=test",
            "attributes": {"name": "Servers", "description": "Managed servers"},
        }]

    connection.connection.extend.standard.paged_search.side_effect = search
    result = discover_ous(connection, "DC=example,DC=test")

    assert len(calls) == 2
    assert len(result["ous"]) == 1
    assert result["ou_discovery_status"] == "Completed"
    assert result["ou_acl_status"] == "Inaccessible"
    assert result["ous"][0]["security_descriptor_status"] == "Inaccessible"


def test_ou_findings_are_informational_without_direct_policy_and_evidence_bound_for_dacl() -> None:
    findings = analyze_ou_security({"ous": [
        {
            "name": "NoDirectPolicy", "distinguishedName": "OU=NoDirectPolicy,DC=example,DC=test",
            "description": "Documented", "gPLink": None, "gPOptions": 1, "direct_gpo_links": [],
            "security_descriptor_status": "Not returned", "security_descriptor": None,
            "source_attributes": {"gPOptions": 1},
        },
        {
            "name": "Delegated", "distinguishedName": "OU=Delegated,DC=example,DC=test",
            "description": "", "gPLink": "[link]", "direct_gpo_links": [{"enabled": True}],
            "security_descriptor_status": "Parsed",
            "security_descriptor": {"dacl_state": "Present", "aces": [{
                "type": "allow", "sid": "S-1-1-0", "mask": 0x00040000,
                "rights": ["write_dacl"], "inherited": False,
            }]},
            "source_attributes": {"name": "Delegated"},
        },
    ]})

    direct_link = next(item for item in findings if item.title.startswith("OU has no directly"))
    write_dacl = next(item for item in findings if item.title.startswith("Broad principal"))
    assert direct_link.severity == Severity.INFO
    assert "does not establish" in direct_link.description
    assert write_dacl.severity == Severity.MEDIUM
    assert write_dacl.evidence["ace"]["sid"] == "S-1-1-0"
    assert "effective access" in write_dacl.detection_limitations