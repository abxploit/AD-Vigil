from unittest.mock import MagicMock

from core.findings.rules.directory_security import analyze_trust_security
from core.trust_assessment import decode_trust, discover_trusts
from core.models import Severity


def test_trust_flags_decode_direction_type_transitivity_and_sid_filtering() -> None:
    trust = decode_trust({"source_attributes": {
        "trustPartner": "partner.example", "trustDirection": 3, "trustType": 1,
        "trustAttributes": 0x4 | 0x10 | 0x200,
    }}, "example.local")

    assert trust["direction"] == "bidirectional"
    assert trust["type"] == "downlevel/external"
    assert trust["transitive"] is None
    assert trust["sid_filtering_enabled"] is True
    assert trust["selective_authentication_indicated"] is True
    assert "cross_organization_no_tgt_delegation" in trust["attribute_flags"]
    assert trust["partner_status"] == "Not inspected"


def test_unknown_trust_values_and_flags_remain_unknown_without_crashing() -> None:
    trust = decode_trust({"source_attributes": {
        "trustPartner": "future.example", "trustDirection": 9, "trustType": 99,
        "trustAttributes": 0x80000000,
    }}, "example.local")

    assert trust["direction"] == "unknown"
    assert trust["type"] == "unknown"
    assert trust["unknown_attribute_bits"] == 0x80000000
    assert trust["transitive"] is None
    assert trust["sid_filtering_enabled"] is None
    assert trust["selective_authentication_indicated"] is None

    signed = decode_trust({"source_attributes": {"trustAttributes": -2147483648}}, "example.local")
    assert signed["unknown_attribute_bits"] == 0x80000000


def test_trust_discovery_uses_system_container_and_pages_records() -> None:
    connection = MagicMock()
    connection.connection.extend.standard.paged_search.return_value = [{
        "type": "searchResEntry", "dn": "CN=partner,CN=System,DC=example,DC=local",
        "attributes": {"trustPartner": "partner.example", "trustDirection": 1, "trustType": 1, "trustAttributes": 0},
    }]
    result = discover_trusts(connection, "DC=example,DC=local", "example.local")

    assert result["trust_discovery_status"] == "Completed"
    assert result["trusts"][0]["direction"] == "inbound"
    assert connection.connection.extend.standard.paged_search.call_args.kwargs["search_base"] == "CN=System,DC=example,DC=local"


def test_external_trust_findings_are_conservative_and_evidence_bound() -> None:
    record = decode_trust({"source_attributes": {
        "trustPartner": "external.example", "trustDirection": 2, "trustType": 1,
        "trustAttributes": 0,
    }}, "example.local")
    record["distinguishedName"] = "CN=external,CN=System,DC=example,DC=local"
    findings = analyze_trust_security({"trusts": [record]})

    assert [finding.severity for finding in findings] == [Severity.INFO, Severity.MEDIUM]
    assert all(
        any(term in finding.detection_limitations for term in ("not checked", "not queried"))
        for finding in findings
    )
    assert all("partner.example" not in finding.description for finding in findings)