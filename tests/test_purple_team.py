from datetime import datetime, timezone

from core.defensive_detections import run_detections
from core.models import Finding, Severity
from core.purple_team import (
    INCONCLUSIVE,
    MATCHED,
    NO_MATCH,
    NOT_EVALUATED,
    TELEMETRY_UNAVAILABLE,
    build_json_report,
    correlate_findings,
    report_json_text,
)
from core.telemetry import LogSourceCoverage, normalize_record


def _finding(category: str = "Privilege", affected: str = "alice") -> Finding:
    return Finding(
        finding_id="AD-TEST-001", title="Privileged account configuration observed",
        severity=Severity.HIGH, category=category, affected_object=affected,
        affected_type="User", description="Evidence from an existing assessment.",
        evidence={"sAMAccountName": affected}, recommended_remediation="Review the access policy.",
    )


def _source(event_ids: list[str], channels: list[str] | None = None) -> LogSourceCoverage:
    return LogSourceCoverage(
        source_name="security-export.csv", format="csv", status="Completed",
        imported_at=datetime(2026, 10, 12, tzinfo=timezone.utc), event_count=0,
        channels=channels or ["Security"], event_ids=event_ids,
        first_seen=datetime(2026, 10, 12, tzinfo=timezone.utc),
        last_seen=datetime(2026, 10, 12, 1, tzinfo=timezone.utc),
    )


def _membership_event():
    return normalize_record({
        "System": {"EventID": 4728, "Computer": "DC01", "Channel": "Security", "EventRecordID": 10,
                   "TimeCreated": "2026-10-12T00:00:00Z"},
        "EventData": {"TargetUserName": "Domain Admins", "MemberName": "EXAMPLE\\alice", "SubjectUserName": "operator"},
    }, "security-export.csv")


def test_correlation_states_cover_unavailable_no_match_and_not_evaluated() -> None:
    finding = _finding()
    unavailable = correlate_findings([finding], [], [], [])[0]
    no_match = correlate_findings([finding], [], [], [_source(["4624", "4625", "4720"])])[0]
    not_evaluated = correlate_findings([_finding("Unknown category")], [], [], [])[0]

    assert unavailable["state"] == TELEMETRY_UNAVAILABLE
    assert no_match["state"] == NO_MATCH
    assert "not proof" in no_match["limitation"].casefold() or "not proof" in no_match["limitation"].casefold()
    assert not_evaluated["state"] == NOT_EVALUATED


def test_correlation_links_matching_privileged_membership_evidence() -> None:
    event = _membership_event()
    alerts = run_detections([event])
    correlation = correlate_findings(
        [_finding()], [event], alerts, [_source(["4728"])],
    )[0]

    assert correlation["state"] == MATCHED
    assert correlation["related_alert_ids"] == [alerts[0].alert_id]
    assert correlation["rule_assessments"][0]["state"] == MATCHED
    assert correlation["retest_guidance"]


    def test_event_ids_without_channel_metadata_still_count_as_telemetry() -> None:
        source = _source(["4728"], channels=[])
        source.channels = []
        event = _membership_event()
        correlation = correlate_findings([_finding()], [event], [], [source])[0]
        assert correlation["state"] == NO_MATCH


    def test_overall_state_does_not_hide_an_unavailable_applicable_rule() -> None:
        finding = _finding("GPO Security", "Baseline")
        powershell_source = _source(["4104"], ["Microsoft-Windows-PowerShell/Operational"])
        correlation = correlate_findings([finding], [], [], [powershell_source])[0]
        assert correlation["state"] == TELEMETRY_UNAVAILABLE
        states = {item["rule_id"]: item["state"] for item in correlation["rule_assessments"]}
        assert states["DET-AD-003"] == TELEMETRY_UNAVAILABLE
        assert states["DET-PS-001"] == NO_MATCH


def test_correlation_marks_missing_fields_inconclusive() -> None:
    event = normalize_record({
        "EventID": 4625, "TimeCreated": "2026-10-12T00:00:00Z", "Computer": "HOST",
        "Channel": "Security",
    }, "security-export.csv")
    finding = _finding("Account Security")
    correlation = correlate_findings([finding], [event], [], [_source(["4625"], ["Security"])])[0]

    assert correlation["state"] == INCONCLUSIVE
    assert any(item["state"] == INCONCLUSIVE for item in correlation["rule_assessments"])


def test_partial_log_source_makes_no_alert_inconclusive() -> None:
    source = _source(["4625"], ["Security"])
    source.status = "Partial"
    source.parse_error_count = 1
    correlation = correlate_findings([_finding("Account Security")], [], [], [source])[0]

    assert correlation["state"] == INCONCLUSIVE


def test_cancelled_detection_analysis_is_inconclusive_not_no_match() -> None:
    event = normalize_record({
        "EventID": 4625, "TimeCreated": "2026-10-12T00:00:00Z", "Computer": "HOST",
        "Channel": "Security", "EventData": {"TargetUserName": "alice", "IpAddress": "192.0.2.1"},
    }, "security-export.csv")
    correlation = correlate_findings(
        [_finding("Account Security")], [event], [], [_source(["4625"], ["Security"])],
        analysis_complete=False,
    )[0]
    assert correlation["state"] == INCONCLUSIVE


def test_combined_json_report_excludes_normalized_raw_event_payload() -> None:
    event = _membership_event()
    event.event_data["PrivateNote"] = "must-not-export"
    alerts = run_detections([event])
    source = _source(["4728"])
    correlations = correlate_findings([_finding()], [event], alerts, [source])
    text = report_json_text(
        {"domain": "EXAMPLE", "server": "dc.example.test", "users": [1]},
        [_finding()], [source], alerts, correlations,
    )
    assert "must-not-export" not in text
    assert "event_data" not in text
    assert "event_refs" in text
    assert "AD-TEST-001" in text


def test_report_serializes_binary_ad_evidence_without_failing() -> None:
    finding = _finding()
    finding.evidence["objectSid"] = b"\x01\x02"
    report = build_json_report({}, [finding], [], [], [])
    assert report["findings"][0]["evidence"]["objectSid"] == {
        "encoding": "hex", "value": "0102",
    }