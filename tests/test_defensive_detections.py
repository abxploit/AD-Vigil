from datetime import datetime, timedelta, timezone
from threading import Event

from core.defensive_detections import run_detections
from core.models import Severity
from core.telemetry import normalize_record


BASE_TIME = datetime(2026, 10, 12, 12, 0, tzinfo=timezone.utc)


def _event(event_id: int, seconds: int = 0, **fields):
    system = {
        "EventID": event_id,
        "TimeCreated": (BASE_TIME + timedelta(seconds=seconds)).isoformat(),
        "Computer": fields.pop("Computer", "HOST01"),
        "Channel": fields.pop("Channel", "Security"),
        "EventRecordID": fields.pop("EventRecordID", str(event_id) + str(seconds)),
    }
    data = fields.pop("EventData", fields)
    return normalize_record({"System": system, "EventData": data}, "synthetic-events.jsonl", synthetic=True)


def test_repeated_failures_group_only_same_account_host_source_and_logon_type() -> None:
    failures = [
        _event(4625, seconds=index * 30, EventData={
            "TargetUserName": "alice", "SubjectUserName": "", "IpAddress": "192.0.2.8", "LogonType": "3",
        })
        for index in range(5)
    ]
    unrelated = _event(4625, seconds=10, Computer="OTHER", EventData={
        "TargetUserName": "alice", "IpAddress": "192.0.2.9", "LogonType": "3",
    })

    alerts = run_detections([*failures, unrelated])

    repeated = [alert for alert in alerts if alert.rule_id == "DET-AUTH-001"]
    assert len(repeated) == 1
    assert repeated[0].event_count == 5
    assert repeated[0].source_ip == "192.0.2.8"
    assert repeated[0].account == "alice"


def test_single_or_missing_source_failures_do_not_create_brute_force_alert() -> None:
    one = _event(4625, EventData={"TargetUserName": "alice", "IpAddress": "192.0.2.8", "LogonType": "3"})
    missing_source = [
        _event(4625, seconds=index, EventData={"TargetUserName": "alice", "LogonType": "3"})
        for index in range(10)
    ]
    assert not [alert for alert in run_detections([one, *missing_source]) if alert.rule_id == "DET-AUTH-001"]


def test_success_after_repeated_failures_requires_same_key_and_time_window() -> None:
    failures = [
        _event(4625, seconds=index * 10, EventData={
            "TargetUserName": "alice", "IpAddress": "198.51.100.5", "LogonType": "3",
        })
        for index in range(3)
    ]
    success = _event(4624, seconds=40, EventData={
        "TargetUserName": "alice", "IpAddress": "198.51.100.5", "LogonType": "3",
    })
    wrong_source = _event(4624, seconds=41, EventData={
        "TargetUserName": "alice", "IpAddress": "198.51.100.6", "LogonType": "3",
    })

    alerts = run_detections([*failures, success, wrong_source])
    correlated = [alert for alert in alerts if alert.rule_id == "DET-AUTH-002"]
    assert len(correlated) == 1
    assert correlated[0].event_count == 4
    assert "not proof of compromise" in correlated[0].explanation


def test_success_after_threshold_is_detected_even_if_later_failure_is_out_of_order() -> None:
    failures = [
        _event(4625, seconds=index, EventData={
            "TargetUserName": "alice", "IpAddress": "198.51.100.25", "LogonType": "3",
        })
        for index in (0, 1, 2, 5)
    ]
    success = _event(4624, seconds=3, EventData={
        "TargetUserName": "alice", "IpAddress": "198.51.100.25", "LogonType": "3",
    })
    alerts = run_detections([failures[0], failures[1], failures[2], failures[3], success])
    correlated = [alert for alert in alerts if alert.rule_id == "DET-AUTH-002"]
    assert len(correlated) == 1
    assert correlated[0].event_count == 4


def test_many_successes_after_one_failure_burst_are_grouped() -> None:
    failures = [
        _event(4625, seconds=index, EventData={"TargetUserName": "alice", "IpAddress": "192.0.2.28", "LogonType": "3"})
        for index in range(3)
    ]
    successes = [
        _event(4624, seconds=index + 3, EventRecordID=f"success-{index}", EventData={
            "TargetUserName": "alice", "IpAddress": "192.0.2.28", "LogonType": "3",
        })
        for index in range(50)
    ]
    alerts = [alert for alert in run_detections([*failures, *successes]) if alert.rule_id == "DET-AUTH-002"]
    assert len(alerts) == 1
    assert alerts[0].event_count == len(failures) + len(successes)


def test_failure_threshold_window_boundary_and_duplicate_run_are_stable() -> None:
    events = [
        _event(4625, seconds=0, EventData={"TargetUserName": "alice", "IpAddress": "203.0.113.9", "LogonType": "3"}),
        _event(4625, seconds=60, EventData={"TargetUserName": "alice", "IpAddress": "203.0.113.9", "LogonType": "3"}),
        _event(4625, seconds=120, EventData={"TargetUserName": "alice", "IpAddress": "203.0.113.9", "LogonType": "3"}),
    ]
    first = run_detections(events, failure_threshold=3, window_minutes=2)
    second = run_detections(events, failure_threshold=3, window_minutes=2)
    assert len(first) == 1
    assert first[0].alert_id == second[0].alert_id
    assert first[0].alert_id == run_detections(list(reversed(events)), failure_threshold=3, window_minutes=2)[0].alert_id


def test_per_rule_severity_override_is_configurable() -> None:
    failures = [
        _event(4625, seconds=index, EventData={"TargetUserName": "alice", "IpAddress": "192.0.2.1", "LogonType": "3"})
        for index in range(5)
    ]
    alerts = run_detections(failures, severity_overrides={"DET-AUTH-001": "HIGH"})
    assert alerts[0].severity == Severity.HIGH


def test_detection_engine_honors_cancellation_event() -> None:
    cancellation = Event()
    cancellation.set()
    failures = [
        _event(4625, seconds=index, EventData={"TargetUserName": "alice", "IpAddress": "192.0.2.1", "LogonType": "3"})
        for index in range(10)
    ]
    assert run_detections(failures, cancellation_event=cancellation) == []


def test_privileged_group_change_and_account_creation_are_observations() -> None:
    group_change = _event(4728, EventData={
        "SubjectUserName": "operator", "TargetUserName": "Domain Admins", "MemberName": "EXAMPLE\\alice",
    })
    unprivileged = _event(4732, EventData={
        "SubjectUserName": "operator", "TargetUserName": "App Readers", "MemberName": "EXAMPLE\\alice",
    })
    created = _event(4720, EventData={"SubjectUserName": "operator", "TargetUserName": "new_user"})

    alerts = run_detections([group_change, unprivileged, created])

    membership = next(alert for alert in alerts if alert.rule_id == "DET-AD-001")
    creation = next(alert for alert in alerts if alert.rule_id == "DET-AD-002")
    assert membership.target_group == "Domain Admins"
    assert membership.member == "EXAMPLE\\alice"
    assert "not inherently malicious" in creation.explanation
    assert len([alert for alert in alerts if alert.rule_id == "DET-AD-001"]) == 1


def test_account_creation_with_missing_target_is_labeled_unavailable() -> None:
    event = _event(4720, EventData={"SubjectUserName": "operator"})

    alerts = run_detections([event])

    creation = next(alert for alert in alerts if alert.rule_id == "DET-AD-002")
    assert creation.account == "Account unavailable"
    assert creation.affected_accounts == []


def test_same_actor_group_change_burst_is_one_alert_with_all_members() -> None:
    events = [
        _event(4728, seconds=index * 5, EventData={
            "SubjectUserName": "operator", "TargetUserName": "Domain Admins",
            "MemberName": f"EXAMPLE\\user{index}",
        })
        for index in range(4)
    ]
    alerts = [item for item in run_detections(events) if item.rule_id == "DET-AD-001"]
    assert len(alerts) == 1
    assert alerts[0].event_count == 4
    assert len(alerts[0].affected_accounts) == 4


def test_new_account_privileged_group_sequence_requires_matching_identity_and_order() -> None:
    created = _event(4720, seconds=0, EventData={
        "SubjectUserName": "operator", "TargetUserName": "new-admin",
    })
    added = _event(4728, seconds=120, EventData={
        "SubjectUserName": "operator", "TargetUserName": "Domain Admins", "MemberName": "EXAMPLE\\new-admin",
    })
    unrelated = _event(4720, seconds=0, EventData={
        "SubjectUserName": "operator", "TargetUserName": "ordinary-user",
    })
    late_add = _event(4728, seconds=90_000, EventData={
        "SubjectUserName": "operator", "TargetUserName": "Domain Admins", "MemberName": "EXAMPLE\\ordinary-user",
    })

    alerts = run_detections([created, added, unrelated, late_add])
    sequences = [alert for alert in alerts if alert.rule_id == "DET-AD-004"]

    assert len(sequences) == 1
    assert sequences[0].account == "new-admin"
    assert sequences[0].target_group == "Domain Admins"
    assert "not proof" in sequences[0].explanation


def test_powershell_indicator_is_explained_without_retaining_secret_assignment() -> None:
    event = _event(4104, EventData={
        "SubjectUserName": "alice",
        "ScriptBlockText": "Invoke-Expression (Get-Content x); $password=SuperSecretValue",
    }, Channel="Microsoft-Windows-PowerShell/Operational")
    alerts = run_detections([event])
    alert = next(alert for alert in alerts if alert.rule_id == "DET-PS-001")
    assert "dynamic_code_execution" in alert.explanation
    assert "SuperSecretValue" not in repr(alert)
    assert alert.mitre_attack == "T1059.001"
    normal = _event(4104, EventData={"SubjectUserName": "alice", "ScriptBlockText": "Get-Process"})
    assert not [item for item in run_detections([normal]) if item.rule_id == "DET-PS-001"]


def test_kerberos_indicators_are_not_labeled_as_confirmed_attacks() -> None:
    no_preauth = _event(4768, EventData={"TargetUserName": "svc", "PreAuthType": "0"})
    rc4 = _event(4769, seconds=3, EventData={
        "TargetUserName": "svc", "ServiceName": "HTTP/app", "TicketEncryptionType": "0x17",
    })
    alerts = run_detections([no_preauth, rc4])
    assert {alert.rule_id for alert in alerts} == {"DET-KRB-001", "DET-KRB-002"}
    assert all(
        any(term in alert.explanation.casefold() for term in ("not proof", "does not establish"))
        for alert in alerts
    )


def test_high_volume_ticket_requests_and_policy_attribute_changes_are_evidence_linked() -> None:
    ticket_events = [
        _event(4769, seconds=index * 5, EventData={
            "TargetUserName": "alice", "IpAddress": "192.0.2.55", "ServiceName": f"HTTP/app{index}",
        })
        for index in range(10)
    ]
    directory_change = _event(5136, seconds=100, EventData={
        "SubjectUserName": "operator", "ObjectDN": "CN={GUID},CN=Policies,CN=System,DC=example,DC=test",
        "AttributeLDAPDisplayName": "gPLink",
    })

    alerts = run_detections([*ticket_events, directory_change])
    volume = next(alert for alert in alerts if alert.rule_id == "DET-KRB-003")
    policy_change = next(alert for alert in alerts if alert.rule_id == "DET-AD-003")
    assert volume.event_count == 10
    assert "does not prove Kerberoasting" in volume.explanation
    assert policy_change.target_object.startswith("CN={GUID}")
