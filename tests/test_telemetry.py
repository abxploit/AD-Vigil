import json
from threading import Event
from pathlib import Path

from core.defensive_detections import detection_coverage, run_detections
from core.telemetry import ingest_log_file, normalize_record


def test_jsonl_normalizes_security_event_and_redacts_sensitive_values(tmp_path) -> None:
    path = tmp_path / "security.jsonl"
    records = [
        {
            "EventID": 4625, "TimeCreated": "2026-10-12T10:00:00Z", "Computer": "DC01",
            "Channel": "Security", "EventRecordID": 8,
            "EventData": {
                "SubjectUserName": "operator", "TargetUserName": "alice",
                "IpAddress": "192.0.2.33", "LogonType": "3", "Password": "should-not-appear",
            },
        },
        {"malformed": "line"},
    ]
    path.write_text("\n".join(json.dumps(item) for item in records[:1]) + "\n{bad json}\n", encoding="utf-8")

    result = ingest_log_file(path)

    assert result.source.status == "Partial"
    assert result.source.parse_error_count == 1
    assert len(result.events) == 1
    event = result.events[0]
    assert event.event_id == "4625"
    assert event.timestamp.isoformat() == "2026-10-12T10:00:00+00:00"
    assert event.target_account == "alice"
    assert event.user == "operator"
    assert event.source_ip == "192.0.2.33"
    assert event.event_data["Password"] == "[REDACTED]"
    assert "should-not-appear" not in repr(result)


def test_csv_import_normalizes_windows_export_and_timezone(tmp_path) -> None:
    path = tmp_path / "export.csv"
    path.write_text(
        "TimeCreated,Computer,Channel,ProviderName,EventID,EventRecordID,TargetUserName,IpAddress,LogonType\n"
        "10/12/2026 10:30:00 AM,HOST01,Security,Microsoft-Windows-Security-Auditing,4624,100,bob,198.51.100.9,3\n",
        encoding="utf-8",
    )

    result = ingest_log_file(path)
    event = result.events[0]

    assert result.source.status == "Partial"
    assert result.source.event_ids == ["4624"]
    assert event.host == "HOST01"
    assert event.target_account == "bob"
    assert event.timestamp is None
    assert "lacks a supported timezone" in event.parse_status
    assert result.source.incomplete_event_count == 1


def test_windows_event_xml_export_normalizes_event_data(tmp_path) -> None:
    path = tmp_path / "events.xml"
    path.write_text(
        '<Events xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><Event>'
        '<System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4720</EventID>'
        '<EventRecordID>77</EventRecordID><Channel>Security</Channel><Computer>HOST02</Computer>'
        '<TimeCreated SystemTime="2026-10-12T11:00:00.000Z"/></System><EventData>'
        '<Data Name="SubjectUserName">admin</Data><Data Name="TargetUserName">newuser</Data>'
        '</EventData></Event></Events>',
        encoding="utf-8",
    )

    result = ingest_log_file(path)
    event = result.events[0]

    assert event.event_id == "4720"
    assert event.record_id == "77"
    assert event.channel == "Security"
    assert event.provider == "Microsoft-Windows-Security-Auditing"
    assert event.user == "admin"
    assert event.target_account == "newuser"
    assert result.source.first_seen == event.timestamp


def test_sanitized_windows_xml_fixture_parses_system_data_versions_and_detects_4720(tmp_path) -> None:
    fixture = Path(__file__).parent / "fixtures" / "windows_security_events.xml"
    path = tmp_path / fixture.name
    path.write_bytes(fixture.read_bytes())

    result = ingest_log_file(path)
    alerts = run_detections(result.events)
    coverage = {row["rule_id"]: row for row in detection_coverage(result.events, alerts)}
    by_id = {event.event_id: event for event in result.events}

    assert result.source.format == "xml"
    assert result.source.event_count == 3
    assert result.source.status == "Completed"
    assert by_id["4720"].host == "DC01.example.test"
    assert by_id["4720"].record_id == "100"
    assert by_id["4720"].version == "0"
    assert by_id["4720"].timestamp.isoformat() == "2026-10-12T14:00:00+00:00"
    assert by_id["4720"].user == "operator-fixture"
    assert by_id["4720"].target_account == "created-fixture"
    assert by_id["4720"].event_data["NestedPayload"]["Part"] == "nested-fixture-value"
    assert by_id["4624"].version == "2"
    assert by_id["4624"].target_account == "user-fixture"
    assert by_id["4625"].source_ip == "192.0.2.40"
    assert by_id["4625"].timestamp.isoformat() == "2026-10-12T14:02:00.500000+00:00"
    assert [alert.rule_id for alert in alerts] == ["DET-AD-002"]
    assert alerts[0].first_seen == alerts[0].last_seen == by_id["4720"].timestamp
    assert alerts[0].host == "DC01.example.test"
    assert coverage["DET-AD-002"]["eligible_events"] == 1
    assert coverage["DET-AD-002"]["evaluated_events"] == 1
    assert coverage["DET-AUTH-001"]["eligible_events"] == 1
    assert coverage["DET-AUTH-001"]["evaluated_events"] == 1
    assert coverage["DET-AUTH-002"]["eligible_events"] == 2


def test_minimal_4720_xml_preserves_fields_through_detection_and_reanalysis(tmp_path) -> None:
    fixture = Path(__file__).parent / "fixtures" / "windows_event_4720.xml"
    path = tmp_path / fixture.name
    path.write_bytes(fixture.read_bytes())

    result = ingest_log_file(path)
    event = result.events[0]
    first_run = run_detections(result.events)
    second_run = run_detections(result.events)
    alert = next(item for item in first_run if item.rule_id == "DET-AD-002")

    assert event.event_id == "4720"
    assert event.timestamp.isoformat() == "2026-10-12T14:00:00+00:00"
    assert event.host == "DC01.example.test"
    assert event.record_id == "200"
    assert event.target_account == "created-fixture"
    assert event.user == "operator-fixture"
    assert alert.first_seen == alert.last_seen == event.timestamp
    assert alert.host == event.host
    assert alert.affected_accounts == [event.target_account]
    assert alert.event_refs[0]["record_id"] == event.record_id
    assert alert.confidence == "Low"
    assert [(item.alert_id, item.event_count) for item in first_run] == [
        (item.alert_id, item.event_count) for item in second_run
    ]


def test_two_distinct_4720_records_remain_in_alert_evidence(tmp_path) -> None:
    fixture = Path(__file__).parent / "fixtures" / "windows_event_4720.xml"
    content = fixture.read_text(encoding="utf-8")
    second_event = '''
  <Event>
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4720</EventID>
      <TimeCreated SystemTime="2026-10-12T14:01:00.000Z" />
      <EventRecordID>201</EventRecordID>
      <Channel>Security</Channel>
      <Computer>DC01.example.test</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">operator-fixture</Data>
      <Data Name="TargetUserName">second-created-fixture</Data>
    </EventData>
  </Event>
'''
    path = tmp_path / "two-account-creations.xml"
    path.write_text(content.replace("</Events>", second_event + "</Events>"), encoding="utf-8")

    result = ingest_log_file(path)
    alerts = [item for item in run_detections(result.events) if item.rule_id == "DET-AD-002"]

    assert result.source.event_count == 2
    assert len(alerts) == 1
    assert alerts[0].event_count == 2
    assert {reference["record_id"] for reference in alerts[0].event_refs} == {"200", "201"}
    assert set(alerts[0].affected_accounts) == {"created-fixture", "second-created-fixture"}


def test_timezone_naive_windows_csv_is_mapped_but_not_assigned_a_timezone(tmp_path) -> None:
    path = tmp_path / "sanitized.csv"
    path.write_text(
        "Keywords,Date and Time,Source,Event ID,Task Category\n"
        "Audit Success,12-10-2026 15:59:11,Microsoft-Windows-Security-Auditing,4720,User Account Management,overflow\n",
        encoding="utf-8",
    )

    result = ingest_log_file(path)
    event = result.events[0]

    assert event.event_id == "4720"
    assert event.provider == "Microsoft-Windows-Security-Auditing"
    assert event.timestamp is None
    assert "timezone" in event.parse_status.casefold()
    assert result.source.parse_error_count == 1
    assert "extra columns" in result.source.parse_errors[0]


def test_missing_xml_time_host_and_rule_fields_are_incomplete_not_invented(tmp_path) -> None:
    path = tmp_path / "missing-fields.xml"
    path.write_text(
        '<Events xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><Event>'
        '<System><EventID>4720</EventID><Channel>Security</Channel></System>'
        '<EventData><Data Name="TargetUserName">created-fixture</Data></EventData>'
        '</Event></Events>',
        encoding="utf-8",
    )

    result = ingest_log_file(path)
    alerts = run_detections(result.events)
    coverage = {row["rule_id"]: row for row in detection_coverage(result.events, alerts)}

    assert result.source.event_count == 1
    assert result.source.incomplete_event_count == 1
    assert result.events[0].host == ""
    assert result.events[0].timestamp is None
    assert len(alerts) == 1 and alerts[0].rule_id == "DET-AD-002"
    assert alerts[0].first_seen is None and alerts[0].host == ""
    assert coverage["DET-AD-002"]["eligible_events"] == 1
    assert coverage["DET-AD-002"]["evaluated_events"] == 1


def test_event_viewer_flattened_4720_message_maps_subject_and_target_names(tmp_path) -> None:
    path = tmp_path / "flattened-4720.csv"
    path.write_text(
        "Keywords,Date and Time,Source,Event ID,Task Category\n"
        'Audit Success,12-10-2026 15:59:11,Microsoft-Windows-Security-Auditing,4720,User Account Management,'
        '"Subject:\r\n  Account Name: operator-fixture\r\nNew Account:\r\n  Account Name: created-fixture\r\nAttributes:"\n',
        encoding="utf-8",
    )

    result = ingest_log_file(path)
    event = result.events[0]
    alert = next(item for item in run_detections(result.events) if item.rule_id == "DET-AD-002")

    assert event.user == "operator-fixture"
    assert event.target_account == "created-fixture"
    assert event.timestamp is None  # The CSV timestamp has no timezone.
    assert alert.account == "created-fixture"
    assert alert.confidence == "Low"


def test_json_event_data_array_and_xml_userdata_are_normalized(tmp_path) -> None:
    json_path = tmp_path / "array.json"
    json_path.write_text(json.dumps({
        "EventID": 4625,
        "EventData": [
            {"Name": "TargetUserName", "Value": "alice"},
            {"Name": "IpAddress", "Value": "192.0.2.44"},
        ],
    }), encoding="utf-8")
    json_event = ingest_log_file(json_path).events[0]
    assert json_event.target_account == "alice"
    assert json_event.source_ip == "192.0.2.44"

    xml_path = tmp_path / "userdata.xml"
    xml_path.write_text(
        "<Events><Event><System><EventID>4720</EventID><Computer>HOST</Computer>"
        "<Channel>Security</Channel><TimeCreated SystemTime='2026-10-12T10:00:00Z'/></System>"
        "<UserData><EventData><SubjectUserName>operator</SubjectUserName>"
        "<TargetUserName>new-user</TargetUserName></EventData></UserData></Event></Events>",
        encoding="utf-8",
    )
    xml_event = ingest_log_file(xml_path).events[0]
    assert xml_event.user == "operator"
    assert xml_event.target_account == "new-user"


def test_utf16_windows_event_xml_export_is_supported(tmp_path) -> None:
    path = tmp_path / "events-utf16.xml"
    path.write_bytes(
        '<Events><Event><System><EventID>4624</EventID><Computer>HOST</Computer>'
        '<Channel>Security</Channel><TimeCreated SystemTime="2026-10-12T11:00:00Z"/>'
        '</System></Event></Events>'.encode("utf-16")
    )
    result = ingest_log_file(path)
    assert result.source.status == "Completed"
    assert result.events[0].event_id == "4624"


def test_duplicate_event_record_ids_are_deduplicated(tmp_path) -> None:
    path = tmp_path / "duplicate.json"
    event = {"EventID": 4625, "Computer": "HOST", "Channel": "Security", "EventRecordID": 5}
    path.write_text(json.dumps([event, event]), encoding="utf-8")

    result = ingest_log_file(path)

    assert len(result.events) == 1
    assert result.source.duplicate_count == 1
    assert result.source.event_count == 1


def test_fallback_deduplication_does_not_merge_distinct_same_time_members(tmp_path) -> None:
    path = tmp_path / "members.json"
    base = {"EventID": 4728, "Computer": "HOST", "Channel": "Security", "TimeCreated": "2026-10-12T10:00:00Z"}
    records = [
        {**base, "EventData": {"TargetUserName": "Domain Admins", "MemberName": member}}
        for member in ("EXAMPLE\\alice", "EXAMPLE\\bob")
    ]
    path.write_text(json.dumps(records), encoding="utf-8")
    result = ingest_log_file(path)
    assert len(result.events) == 2


def test_command_line_redacts_quoted_credential_assignments() -> None:
    event = normalize_record({
        "EventID": 4688, "Computer": "HOST", "Channel": "Security",
        "CommandLine": 'tool.exe -Password="multi word secret" -Token other-secret -Mode safe',
    }, "process.csv")
    assert "multi word secret" not in event.command_line
    assert "other-secret" not in event.command_line
    assert "[REDACTED]" in event.command_line


def test_malformed_xml_and_unsupported_or_oversize_files_return_status(tmp_path) -> None:
    malformed = tmp_path / "bad.xml"
    malformed.write_text("<Events><Event>", encoding="utf-8")
    evtx = tmp_path / "security.evtx"
    evtx.write_bytes(b"ElfFile\x00")
    large = tmp_path / "large.json"
    large.write_text("{}", encoding="utf-8")

    assert ingest_log_file(malformed).source.status == "Failed"
    dtd = tmp_path / "entity.xml"
    dtd.write_text('<!DOCTYPE Events [<!ENTITY secret "value">]><Events/>', encoding="utf-8")
    assert ingest_log_file(dtd).source.status == "Failed"
    assert ingest_log_file(evtx).source.status == "Unsupported"
    limited = ingest_log_file(large, max_bytes=1)
    assert limited.source.status == "Failed"
    assert "limit" in limited.source.parse_errors[0].casefold()


def test_csv_without_event_id_header_is_reported_as_malformed(tmp_path) -> None:
    path = tmp_path / "not-events.csv"
    path.write_text("Name,Message\nitem,not an event log\n", encoding="utf-8")
    result = ingest_log_file(path)
    assert result.source.status == "Failed"
    assert "event ID" in result.source.parse_errors[0]


def test_cancellation_returns_partial_import_coverage(tmp_path) -> None:
    path = tmp_path / "many.jsonl"
    path.write_text("\n".join(json.dumps({"EventID": 4625, "EventRecordID": index}) for index in range(10)), encoding="utf-8")
    cancellation = Event()
    progress_calls = 0

    def cancel_after_progress(_value: int, _message: str) -> None:
        nonlocal progress_calls
        progress_calls += 1
        cancellation.set()

    result = ingest_log_file(path, cancellation_event=cancellation, progress=cancel_after_progress)

    assert result.source.status == "Cancelled"
    assert result.events
