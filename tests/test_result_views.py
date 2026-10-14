import json
import os
from datetime import datetime, timezone
from threading import Event
from unittest.mock import MagicMock, patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import QEventLoop, QTimer
from PySide6.QtWidgets import QApplication

from core.ldap_connection import ConnectionTestResult
from core.models import Finding, Severity
from core.telemetry import IngestionResult, LogSourceCoverage, normalize_record
from core.scanner import AssessmentCancelled
from gui.directory_security_views import OUAssessmentView, ProtocolAssessmentView, TrustAssessmentView
from gui.main_window import MainWindow
from gui.purple_team_view import PurpleTeamDashboard, TelemetryImportWorker
from gui.gpo_view import GPOAssessmentView
from gui.result_views import (
    CollectionResultView,
    domain_controller_name,
    format_computer_details,
    format_domain_controller_details,
    format_group_details,
    format_spn_details,
    format_user_details,
    serialize_raw_records,
)


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    return QApplication.instance() or QApplication([])


def test_user_details_format_status_empty_fields_and_last_logon() -> None:
    details = format_user_details({
        "sAMAccountName": "alice",
        "userAccountControl": 514,
        "mail": [],
        "lastLogonTimestamp": "2026-09-27T04:37:29Z",
    })

    assert "Username: alice" in details
    assert "Status: Disabled" in details
    assert "Email: None detected" in details
    assert "Last Logon: 2026-09-27 04:37:29 UTC" in details
    assert "Display name: Not available" in details
    assert "[]" not in details
    assert "null" not in details


def test_user_details_marks_enabled_account() -> None:
    assert "Status: Enabled" in format_user_details({"userAccountControl": 512})


def test_group_details_decode_security_type_scope_and_members() -> None:
    details = format_group_details({
        "name": "Account Operators",
        "groupType": -2147483646,
        "member": ["CN=Administrator,DC=example,DC=local"],
    })

    assert "Type: Security group" in details
    assert "Scope: Global" in details
    assert "Members: CN=Administrator,DC=example,DC=local" in details


def test_computer_role_uses_collected_dc_data_and_os() -> None:
    domain_controllers = [{"dn": "CN=DC01,OU=Domain Controllers,DC=example,DC=local"}]
    context = {"domain_controllers": domain_controllers}
    controller = format_computer_details({
        "dn": domain_controllers[0]["dn"],
        "operatingSystem": "Windows Server 2022",
    }, context)
    workstation = format_computer_details({"operatingSystem": "Windows 10 Pro"}, context)
    unknown = format_computer_details({"operatingSystem": "Linux"}, context)

    assert "Role: Domain Controller" in controller
    assert "Role: Workstation" in workstation
    assert "Role: Not available" in unknown


def test_spn_details_list_multiple_values_without_security_label() -> None:
    details = format_spn_details({
        "sAMAccountName": "desktop$",
        "servicePrincipalName": ["HOST/desktop", "RestrictedKrbHost/desktop"],
    })

    assert "Account: desktop$" in details
    assert "- HOST/desktop" in details
    assert "- RestrictedKrbHost/desktop" in details
    assert "vulnerab" not in details.casefold()


def test_overview_dc_name_comes_from_collected_controller_records() -> None:
    assert domain_controller_name({
        "server_name": "Unknown",
        "domain_controllers": [{"dNSHostName": "DC01.example.local"}],
    }) == "DC01.example.local"


def test_domain_controller_details_use_connected_ip_only_when_unambiguous() -> None:
    controller = {
        "dn": "CN=DC01,OU=Domain Controllers,DC=example,DC=local",
        "dNSHostName": "DC01.example.local",
    }
    details = format_domain_controller_details(controller, {
        "server": "192.0.2.10",
        "domain": "EXAMPLE",
        "domain_controllers": [controller],
    })
    ambiguous = format_domain_controller_details(controller, {
        "server": "192.0.2.10",
        "domain": "EXAMPLE",
        "domain_controllers": [controller, {"dn": "CN=DC02"}],
    })

    assert "IP address: 192.0.2.10" in details
    assert "IP address: Not available" in ambiguous


def test_raw_json_round_trip_preserves_all_ldap_values() -> None:
    records = [{
        "dn": "CN=Alice,DC=example,DC=local",
        "empty": [],
        "missingValue": None,
        "longAttribute": "x" * 5000,
        "sAMAccountName": "alice",
    }]

    serialized = serialize_raw_records(records)

    assert json.loads(serialized) == records
    assert "[]" in serialized
    assert "null" in serialized
    assert "x" * 5000 in serialized


def test_collection_view_defaults_readable_and_keeps_filterable_raw_data(qapp: QApplication) -> None:
    records = [
        {"sAMAccountName": "alice", "displayName": "Alice Example", "userAccountControl": 512},
        {"sAMAccountName": "bob", "displayName": "Bob Example", "userAccountControl": 514},
    ]
    original_records = json.loads(json.dumps(records))
    view = CollectionResultView("users", "Users")

    view.set_results(records, {"domain": "EXAMPLE", "domain_controllers": []})
    assert view.stack.currentIndex() == 0
    assert view.proxy.rowCount() == 2

    view.search.setText("alice")
    view.filter_timer.stop()
    view._apply_filter()
    assert view.proxy.rowCount() == 1

    view.raw_button.setChecked(True)
    assert view.stack.currentIndex() == 1
    assert json.loads(view.raw_editor.toPlainText()) == original_records
    view.copy_button.click()
    assert qapp.clipboard().text() == view.raw_text
    assert records == original_records


def test_collection_view_filters_large_result_list(qapp: QApplication) -> None:
    records = [
        {"sAMAccountName": f"user{index}", "userAccountControl": 512}
        for index in range(1200)
    ]
    view = CollectionResultView("users", "Users")
    view.set_results(records, {"domain_controllers": []})

    view.search.setText("user1199")
    view.filter_timer.stop()
    view._apply_filter()

    assert view.proxy.rowCount() == 1
    assert view.proxy.index(0, 0).data() == "user1199"
    view.raw_button.setChecked(True)
    view.show()
    qapp.processEvents()
    assert view.raw_editor.verticalScrollBar().maximum() > 0
    view.close()


def test_gpo_view_filters_and_displays_link_state_and_coverage(qapp: QApplication) -> None:
    view = GPOAssessmentView()
    gpo = {
        "displayName": "Server Baseline",
        "objectGUID": "11111111-2222-3333-4444-555555555555",
        "distinguishedName": "CN={11111111-2222-3333-4444-555555555555},CN=Policies,CN=System,DC=example,DC=local",
        "gPCFileSysPath": r"\\example.local\SYSVOL\example.local\Policies\baseline",
        "assessment_status": "Partially assessed",
        "content_status": "Partially assessed",
        "links": [{"linked_object_dn": "OU=Servers,DC=example,DC=local", "link_order": 1, "enabled": True, "enforced": True}],
        "linked_objects": ["OU=Servers,DC=example,DC=local"],
        "source_attributes": {"displayName": "Server Baseline"},
        "settings": [{"setting": "MinimumPasswordLength", "observed_value": "6"}],
    }

    view.set_results([gpo], gpo["links"], [], "Completed")
    view.search.setText("Server Baseline")

    assert view.table.rowCount() == 1
    assert "order 1: enabled, enforced" in view.table.item(0, 5).text()
    assert "Partially assessed" in view.table.item(0, 6).text()
    assert "Partially assessed" in view.readable.toPlainText()
    view.search.setText("not-a-gpo")
    assert view.table.rowCount() == 0


def test_ou_trust_and_protocol_views_display_evidence_and_unknown_states(qapp: QApplication) -> None:
    ou_view = OUAssessmentView()
    ou_view.set_results([
        {"name": "Parent", "distinguishedName": "OU=Parent,DC=example,DC=test", "parent_ou_dn": "", "child_ous": ["OU=Child,OU=Parent,DC=example,DC=test"], "source_attributes": {"description": "Root"}, "security_descriptor_status": "Inaccessible", "direct_gpo_links": [], "contained_counts": {"users": 2}},
        {"name": "Child", "distinguishedName": "OU=Child,OU=Parent,DC=example,DC=test", "parent_ou_dn": "OU=Parent,DC=example,DC=test", "child_ous": [], "source_attributes": {}, "security_descriptor_status": "Not returned", "direct_gpo_links": [], "contained_counts": {}},
    ], [], "Completed", "Partially assessed")
    assert ou_view.source_model.rowCount() == 1
    assert ou_view.source_model.item(0, 0).rowCount() == 1
    assert "Inaccessible" in ou_view.summary.toPlainText()
    assert "not effective policy" in ou_view.summary.toPlainText()

    trust_view = TrustAssessmentView()
    trust_view.set_results([{
        "trustPartner": "partner.example", "source_domain": "source.example", "direction": "inbound",
        "type": "downlevel/external", "transitive": None, "sid_filtering_enabled": None,
        "collection_status": "Discovered", "source_attributes": {"trustDirection": 1},
        "limitations": "Partner not inspected.",
    }], [], "Completed")
    assert "inbound (relative to source.example)" in trust_view.table.item(0, 2).text()
    assert "Unknown" in trust_view.table.item(0, 3).text()
    assert "not prove reachability" in trust_view.layout().itemAt(1).widget().text()

    protocol_view = ProtocolAssessmentView()
    protocol_view.set_results([{
        "check": "LDAP signing requirement", "status": "Unknown", "evidence_source": "Not observable",
    }], [], "Completed")
    assert protocol_view.table.item(0, 1).text() == "Unknown"
    assert "remain unknown" in protocol_view.details.toPlainText()

    window = MainWindow()
    assert window.ou_view is not None
    assert window.trust_view is not None
    assert window.protocol_view is not None


def test_scan_history_records_independent_ou_trust_protocol_coverage(qapp: QApplication) -> None:
    window = MainWindow()
    counts = {severity.value: 0 for severity in Severity}
    window._record_scan_history({
        "domain": "EXAMPLE",
        "gpos": [],
        "ous": [{"security_descriptor_status": "Inaccessible"}],
        "trusts": [],
        "protocols": [{"check": "LDAP signing", "status": "Unknown"}],
        "ou_discovery_status": "Completed",
        "ou_acl_status": "Partially assessed",
        "trust_discovery_status": "Completed",
        "protocol_assessment_status": "Completed",
    }, {}, 0, counts, "dc.example.test", "192.0.2.10")

    scan = window.scan_history[-1]
    assert scan["ous"] == 1
    assert scan["trusts"] == 0
    assert scan["protocols"] == 1
    assert scan["ou_acl_status"] == "Partially assessed"
    assert scan["trust_discovery_status"] == "Completed"
    assert scan["protocol_assessment_status"] == "Completed"


def test_purple_team_synthetic_demo_creates_alerts_and_correlates_existing_finding(qapp: QApplication) -> None:
    finding = Finding(
        finding_id="AD-PRIV-001", title="Privileged membership observed",
        severity=Severity.HIGH, category="Privilege", affected_object="demo-user",
        affected_type="User", description="Synthetic test finding for UI correlation.",
        evidence={"sAMAccountName": "demo-user"},
        recommended_remediation="Review the demonstrated membership.",
    )
    worker = TelemetryImportWorker(
        existing_events=[], existing_sources=[], findings=[finding],
        cancellation_event=Event(), failure_threshold=5, window_minutes=10,
        synthetic_demo=True,
    )
    output: list[dict] = []
    worker.completed.connect(output.append)
    worker.run()

    dashboard = PurpleTeamDashboard()
    dashboard.set_assessment({"domain": "SYNTHETIC LAB", "server": "SYNTHETIC-DC"}, [finding])
    dashboard.set_purple_results(output[0])

    assert output[0]["success"] is True
    assert output[0]["sources"][0].synthetic is True
    assert {alert.rule_id for alert in dashboard.alerts} >= {"DET-AUTH-001", "DET-AUTH-002", "DET-AD-001", "DET-PS-001"}
    assert dashboard.correlations[0]["state"] == "Matching events found"
    assert dashboard.source_table.item(0, 0).text() == "SYNTHETIC DEMO (not observed)"


def test_detection_reanalysis_uses_new_threshold_without_reimporting_source() -> None:
    events = [normalize_record({
        "EventID": 4625, "TimeCreated": f"2026-10-12T12:00:0{index}Z", "Computer": "HOST",
        "Channel": "Security", "EventRecordID": str(index),
        "EventData": {"TargetUserName": "alice", "IpAddress": "192.0.2.80", "LogonType": "3"},
    }, "security.jsonl") for index in range(4)]
    source = LogSourceCoverage(
        source_name="security.jsonl", format="jsonl", status="Completed",
        imported_at=datetime.now(timezone.utc), event_count=len(events), channels=["Security"],
        event_ids=["4625"],
    )
    worker = TelemetryImportWorker(
        existing_events=events, existing_sources=[source], findings=[],
        cancellation_event=Event(), failure_threshold=4, window_minutes=10,
        reanalyze_only=True,
    )
    output: list[dict] = []
    worker.completed.connect(output.append)
    worker.run()

    assert output[0]["status"] == "Reanalyzed"
    assert output[0]["sources"] == [source]
    assert any(alert.rule_id == "DET-AUTH-001" for alert in output[0]["alerts"])


def test_repeated_detection_result_replaces_dashboard_alerts(qapp: QApplication) -> None:
    event = normalize_record({
        "System": {
            "EventID": 4720, "TimeCreated": "2026-10-12T12:00:00Z", "Computer": "HOST",
            "Channel": "Security", "EventRecordID": "200",
        },
        "EventData": {"SubjectUserName": "operator", "TargetUserName": "created-user"},
    }, "security.xml")
    worker = TelemetryImportWorker(
        existing_events=[event], existing_sources=[], findings=[], cancellation_event=Event(),
        failure_threshold=5, window_minutes=10, reanalyze_only=True,
    )
    output: list[dict] = []
    worker.completed.connect(output.append)
    worker.run()
    dashboard = PurpleTeamDashboard()

    dashboard.set_purple_results(output[0])
    first_ids = [alert.alert_id for alert in dashboard.alerts]
    first_count = len(dashboard.alerts)
    assert dashboard.alert_table.item(0, 1).text() == "2026-10-12T12:00:00+00:00"
    assert dashboard.alert_table.item(0, 3).text() == "HOST"
    assert dashboard.alert_table.item(0, 4).text() == "created-user"
    assert "Confidence: Low" in dashboard.alert_details.toPlainText()
    dashboard.set_purple_results(output[0])

    assert first_count == 1
    assert [alert.alert_id for alert in dashboard.alerts] == first_ids
    assert len(dashboard.alerts) == first_count


def test_telemetry_worker_error_preserves_previous_snapshot(qapp: QApplication) -> None:
    event = normalize_record({"EventID": 4624, "EventRecordID": "existing"}, "previous.json")
    source = LogSourceCoverage(
        source_name="previous.json", format="json", status="Completed",
        imported_at=datetime.now(timezone.utc), event_count=1,
    )
    worker = TelemetryImportWorker(
        existing_events=[event], existing_sources=[source], findings=[],
        cancellation_event=Event(), failure_threshold=5, window_minutes=10,
        reanalyze_only=True,
    )
    output: list[dict] = []
    worker.completed.connect(output.append)
    with patch("gui.purple_team_view.run_detections", side_effect=RuntimeError("synthetic test error")):
        worker.run()

    assert output[0]["success"] is False
    assert output[0]["events"] == [event]
    assert output[0]["sources"] == [source]


def test_purple_dashboard_imports_file_in_worker_and_updates_coverage(qapp: QApplication, tmp_path) -> None:
    path = tmp_path / "account-create.jsonl"
    path.write_text(json.dumps({
        "EventID": 4720, "TimeCreated": "2026-10-12T12:00:00Z", "Computer": "HOST",
        "Channel": "Security", "EventRecordID": 91,
        "EventData": {"SubjectUserName": "operator", "TargetUserName": "new-user"},
    }), encoding="utf-8")
    dashboard = PurpleTeamDashboard()

    dashboard._start_import(str(path))
    loop = QEventLoop()
    poll = QTimer()
    poll.setInterval(5)
    poll.timeout.connect(lambda: loop.quit() if dashboard._thread is None else None)
    poll.start()
    QTimer.singleShot(5000, loop.quit)
    loop.exec()
    poll.stop()

    assert dashboard._thread is None
    assert dashboard.sources[0].source_name == path.name
    assert dashboard.sources[0].event_ids == ["4720"]
    assert any(alert.rule_id == "DET-AD-002" for alert in dashboard.alerts)
    assert "Events: 1" in dashboard.status.text()


def test_purple_dashboard_cancel_waits_for_worker_cleanup(qapp: QApplication) -> None:
    dashboard = PurpleTeamDashboard()
    started = Event()

    def blocked_import(path, cancellation_event, progress):
        started.set()
        cancellation_event.wait(2)
        source = LogSourceCoverage(
            source_name="partial.jsonl", format="jsonl", status="Cancelled",
            imported_at=datetime.now(timezone.utc),
        )
        return IngestionResult([], source)

    with patch("gui.purple_team_view.ingest_log_file", side_effect=blocked_import):
        dashboard._start_import("partial.jsonl")
        assert started.wait(2)
        assert dashboard.cancel_import_and_wait(2000)
        qapp.processEvents()

    assert dashboard._thread is None
    assert dashboard.sources[0].status == "Cancelled"
    assert "Cancelled" in dashboard.status.text()


def test_dashboard_renders_collected_results_and_preserves_history(qapp: QApplication) -> None:
    window = MainWindow()
    controller = {
        "dn": "CN=DC01,OU=Domain Controllers,DC=example,DC=local",
        "dNSHostName": "DC01.example.local",
        "sAMAccountName": "DC01$",
    }
    data = {
        "server": "192.0.2.10",
        "server_name": "Unknown",
        "domain": "EXAMPLE",
        "base_dn": "DC=example,DC=local",
        "connection_diagnostics": {
            "hostname": "dc01.example.local",
            "resolved_ip": "192.0.2.10",
            "ldap": "Reachable",
            "result": "Success",
        },
        "users": [{"sAMAccountName": "alice", "userAccountControl": 512}],
        "groups": [{"name": "Domain Users"}],
        "computers": [controller],
        "domain_controllers": [controller],
        "spns": [{"sAMAccountName": "svc", "servicePrincipalName": ["HTTP/app"]}],
    }

    window._handle_assessment_result({"success": True, "data": data})

    overview = window.result_panels["overview"].toPlainText()
    assert "Domain controller: DC01.example.local (192.0.2.10)" in overview
    assert "Hostname: dc01.example.local" in overview
    assert "LDAP: Reachable" in overview
    assert "Users: 1" in overview
    assert "Groups: 1" in overview
    assert "Computers: 1" in overview
    assert "Domain controllers: 1" in overview
    assert "Objects with SPNs: 1" in overview
    assert window.findings_view is not None
    assert window.findings_view.empty_title.text() == "No security findings detected."
    assert "Security Findings: 0" in overview
    assert "Critical: 0" in overview
    assert "Completed:" in window.result_panels["scan_history"].toPlainText()
    assert window.collection_views["users"].records is data["users"]

    window._handle_assessment_result({"success": True, "data": data})
    history = window.result_panels["scan_history"].toPlainText()
    assert len(window.scan_history) == 2
    assert "Scan 1" in history
    assert "Scan 2" in history
    assert "Findings: 0" in history


def test_cancelled_assessment_keeps_progress_and_records_cancelled_status(qapp: QApplication) -> None:
    window = MainWindow()
    previous_users = [{"sAMAccountName": "previous_completed_user"}]
    window.collection_views["users"].set_results(previous_users, {"domain_controllers": []})
    window._cancellation_event = Event()
    window.assess_button.setEnabled(False)
    window.stop_button.setEnabled(True)

    window._stop_assessment()

    assert window._cancellation_event.is_set()
    assert window.status.text() == "Stopping assessment..."
    assert not window.stop_button.isEnabled()
    assert not window.assess_button.isEnabled()

    window._handle_assessment_result({
        "success": False,
        "status": "cancelled",
        "progress": 61,
        "partial_data": {
            "server": "192.0.2.10",
            "server_name": "DC01",
            "domain": "EXAMPLE",
            "users": [{"sAMAccountName": "partial_user"}],
            "completed_categories": [],
            "in_progress_category": "users",
        },
        "connection_diagnostics": {"resolved_ip": "192.0.2.10"},
    })

    assert window.progress.value() == 61
    assert window.status.text() == "Assessment stopped by user."
    assert "PARTIAL / CANCELLED" in window.result_panels["overview"].toPlainText()
    assert "Users: 1 (partial)" in window.result_panels["overview"].toPlainText()
    assert window.collection_views["users"].records is previous_users
    assert window.findings_view.empty_title.text() == "Assessment cancelled."
    assert window.scan_history[-1]["status"] == "Cancelled"
    assert window.scan_history[-1]["progress"] == 61
    assert "Status: Cancelled" in window.result_panels["scan_history"].toPlainText()
    assert "Status: Completed" not in window.result_panels["scan_history"].toPlainText()

    window._connection_thread_finished()
    assert window.assess_button.isEnabled()
    assert not window.stop_button.isEnabled()


def test_qthread_stop_then_restart_completes_without_duplicate_workers(qapp: QApplication) -> None:
    window = MainWindow()
    window.server_input.setText("192.0.2.10")
    window.domain_input.setText("EXAMPLE")
    window.username_input.setText("analyst")
    window.password_input.setText("test-password")
    manager = MagicMock()
    manager.settings.server = "192.0.2.10"
    manager.connect.return_value = ConnectionTestResult(
        True, "192.0.2.10", "LDAP authentication succeeded",
        resolved_ip="192.0.2.10", ldap_reachable=True,
    )
    scan_started = Event()
    partial = {
        "server": "192.0.2.10",
        "server_name": "DC01",
        "domain": "EXAMPLE",
        "base_dn": "DC=example,DC=local",
        "users": [{"sAMAccountName": "partial_user"}],
        "completed_categories": [],
        "in_progress_category": "users",
    }
    completed_inventory = {
        "server": "192.0.2.10",
        "server_name": "DC01",
        "domain": "EXAMPLE",
        "base_dn": "DC=example,DC=local",
        "users": [{"sAMAccountName": "complete_user", "userAccountControl": 512}],
        "groups": [],
        "computers": [],
        "domain_controllers": [],
        "spns": [],
    }

    def cancel_first_scan(progress, cancellation):
        progress(10, "Enumerating Users")
        scan_started.set()
        cancellation.wait(3)
        raise AssessmentCancelled(partial)

    scan_calls = 0

    def run_scan(progress, cancellation):
        nonlocal scan_calls
        scan_calls += 1
        if scan_calls == 1:
            return cancel_first_scan(progress, cancellation)
        return completed_inventory

    with (
        patch("gui.main_window.LDAPConnectionManager", return_value=manager),
        patch("gui.main_window.AssessmentScanner") as scanner_class,
    ):
        scanner_class.return_value.run_assessment.side_effect = run_scan

        def wait_for_worker() -> None:
            loop = QEventLoop()
            poll = QTimer()
            poll.setInterval(5)
            poll.timeout.connect(lambda: loop.quit() if window._ldap_thread is None else None)
            poll.start()
            QTimer.singleShot(5000, loop.quit)
            loop.exec()
            poll.stop()
            assert window._ldap_thread is None

        window._start_assessment()
        assert not window.assess_button.isEnabled()
        assert window.stop_button.isEnabled()
        assert scan_started.wait(2)
        window.stop_button.click()
        wait_for_worker()

        assert window.status.text() == "Assessment stopped by user."
        assert window.progress.value() < 100
        assert window.assess_button.isEnabled()
        assert not window.stop_button.isEnabled()

        window._start_assessment()
        wait_for_worker()

    assert window.status.text().startswith("Assessment complete;")
    assert window.progress.value() == 100
    assert [scan["status"] for scan in window.scan_history] == ["Cancelled", "Completed"]
    assert manager.disconnect.call_count == 2
    assert scan_calls == 2
