import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from core.models import Finding, Severity
from gui.main_window import MainWindow


def _app():
    return QApplication.instance() or QApplication([])


def test_workspaces_keep_existing_views_and_navigation_state():
    _app()
    window = MainWindow()

    assert window.workspace_tabs.count() == 2
    assert [window.workspace_tabs.tabText(i) for i in range(2)] == ["AD Assessment", "Purple Team"]
    assert [window.assessment_tabs.tabText(i) for i in range(window.assessment_tabs.count())] == [
        "Overview", "Users", "Groups", "Computers", "Domain Controllers", "SPNs",
        "GPOs", "OUs", "Trusts", "Protocols", "Findings", "Scan History",
    ]
    assert window.workspace_tabs.widget(1) is window.purple_team_view
    assert window.assess_button.text() == "Start assessment"
    assert window.stop_button.text() == "Stop Assessment"
    assert window.report_button.text() == "Generate Security Report"

    window.assessment_tabs.setCurrentIndex(window.assessment_tabs.indexOf(window.findings_view))
    window.workspace_tabs.setCurrentIndex(1)
    window.purple_team_view.tabs.setCurrentIndex(1)
    window.purple_team_view.alert_search.setText("domain controller")
    window.workspace_tabs.setCurrentIndex(0)
    window.workspace_tabs.setCurrentIndex(1)

    assert window.assessment_tabs.currentWidget() is window.findings_view
    assert window.workspace_tabs.widget(1) is window.purple_team_view
    assert window.purple_team_view.tabs.currentIndex() == 1
    assert window.purple_team_view.alert_search.text() == "domain controller"
    window.close()


def test_new_domain_marks_retained_telemetry_correlations_inconclusive():
    _app()
    window = MainWindow()
    dashboard = window.purple_team_view
    finding = Finding(
        finding_id="AD-1", title="Observed configuration", category="Privilege",
        severity=Severity.HIGH, affected_object="alice", description="Evidence.",
        recommended_remediation="Review access.",
    )
    dashboard.set_assessment({"domain": "old.example"}, [finding])
    retained_alerts = [object()]
    dashboard.alerts = retained_alerts
    dashboard.set_assessment({"domain": "new.example"}, [finding])

    assert dashboard.alerts is retained_alerts
    assert dashboard._assessment_scope_changed is True
    assert dashboard.analyze_button.isEnabled() is False
    assert dashboard.correlations[0]["finding_id"] == "AD-1"
    assert dashboard.correlations[0]["state"] == "Inconclusive"
    assert "target changed" in dashboard.correlations[0]["limitation"]

    dashboard.set_purple_results({
        "success": True, "status": "Reanalyzed", "events": [], "sources": [], "alerts": [],
        "correlations": [{"finding_id": "AD-1", "state": "Matching events found"}],
        "assessment_generation": dashboard._assessment_generation - 1,
    })
    assert dashboard.correlations[0]["state"] == "Inconclusive"

    dashboard._replace_import_in_progress = True
    dashboard.set_purple_results({
        "success": True, "status": "Completed", "events": [], "sources": [], "alerts": [],
        "correlations": [{"finding_id": "AD-1", "state": "No matching events observed"}],
        "assessment_generation": dashboard._assessment_generation,
    })
    assert dashboard._assessment_scope_changed is False
    assert dashboard.correlations[0]["state"] == "No matching events observed"
    window.close()
