import json
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtWidgets import QApplication

from core.models import Finding, Severity
from gui.findings_view import FindingsDashboard


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    return QApplication.instance() or QApplication([])


def _finding(
    finding_id: str,
    severity: Severity,
    category: str,
    account: str,
    evidence: dict | None = None,
) -> Finding:
    return Finding(
        finding_id=finding_id,
        title=f"Finding for {account}",
        severity=severity,
        category=category,
        affected_object=account,
        affected_type="User",
        description="Observed configuration from collected LDAP attributes.",
        evidence=evidence or {"sAMAccountName": account, "userAccountControl": 512},
        security_impact="Review the account configuration.",
        recommended_remediation="Apply the documented account policy.",
        confidence="High",
        source="AD-TEST",
    )


def test_empty_findings_state_uses_scoped_message(qapp: QApplication) -> None:
    view = FindingsDashboard()
    view.set_findings([])

    assert view.content.currentWidget() is view.empty_state
    assert view.empty_title.text() == "No security findings detected."
    assert "no configured detection rules identified" in view.empty_body.text()
    assert "No vulnerabilities exist" not in view.empty_body.text()


def test_dashboard_counts_deduplicates_and_filters_findings(qapp: QApplication) -> None:
    high = _finding("AD-1", Severity.HIGH, "Kerberos", "svc_backup")
    medium = _finding("AD-2", Severity.MEDIUM, "Account Security", "svc_db")
    info = _finding("AD-3", Severity.INFO, "Configuration", "svc_info")
    view = FindingsDashboard()
    view.set_findings([high, medium, info, high])

    assert len(view.findings) == 3
    assert "Total: 3" in view.summary.text()
    assert "High: 1" in view.summary.text()
    assert "Info: 1" in view.summary.text()
    assert view.finding_list.count() == 3

    view.severity_filter.setCurrentIndex(view.severity_filter.findData(Severity.HIGH.value))
    view.category_filter.setCurrentText("Kerberos")
    view.search.setText("svc_backup")

    assert view.finding_list.count() == 1
    assert "svc_backup" in view.finding_list.item(0).text()


def test_selected_finding_details_switch_readable_and_raw_evidence(qapp: QApplication) -> None:
    evidence = {
        "sAMAccountName": "svc_backup",
        "userAccountControl": 66048,
        "dn": "CN=svc_backup,CN=Users,DC=example,DC=local",
    }
    view = FindingsDashboard()
    view.set_findings([_finding("AD-1", Severity.MEDIUM, "Account Security", "svc_backup", evidence)])
    view.finding_list.setCurrentRow(0)

    assert view.detail_title.text() == "Finding for svc_backup"
    assert "Affected object: svc_backup (User)" in view.metadata.text()
    assert "Account: svc_backup" in view.evidence_readable_text.toPlainText()
    assert "Remediation: Apply the documented account policy." == view.remediation.text()

    view.evidence_raw.click()
    assert view.evidence_stack.currentIndex() == 1
    assert json.loads(view.evidence_raw_text.toPlainText()) == evidence
    assert view.evidence_raw.isChecked()
    assert not view.evidence_readable.isChecked()


def test_finding_details_show_purple_team_correlation(qapp: QApplication) -> None:
    finding = _finding("AD-1", Severity.HIGH, "Privilege", "alice")
    view = FindingsDashboard()
    view.set_findings([finding])
    view.set_purple_correlations([{
        "finding_id": "AD-1", "state": "Matching events found",
        "applicable_rules": ["DET-AD-001"], "related_alert_ids": ["DET-AD-001-ABC"],
        "investigation_steps": ["Review the group change actor."],
        "limitation": "Imported logs are time-bounded.",
    }])

    assert "Matching events found" in view.purple_correlation.toPlainText()
    assert "DET-AD-001-ABC" in view.purple_correlation.toPlainText()