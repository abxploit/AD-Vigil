"""Filterable findings dashboard and evidence detail renderer."""

import json
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtGui import QFontDatabase
from PySide6.QtWidgets import (
    QButtonGroup,
    QComboBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSplitter,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from core.models import Finding, Severity


SEVERITY_FILTERS = (
    ("All", "ALL"),
    ("Critical", Severity.CRITICAL.value),
    ("High", Severity.HIGH.value),
    ("Medium", Severity.MEDIUM.value),
    ("Low", Severity.LOW.value),
    ("Info", Severity.INFO.value),
)
CATEGORY_FILTERS = (
    "All",
    "Account Security",
    "Kerberos",
    "Kerberos / Privilege",
    "Privilege",
    "Delegation",
    "Configuration",
    "GPO Security",
    "OU Security",
    "Trust Security",
    "Protocol Security",
)
TECHNIQUE_FILTERS = (
    "All",
    "Kerberoasting",
    "AS-REP Roasting",
    "Golden Ticket",
    "Silver Ticket",
    "Unconstrained Delegation",
    "Constrained Delegation",
    "RBCD",
)

EVIDENCE_LABELS = {
    "sAMAccountName": "Account",
    "userAccountControl": "User Account Control",
    "objectSid": "Object SID",
    "servicePrincipalName": "Service Principal Names",
    "serviceClasses": "Service classes",
    "dn": "Distinguished Name",
    "user_dn": "User distinguished name",
    "memberOf": "Direct group memberships",
    "member": "Broad group members",
    "enabled": "Enabled",
}


def readable_evidence(evidence: dict[str, Any]) -> str:
    lines: list[str] = []
    for key, value in evidence.items():
        label = EVIDENCE_LABELS.get(key, key.replace("_", " ").replace("camel", "").capitalize())
        if value is None:
            rendered = "Not available"
        elif isinstance(value, (list, tuple)) and not value:
            rendered = "None detected"
        elif key == "privileged_groups" and isinstance(value, list):
            rendered = "\n".join(
                f"{item.get('name', 'Group')} ({item.get('relationship', 'Membership')})\n"
                f"  Path: {' -> '.join(item.get('path', []))}"
                for item in value
            ) or "None detected"
        elif isinstance(value, (list, tuple)):
            rendered = "\n".join(f"- {item}" for item in value)
        elif isinstance(value, dict):
            rendered = json.dumps(value, indent=2, sort_keys=True, default=str)
        else:
            rendered = str(value)
        lines.append(f"{label}: {rendered}")
    return "\n".join(lines) if lines else "No evidence was collected."


class FindingsDashboard(QWidget):
    """Render the generated findings without embedding any detection logic."""

    def __init__(self) -> None:
        super().__init__()
        self.findings: list[Finding] = []
        self._by_id: dict[str, Finding] = {}
        self._purple_correlations: dict[str, dict[str, Any]] = {}
        self._build_ui()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(8)

        self.summary = QLabel("Security Findings")
        self.summary.setObjectName("findingsSummary")
        root.addWidget(self.summary)

        filter_row = QHBoxLayout()
        self.severity_filter = QComboBox()
        for label, value in SEVERITY_FILTERS:
            self.severity_filter.addItem(label, value)
        self.category_filter = QComboBox()
        self.category_filter.addItems(CATEGORY_FILTERS)
        self.technique_filter = QComboBox()
        self.technique_filter.addItems(TECHNIQUE_FILTERS)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search findings...")
        filter_row.addWidget(QLabel("Severity"))
        filter_row.addWidget(self.severity_filter)
        filter_row.addWidget(QLabel("Category"))
        filter_row.addWidget(self.category_filter)
        filter_row.addWidget(QLabel("Technique"))
        filter_row.addWidget(self.technique_filter)
        filter_row.addWidget(self.search, 1)
        root.addLayout(filter_row)

        self.empty_state = QWidget()
        empty_layout = QVBoxLayout(self.empty_state)
        empty_layout.addStretch(1)
        self.empty_title = QLabel("No security findings detected.")
        self.empty_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty_body = QLabel(
            "The assessment completed successfully, but no configured detection rules "
            "identified security-relevant conditions in the collected AD data."
        )
        self.empty_body.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty_body.setWordWrap(True)
        empty_layout.addWidget(self.empty_title)
        empty_layout.addWidget(self.empty_body)
        empty_layout.addStretch(1)

        self.results = QSplitter(Qt.Orientation.Horizontal)
        self.finding_list = QListWidget()
        self.finding_list.setMinimumWidth(260)
        self.finding_list.currentItemChanged.connect(self._show_finding)
        self.detail_scroll = self._build_detail_panel()
        self.results.addWidget(self.finding_list)
        self.results.addWidget(self.detail_scroll)
        self.results.setStretchFactor(0, 2)
        self.results.setStretchFactor(1, 3)

        self.content = QStackedWidget()
        self.content.addWidget(self.results)
        self.content.addWidget(self.empty_state)
        root.addWidget(self.content, 1)

        self.severity_filter.currentIndexChanged.connect(self._apply_filters)
        self.category_filter.currentIndexChanged.connect(self._apply_filters)
        self.technique_filter.currentIndexChanged.connect(self._apply_filters)
        self.search.textChanged.connect(self._apply_filters)
        self.setStyleSheet(
            "QListWidget { background: #172333; border: 1px solid #344962; }"
            "QListWidget::item { background: #1b2a3c; border: 1px solid #344962; margin: 3px; padding: 8px; }"
            "QListWidget::item:selected { background: #274257; border-color: #63d7c8; }"
            "#findingsSummary { color: #63d7c8; font-size: 16px; font-weight: bold; padding: 4px; }"
        )

    def _build_detail_panel(self) -> QScrollArea:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        panel = QWidget()
        layout = QVBoxLayout(panel)
        self.detail_title = QLabel("Select a finding")
        self.detail_title.setObjectName("findingTitle")
        self.detail_title.setWordWrap(True)
        layout.addWidget(self.detail_title)
        self.metadata = QLabel("")
        self.metadata.setWordWrap(True)
        layout.addWidget(self.metadata)
        self.description = QLabel("")
        self.description.setWordWrap(True)
        layout.addWidget(self.description)
        self.impact = QLabel("")
        self.impact.setWordWrap(True)
        layout.addWidget(self.impact)

        evidence_header = QHBoxLayout()
        evidence_header.addWidget(QLabel("Evidence"))
        evidence_header.addStretch(1)
        self.evidence_readable = QPushButton("Readable")
        self.evidence_raw = QPushButton("Raw")
        self.evidence_readable.setCheckable(True)
        self.evidence_raw.setCheckable(True)
        self.evidence_readable.setProperty("viewToggle", True)
        self.evidence_raw.setProperty("viewToggle", True)
        self.evidence_view_group = QButtonGroup(self)
        self.evidence_view_group.setExclusive(True)
        self.evidence_view_group.addButton(self.evidence_readable)
        self.evidence_view_group.addButton(self.evidence_raw)
        self.evidence_readable.setChecked(True)
        self.evidence_readable.clicked.connect(lambda: self.evidence_stack.setCurrentIndex(0))
        self.evidence_raw.clicked.connect(lambda: self.evidence_stack.setCurrentIndex(1))
        evidence_header.addWidget(self.evidence_readable)
        evidence_header.addWidget(self.evidence_raw)
        layout.addLayout(evidence_header)

        self.evidence_stack = QStackedWidget()
        self.evidence_readable_text = QPlainTextEdit()
        self.evidence_readable_text.setReadOnly(True)
        self.evidence_readable_text.setMaximumHeight(190)
        self.evidence_raw_text = QPlainTextEdit()
        self.evidence_raw_text.setReadOnly(True)
        self.evidence_raw_text.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.evidence_raw_text.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        self.evidence_raw_text.setMaximumHeight(240)
        self.evidence_stack.addWidget(self.evidence_readable_text)
        self.evidence_stack.addWidget(self.evidence_raw_text)
        layout.addWidget(self.evidence_stack)

        self.remediation = QLabel("")
        self.remediation.setWordWrap(True)
        layout.addWidget(self.remediation)
        self.detection_limitations = QLabel("")
        self.detection_limitations.setWordWrap(True)
        layout.addWidget(self.detection_limitations)
        self.purple_correlation = QPlainTextEdit()
        self.purple_correlation.setReadOnly(True)
        self.purple_correlation.setMaximumHeight(170)
        self.purple_correlation.setPlaceholderText("Purple Team telemetry correlation is not evaluated yet.")
        layout.addWidget(self.purple_correlation)
        layout.addStretch(1)
        scroll.setWidget(panel)
        return scroll

    def set_findings(self, findings: list[Finding]) -> None:
        self.empty_title.setText("No security findings detected.")
        self.empty_body.setText(
            "The assessment completed successfully, but no configured detection rules "
            "identified security-relevant conditions in the collected AD data."
        )
        self._by_id = {}
        for finding in findings:
            self._by_id.setdefault(finding.finding_id, finding)
        self.findings = list(self._by_id.values())
        self._update_summary()
        self._apply_filters()

    def set_cancelled(self) -> None:
        """Clear findings for a cancelled run without implying a clean assessment."""
        self.findings = []
        self._by_id = {}
        self._update_summary()
        self.empty_title.setText("Assessment cancelled.")
        self.empty_body.setText(
            "Findings were not committed because the assessment was cancelled before completion."
        )
        self.finding_list.clear()
        self._clear_details()
        self.content.setCurrentWidget(self.empty_state)

    def set_purple_correlations(self, correlations: list[dict[str, Any]]) -> None:
        self._purple_correlations = {
            str(item.get("finding_id", "")): item for item in correlations
        }
        current = self.finding_list.currentItem()
        if current is not None:
            self._show_finding(current, None)

    def _update_summary(self) -> None:
        counts = {
            severity: sum(finding.severity == severity for finding in self.findings)
            for severity in Severity
        }
        self.summary.setText(
            f"Security Findings    Total: {len(self.findings)}    "
            f"Critical: {counts[Severity.CRITICAL]}    High: {counts[Severity.HIGH]}    "
            f"Medium: {counts[Severity.MEDIUM]}    Low: {counts[Severity.LOW]}    "
            f"Info: {counts[Severity.INFO]}"
        )

    def _apply_filters(self, *_args: Any) -> None:
        severity = self.severity_filter.currentData()
        category = self.category_filter.currentText()
        technique = self.technique_filter.currentText()
        query = self.search.text().strip().casefold()
        visible = []
        for finding in self.findings:
            if severity != "ALL" and finding.severity.value != severity:
                continue
            if category != "All" and finding.category != category:
                continue
            if technique != "All" and (finding.technique or "") != technique:
                continue
            searchable = " ".join((
                finding.title,
                finding.affected_object,
                finding.affected_type,
                finding.category,
                finding.technique,
                finding.mitre_attack,
                finding.description,
                json.dumps(finding.evidence, sort_keys=True, default=str),
            )).casefold()
            if query and query not in searchable:
                continue
            visible.append(finding)

        self.finding_list.clear()
        for finding in visible:
            item = QListWidgetItem(
                f"{finding.severity.value}  |  {finding.title}\n"
                f"{finding.affected_type}: {finding.affected_object}  |  {finding.category}"
            )
            item.setData(Qt.ItemDataRole.UserRole, finding.finding_id)
            self.finding_list.addItem(item)

        if not self.findings:
            self.content.setCurrentWidget(self.empty_state)
            self._clear_details()
        else:
            self.content.setCurrentWidget(self.results)
            if visible:
                self.finding_list.setCurrentRow(0)
            else:
                self._clear_details()
                self.detail_title.setText("No findings match the selected filters.")

    def _show_finding(self, current: QListWidgetItem | None, _previous: QListWidgetItem | None) -> None:
        if current is None:
            return
        finding = self._by_id.get(current.data(Qt.ItemDataRole.UserRole))
        if finding is None:
            return
        self.detail_title.setText(finding.title)
        technique_text = f"Technique: {finding.technique}" if finding.technique else "Technique: Not specified"
        mitre_text = f"MITRE ATT&CK: {finding.mitre_attack}" if finding.mitre_attack else "MITRE ATT&CK: Not mapped"
        self.metadata.setText(
            f"Severity: {finding.severity.value}    Category: {finding.category}\n"
            f"Affected object: {finding.affected_object} ({finding.affected_type})\n"
            f"{technique_text}\n{mitre_text}\n"
            f"Confidence: {finding.confidence}"
        )
        self.description.setText(f"Description: {finding.description}")
        self.impact.setText(f"Why it matters: {finding.security_impact or 'Not available'}")
        self.evidence_readable_text.setPlainText(readable_evidence(finding.evidence))
        self.evidence_raw_text.setPlainText(
            json.dumps(finding.evidence, indent=2, sort_keys=True, default=str)
        )
        self.evidence_stack.setCurrentIndex(0)
        self.evidence_readable.setChecked(True)
        self.evidence_raw.setChecked(False)
        self.remediation.setText(
            f"Remediation: {finding.recommended_remediation or 'Not available'}"
        )
        self.detection_limitations.setText(
            f"Detection limitations: {finding.detection_limitations or 'Not specified'}"
        )
        correlation = self._purple_correlations.get(finding.finding_id)
        if correlation is None:
            self.purple_correlation.setPlainText("Purple Team correlation: Not evaluated.")
        else:
            self.purple_correlation.setPlainText(
                f"Purple Team correlation: {correlation.get('state', 'Not evaluated')}\n"
                f"Applicable rules: {', '.join(correlation.get('applicable_rules', [])) or 'None'}\n"
                f"Related alerts: {', '.join(correlation.get('related_alert_ids', [])) or 'None observed'}\n"
                f"Investigation: {'; '.join(correlation.get('investigation_steps', []))}\n"
                f"Coverage limitation: {correlation.get('limitation', '')}"
            )

    def _clear_details(self) -> None:
        self.detail_title.setText("Select a finding")
        self.metadata.clear()
        self.description.clear()
        self.impact.clear()
        self.evidence_readable_text.clear()
        self.evidence_raw_text.clear()
        self.remediation.clear()
        self.detection_limitations.clear()
        self.purple_correlation.clear()
