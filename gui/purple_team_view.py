"""Purple Team telemetry import, alert review, coverage, correlation, and export UI."""

import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Event
from typing import Any

from PySide6.QtCore import QObject, QThread, Signal, Slot, Qt
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from core.defensive_detections import DetectionAlert, detection_coverage, run_detections
from core.models import Finding
from core.purple_team import build_json_report, correlate_findings
from core.telemetry import (
    IngestionResult,
    LogSourceCoverage,
    NormalizedEvent,
    ingest_log_file,
)

logger = logging.getLogger(__name__)


class TelemetryImportWorker(QObject):
    completed = Signal(object)
    progress = Signal(int, str)

    def __init__(
        self,
        *,
        path: str = "",
        existing_events: list[NormalizedEvent],
        existing_sources: list[LogSourceCoverage],
        findings: list[Finding],
        cancellation_event: Event,
        failure_threshold: int,
        window_minutes: int,
        synthetic_demo: bool = False,
        reanalyze_only: bool = False,
        assessment_generation: int = 0,
    ) -> None:
        super().__init__()
        self.path = path
        self.events = list(existing_events)
        self.sources = list(existing_sources)
        self._initial_events = list(existing_events)
        self._initial_sources = list(existing_sources)
        self.findings = list(findings)
        self.cancellation_event = cancellation_event
        self.failure_threshold = failure_threshold
        self.window_minutes = window_minutes
        self.synthetic_demo = synthetic_demo
        self.reanalyze_only = reanalyze_only
        self.assessment_generation = assessment_generation

    @Slot()
    def run(self) -> None:
        try:
            if self.synthetic_demo:
                new_events, source = synthetic_demo_events()
                self.progress.emit(70, "Analyzing synthetic demonstration events")
            elif self.reanalyze_only:
                new_events, source = [], None
                self.progress.emit(60, "Re-running detection rules over imported telemetry")
            else:
                result = ingest_log_file(
                    self.path,
                    cancellation_event=self.cancellation_event,
                    progress=self.progress.emit,
                )
                new_events, source = result.events, result.source
            if source is not None:
                self.sources.append(source)
            self.events = _deduplicate_events([*self.events, *new_events])
            self.progress.emit(90, "Evaluating defensive detection rules")
            alerts = run_detections(
                self.events,
                self.failure_threshold,
                self.window_minutes,
                cancellation_event=self.cancellation_event,
            )
            analysis_complete = not self.cancellation_event.is_set()
            correlations = correlate_findings(
                self.findings,
                self.events,
                alerts,
                self.sources,
                analysis_complete=analysis_complete,
                cancellation_event=self.cancellation_event,
            )
            analysis_complete = analysis_complete and not self.cancellation_event.is_set()
            self.completed.emit({
                "success": True,
                "events": self.events,
                "sources": self.sources,
                "alerts": alerts,
                "correlations": correlations,
                "assessment_generation": self.assessment_generation,
                "status": (
                    "Cancelled" if not analysis_complete
                    else source.status if source is not None else "Reanalyzed"
                ),
            })
        except Exception as exc:
            logger.warning("Telemetry import or analysis failed", extra={"error_type": type(exc).__name__})
            self.completed.emit({
                "success": False,
                "error": f"Telemetry processing failed ({type(exc).__name__}).",
                "events": self._initial_events,
                "sources": self._initial_sources,
                "assessment_generation": self.assessment_generation,
            })


class PurpleTeamDashboard(QWidget):
    """Integrated defensive telemetry and finding-correlation interface."""

    correlationsChanged = Signal(object)

    ALERT_HEADERS = ("Severity", "First seen (UTC)", "Rule", "Host", "Account", "Source", "Events")
    SOURCE_HEADERS = ("Source", "Format", "Status", "Events", "Channels", "Event IDs", "Time range")
    CORRELATION_HEADERS = ("Finding ID", "Finding", "Category", "State", "Related alerts")

    def __init__(self) -> None:
        super().__init__()
        self.events: list[NormalizedEvent] = []
        self.sources: list[LogSourceCoverage] = []
        self.alerts: list[DetectionAlert] = []
        self.correlations: list[dict[str, Any]] = []
        self.findings: list[Finding] = []
        self.assessment: dict[str, Any] = {}
        self._last_assessment_domain = ""
        self._assessment_scope_changed = False
        self._replace_import_in_progress = False
        self._assessment_generation = 0
        self._thread: QThread | None = None
        self._worker: TelemetryImportWorker | None = None
        self._cancel_event: Event | None = None
        self._build_ui()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        toolbar = QHBoxLayout()
        self.import_button = QPushButton("Import event log")
        self.import_button.clicked.connect(self._choose_file)
        self.demo_button = QPushButton("Load synthetic demo")
        self.demo_button.clicked.connect(self._load_demo)
        self.analyze_button = QPushButton("Run detections")
        self.analyze_button.setEnabled(False)
        self.analyze_button.clicked.connect(self._reanalyze)
        self.cancel_button = QPushButton("Cancel import")
        self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(self._cancel_import)
        self.export_button = QPushButton("Export JSON report")
        self.export_button.clicked.connect(self._export_report)
        self.threshold = QSpinBox()
        self.threshold.setRange(2, 100)
        self.threshold.setValue(5)
        self.threshold.setToolTip("Failed logons required for an authentication alert")
        self.window = QSpinBox()
        self.window.setRange(1, 240)
        self.window.setValue(10)
        self.window.setSuffix(" min")
        self.window.setToolTip("Correlation time window")
        for button in (self.import_button, self.demo_button, self.analyze_button, self.cancel_button, self.export_button):
            button.setStyleSheet("padding: 5px 8px;")
        toolbar.addWidget(self.import_button)
        toolbar.addWidget(self.demo_button)
        toolbar.addWidget(self.analyze_button)
        toolbar.addWidget(self.cancel_button)
        toolbar.addStretch(1)
        toolbar.addWidget(self.export_button)
        root.addLayout(toolbar)
        settings_toolbar = QHBoxLayout()
        settings_toolbar.addWidget(QLabel("Failure threshold"))
        settings_toolbar.addWidget(self.threshold)
        settings_toolbar.addWidget(QLabel("Correlation window"))
        settings_toolbar.addWidget(self.window)
        settings_toolbar.addStretch(1)
        root.addLayout(settings_toolbar)
        self.status = QLabel("No telemetry imported; defensive analysis has not been evaluated.")
        root.addWidget(self.status)
        self.progress_label = QLabel("")
        root.addWidget(self.progress_label)

        self.tabs = QTabWidget()
        self.alerts_page = self._build_alerts_page()
        self.sources_page = self._build_sources_page()
        self.correlation_page = self._build_correlation_page()
        self.tabs.addTab(self.alerts_page, "Detection Alerts")
        self.tabs.addTab(self.sources_page, "Log Sources and Coverage")
        self.tabs.addTab(self.correlation_page, "Purple Team Correlation")
        root.addWidget(self.tabs, 1)

    def _build_alerts_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        toolbar = QHBoxLayout()
        self.alert_search = QLineEdit()
        self.alert_search.setPlaceholderText("Search rule, host, account, or evidence reference...")
        self.alert_severity = QComboBox()
        self.alert_severity.addItems(["All severities", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
        self.alert_search.textChanged.connect(self._render_alerts)
        self.alert_severity.currentIndexChanged.connect(self._render_alerts)
        toolbar.addWidget(self.alert_search, 1)
        toolbar.addWidget(self.alert_severity)
        layout.addLayout(toolbar)
        splitter = QSplitter(Qt.Orientation.Vertical)
        self.alert_table = self._table(self.ALERT_HEADERS)
        self.alert_table.itemSelectionChanged.connect(self._show_alert)
        splitter.addWidget(self.alert_table)
        self.alert_details = self._text_panel()
        splitter.addWidget(self.alert_details)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        layout.addWidget(splitter, 1)
        return page

    def _build_sources_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        self.coverage_tabs = QTabWidget()
        sources_page = QWidget()
        sources_layout = QVBoxLayout(sources_page)
        self.source_table = self._table(self.SOURCE_HEADERS)
        self.source_table.itemSelectionChanged.connect(self._show_source)
        sources_layout.addWidget(self.source_table, 2)
        self.source_details = self._text_panel()
        sources_layout.addWidget(self.source_details, 1)
        self.coverage_tabs.addTab(sources_page, "Log Sources")

        rule_page = QWidget()
        rule_layout = QVBoxLayout(rule_page)
        self.rule_coverage_summary = QLabel("No events evaluated.")
        self.rule_coverage_summary.setWordWrap(True)
        rule_layout.addWidget(self.rule_coverage_summary)
        self.rule_coverage_table = self._table((
            "Rule", "Eligible IDs", "Events eligible", "Events evaluated", "Not evaluated", "Alerts", "Result",
        ))
        rule_layout.addWidget(self.rule_coverage_table, 1)
        self.coverage_tabs.addTab(rule_page, "Detection Coverage")
        layout.addWidget(self.coverage_tabs, 1)
        return page

    def _build_correlation_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        self.correlation_search = QLineEdit()
        self.correlation_search.setPlaceholderText("Search finding, object, detection rule, or correlation state...")
        self.correlation_search.textChanged.connect(self._render_correlations)
        layout.addWidget(self.correlation_search)
        splitter = QSplitter(Qt.Orientation.Vertical)
        self.correlation_table = self._table(self.CORRELATION_HEADERS)
        self.correlation_table.itemSelectionChanged.connect(self._show_correlation)
        splitter.addWidget(self.correlation_table)
        self.correlation_details = self._text_panel()
        splitter.addWidget(self.correlation_details)
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 3)
        layout.addWidget(splitter, 1)
        return page

    @staticmethod
    def _table(headers: tuple[str, ...]) -> QTableWidget:
        table = QTableWidget(0, len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        return table

    @staticmethod
    def _text_panel() -> QPlainTextEdit:
        panel = QPlainTextEdit()
        panel.setReadOnly(True)
        return panel

    def set_assessment(self, assessment: dict[str, Any], findings: list[Finding]) -> None:
        self._assessment_generation += 1
        domain = str(assessment.get("domain") or "")
        domain_changed = bool(self._last_assessment_domain and domain and domain.casefold() != self._last_assessment_domain.casefold())
        self.assessment = {
            **assessment,
            "assessment_completed_at": datetime.now(timezone.utc),
        }
        self._last_assessment_domain = domain
        self.findings = list(findings)
        if domain_changed:
            self._assessment_scope_changed = True
            self.analyze_button.setEnabled(False)
            self.correlations = [{
                "finding_id": finding.finding_id,
                "finding_title": finding.title,
                "affected_object": finding.affected_object,
                "category": finding.category,
                "state": "Inconclusive",
                "applicable_rules": [],
                "rule_assessments": [],
                "related_alert_ids": [],
                "investigation_steps": ["Re-import telemetry collected for the current assessment target, then run detections."],
                "remediation": finding.recommended_remediation,
                "retest_guidance": "Re-evaluate after importing telemetry for the current target.",
                "limitation": "The assessment target changed; previously imported telemetry was retained but is not attributed to this target.",
            } for finding in self.findings]
            self.correlationsChanged.emit(self.correlations)
            self._render_correlations()
            self.status.setText("Assessment target changed; retained telemetry is not correlated to this target. Re-import current-target telemetry before running detections.")
        else:
            self._recompute_correlations()

    def set_purple_results(self, result: dict[str, Any]) -> None:
        is_current_assessment = result.get("assessment_generation", self._assessment_generation) == self._assessment_generation
        if not result.get("success"):
            if not self._replace_import_in_progress:
                self.events = result.get("events", self.events)
                self.sources = result.get("sources", self.sources)
            self._render_sources()
            self._render_detection_coverage()
            self.status.setText(str(result.get("error", "Telemetry processing failed.")))
            return
        if self._replace_import_in_progress and result.get("status") == "Cancelled":
            self._render_sources()
            self.status.setText("Telemetry replacement cancelled; retained telemetry was kept and remains uncorrelated to the new assessment target.")
            return
        if not is_current_assessment and self._replace_import_in_progress:
            self.status.setText("Assessment target changed during telemetry replacement; retained telemetry was kept. Re-import for the current target.")
            return
        self.events = result["events"]
        self.sources = result["sources"]
        self.alerts = result["alerts"]
        is_current_scope_replacement = (
            self._assessment_scope_changed
            and self._replace_import_in_progress
            and is_current_assessment
        )
        if self._assessment_scope_changed and not is_current_scope_replacement:
            # Keep the target-change Inconclusive rows; these sources have not
            # been explicitly re-imported after the target changed.
            self._render_alerts()
            self._render_sources()
            self._render_detection_coverage()
            self.analyze_button.setEnabled(False)
            self.status.setText("Assessment target changed; telemetry was retained but remains uncorrelated until current-target data is imported.")
            self.progress_label.clear()
            return
        if is_current_scope_replacement:
            self._assessment_scope_changed = False
        if is_current_assessment:
            self.correlations = result["correlations"]
        else:
            # Import output remains useful, but correlate it against the latest
            # findings rather than the worker's now-stale findings snapshot.
            self.correlations = correlate_findings(self.findings, self.events, self.alerts, self.sources)
        self._assessment_scope_changed = False
        self._replace_import_in_progress = False
        self.correlationsChanged.emit(self.correlations)
        self.status.setText(
            f"Telemetry status: {result.get('status', 'Completed')}    "
            f"Events: {len(self.events)}    Sources: {len(self.sources)}    "
            f"Alerts: {len(self.alerts)}    Correlated AD findings: {len(self.correlations)}"
        )
        self.progress_label.clear()
        self._render_alerts()
        self._render_sources()
        self._render_detection_coverage()
        self._render_correlations()

    def set_correlations(self, correlations: list[dict[str, Any]]) -> None:
        self.correlations = correlations
        self._render_correlations()

    def _choose_file(self) -> None:
        path, _selected_filter = QFileDialog.getOpenFileName(
            self,
            "Import Windows event log export",
            "",
            "Supported event exports (*.json *.jsonl *.ndjson *.csv *.xml);;All files (*.*)",
        )
        if path:
            replace_existing = False
            if self._assessment_scope_changed:
                answer = QMessageBox.question(
                    self,
                    "Replace telemetry for the new target?",
                    "The assessment target changed. Importing this file will replace the retained telemetry so detections cannot mix events from different targets. Continue?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No,
                )
                if answer != QMessageBox.StandardButton.Yes:
                    return
                replace_existing = True
            self._start_import(path, replace_existing=replace_existing)

    def _load_demo(self) -> None:
        self._start_import(synthetic_demo=True, replace_existing=self._assessment_scope_changed)

    def _reanalyze(self) -> None:
        if self.events and not self._assessment_scope_changed:
            self._start_import(reanalyze_only=True)

    def _start_import(
        self, path: str = "", synthetic_demo: bool = False, reanalyze_only: bool = False,
        replace_existing: bool = False,
    ) -> None:
        if self._thread is not None:
            return
        self._cancel_event = Event()
        self.import_button.setEnabled(False)
        self.demo_button.setEnabled(False)
        self.analyze_button.setEnabled(False)
        self.cancel_button.setEnabled(True)
        self.progress_label.setText("Preparing telemetry import...")
        self._thread = QThread(self)
        replacing = replace_existing and (bool(path) or synthetic_demo)
        self._replace_import_in_progress = replacing
        self._worker = TelemetryImportWorker(
            path=path,
            existing_events=[] if replacing else self.events,
            existing_sources=[] if replacing else self.sources,
            findings=self.findings,
            cancellation_event=self._cancel_event,
            failure_threshold=self.threshold.value(),
            window_minutes=self.window.value(),
            synthetic_demo=synthetic_demo,
            reanalyze_only=reanalyze_only,
            assessment_generation=self._assessment_generation,
        )
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.progress.connect(self._set_progress)
        self._worker.completed.connect(self.set_purple_results)
        self._worker.completed.connect(self._thread.quit)
        self._worker.completed.connect(self._worker.deleteLater)
        self._thread.finished.connect(self._thread_finished)
        self._thread.finished.connect(self._thread.deleteLater)
        self._thread.start()

    @Slot(int, str)
    def _set_progress(self, value: int, message: str) -> None:
        self.progress_label.setText(f"{value}%  {message}")

    @Slot()
    def _cancel_import(self) -> None:
        if self._cancel_event is not None:
            self._cancel_event.set()
            self.cancel_button.setEnabled(False)
            self.progress_label.setText("Cancelling telemetry import...")

    def cancel_import_and_wait(self, timeout_milliseconds: int = 1000) -> bool:
        if self._cancel_event is not None:
            self._cancel_event.set()
        if self._thread is None or not self._thread.isRunning():
            return True
        return self._thread.wait(timeout_milliseconds)

    @Slot()
    def _thread_finished(self) -> None:
        self._thread = None
        self._worker = None
        self._cancel_event = None
        if self._replace_import_in_progress:
            self._replace_import_in_progress = False
        self.import_button.setEnabled(True)
        self.demo_button.setEnabled(True)
        self.analyze_button.setEnabled(bool(self.events) and not self._assessment_scope_changed)
        self.cancel_button.setEnabled(False)

    def _recompute_correlations(self) -> None:
        self.correlations = correlate_findings(self.findings, self.events, self.alerts, self.sources)
        self.correlationsChanged.emit(self.correlations)
        self._render_correlations()

    def _render_alerts(self, *_args: Any) -> None:
        query = self.alert_search.text().strip().casefold()
        severity = self.alert_severity.currentText()
        visible = [
            alert for alert in self.alerts
            if (severity == "All severities" or alert.severity.value == severity)
            and (not query or query in json.dumps({
                "rule_id": alert.rule_id, "title": alert.title, "host": alert.host,
                "account": alert.account, "source": alert.source_ip,
                "event_refs": alert.event_refs, "explanation": alert.explanation,
            }, default=str).casefold())
        ]
        self.alert_table.setRowCount(len(visible))
        for row, alert in enumerate(visible):
            if alert.rule_id == "DET-AD-002":
                logger.debug(
                    "Rendered account-creation alert row",
                    extra={
                        "telemetry_stage": "ui_row",
                        "alert_id": alert.alert_id,
                        "has_timestamp": alert.first_seen is not None,
                        "has_host": bool(alert.host),
                        "has_account": bool(alert.account),
                        "has_source": bool(alert.source_ip),
                        "confidence": alert.confidence,
                    },
                )
            values = (
                alert.severity.value,
                alert.first_seen.isoformat() if alert.first_seen else "Not available",
                f"{alert.rule_id}  {alert.title}", alert.host or "Not available",
                alert.account or "Not available", alert.source_ip or "Not available", str(alert.event_count),
            )
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setData(Qt.ItemDataRole.UserRole, alert.alert_id)
                item.setToolTip(value)
                self.alert_table.setItem(row, column, item)
        if visible:
            self.alert_table.selectRow(0)
        else:
            self.alert_details.setPlainText(
                "No matching detection alerts were observed in the imported records. "
                "This is not evidence that no suspicious activity occurred."
            )

    def _show_alert(self) -> None:
        row = self.alert_table.currentRow()
        alert_id = self.alert_table.item(row, 0).data(Qt.ItemDataRole.UserRole) if row >= 0 else None
        alert = next((item for item in self.alerts if item.alert_id == alert_id), None)
        if alert is None:
            self.alert_details.clear()
            return
        if alert.rule_id == "DET-AD-002":
            logger.debug(
                "Displayed account-creation alert details",
                extra={
                    "telemetry_stage": "ui_details",
                    "alert_id": alert.alert_id,
                    "has_timestamp": alert.first_seen is not None or alert.last_seen is not None,
                    "has_host": bool(alert.host),
                    "has_account": bool(alert.account),
                    "has_source": bool(alert.source_ip),
                    "event_reference_count": len(alert.event_refs),
                },
            )
        self.alert_details.setPlainText("\n".join((
            f"{alert.severity.value}: {alert.title}",
            f"Rule: {alert.rule_id}    Confidence: {alert.confidence}",
            f"First/last seen: {alert.first_seen} / {alert.last_seen}",
            f"Host: {alert.host or 'Not available'}    Account: {alert.account or 'Not available'}",
            f"Affected accounts/members: {', '.join(alert.affected_accounts) or alert.member or 'Not available'}",
            f"Source: {alert.source_ip or 'Not available'}    Target group: {alert.target_group or 'Not available'}",
            f"Why it matched: {alert.explanation}",
            f"Evidence event references:\n{json.dumps(alert.event_refs, indent=2)}",
            f"MITRE ATT&CK: {alert.mitre_attack or 'Not mapped'}",
            f"Investigation:\n- " + "\n- ".join(alert.investigation_steps),
            f"Defensive actions:\n- " + "\n- ".join(alert.defensive_actions),
        )))

    def _render_sources(self) -> None:
        self.source_table.setRowCount(len(self.sources))
        for row, source in enumerate(self.sources):
            time_range = (
                f"{source.first_seen.isoformat()} to {source.last_seen.isoformat()}"
                if source.first_seen and source.last_seen else "Not available"
            )
            values = (
                source.source_name, source.format, source.status, str(source.event_count),
                ", ".join(source.channels) or "Not available",
                ", ".join(source.event_ids) or "Not available", time_range,
            )
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setData(Qt.ItemDataRole.UserRole, row)
                item.setToolTip(value)
                self.source_table.setItem(row, column, item)
        if self.sources:
            self.source_table.selectRow(0)
        else:
            self.source_details.setPlainText("No log sources imported. Required telemetry is unavailable.")

    def _render_detection_coverage(self) -> None:
        rows = detection_coverage(self.events, self.alerts)
        rules_matched = sum(row["matches"] > 0 for row in rows)
        incomplete = sum(event.parse_status != "Normalized" for event in self.events)
        missing_ids = sum(not event.event_id for event in self.events)
        parse_errors = sum(source.parse_error_count for source in self.sources)
        self.rule_coverage_summary.setText(
            f"Parsed unique events: {len(self.events)}    Sources: {len(self.sources)}    "
            f"Incomplete events: {incomplete}    Events without ID: {missing_ids}    "
            f"Parse errors: {parse_errors}    Rules with alerts: {rules_matched}/{len(rows)}. "
            "Eligible counts use event IDs; evaluated counts require the rule's minimum fields. "
            "A rule with zero matches may still have evaluated events."
        )
        self.rule_coverage_table.setRowCount(len(rows))
        for row_index, row in enumerate(rows):
            values = (
                row["rule_id"], ", ".join(row["event_ids"]), str(row["eligible_events"]),
                str(row["evaluated_events"]), str(row["not_evaluated_events"]),
                str(row["matches"]), row["status"],
            )
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                self.rule_coverage_table.setItem(row_index, column, item)

    def _show_source(self) -> None:
        row = self.source_table.currentRow()
        if row < 0 or row >= len(self.sources):
            self.source_details.clear()
            return
        source = self.sources[row]
        self.source_details.setPlainText("\n".join((
            f"Source: {source.source_name}", f"Format: {source.format}", f"Status: {source.status}",
            f"Events: {source.event_count}    Duplicates skipped: {source.duplicate_count}",
            f"Events with incomplete core fields: {source.incomplete_event_count}",
            f"Channels: {', '.join(source.channels) or 'Not available'}",
            f"Event IDs: {', '.join(source.event_ids) or 'Not available'}",
            f"Time range: {source.first_seen or 'Not available'} to {source.last_seen or 'Not available'}",
            f"Parse errors: {source.parse_error_count}",
            *source.parse_errors,
            f"Synthetic demonstration data: {'Yes' if source.synthetic else 'No'}",
        )))

    def _render_correlations(self, *_args: Any) -> None:
        query = self.correlation_search.text().strip().casefold()
        visible = [item for item in self.correlations if not query or query in json.dumps(item, default=str).casefold()]
        self.correlation_table.setRowCount(len(visible))
        for row, correlation in enumerate(visible):
            values = (
                str(correlation.get("finding_id", "")),
                str(correlation.get("finding_title", "")),
                str(correlation.get("category", "")),
                str(correlation.get("state", "Not evaluated")),
                str(len(correlation.get("related_alert_ids", []))),
            )
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setData(Qt.ItemDataRole.UserRole, correlation.get("finding_id"))
                item.setToolTip(value)
                self.correlation_table.setItem(row, column, item)
        if visible:
            self.correlation_table.selectRow(0)
        elif not self.correlations:
            self.correlation_details.setPlainText("Assessment findings will be correlated when available.")
        else:
            self.correlation_details.setPlainText("No correlations match the search.")

    def _show_correlation(self) -> None:
        row = self.correlation_table.currentRow()
        finding_id = self.correlation_table.item(row, 0).data(Qt.ItemDataRole.UserRole) if row >= 0 else None
        correlation = next((item for item in self.correlations if item.get("finding_id") == finding_id), None)
        if correlation is None:
            self.correlation_details.clear()
            return
        self.correlation_details.setPlainText("\n".join((
            f"{correlation.get('finding_id')}: {correlation.get('finding_title')}",
            f"Affected object: {correlation.get('affected_object')}",
            f"Correlation state: {correlation.get('state')}",
            f"Threat scenario: {correlation.get('threat_scenario', 'Not available')}",
            f"Rule assessments:\n{json.dumps(correlation.get('rule_assessments', []), indent=2)}",
            f"Related alert IDs: {', '.join(correlation.get('related_alert_ids', [])) or 'None observed'}",
            f"Investigation:\n- " + "\n- ".join(correlation.get("investigation_steps", [])),
            f"Remediation: {correlation.get('remediation') or 'Review the original AD finding.'}",
            f"Retest: {correlation.get('retest_guidance', '')}",
            f"Limitations: {correlation.get('limitation', '')}",
        )))

    def _export_report(self) -> None:
        path, _selected_filter = QFileDialog.getSaveFileName(
            self, "Export combined Purple Team report", "ad-vigil-purple-team-report.json", "JSON report (*.json)"
        )
        if not path:
            return
        try:
            report = build_json_report(self.assessment, self.findings, self.sources, self.alerts, self.correlations)
            Path(path).write_text(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True), encoding="utf-8")
            self.status.setText(f"JSON report exported: {Path(path).name}")
        except (OSError, TypeError, ValueError) as exc:
            QMessageBox.warning(self, "Export failed", f"Unable to write report ({type(exc).__name__}).")


def _deduplicate_events(events: list[NormalizedEvent]) -> list[NormalizedEvent]:
    unique: dict[str, NormalizedEvent] = {}
    for event in events:
        identity = (
            event.host.casefold(), event.channel.casefold(), event.record_id, event.event_id,
        ) if event.record_id else (
            event.timestamp.isoformat() if event.timestamp else "", event.host.casefold(),
            event.channel.casefold(), event.provider.casefold(), event.event_id,
            event.account_key, event.target_group.casefold(), event.member.casefold(),
            event.source_ip, event.logon_type, event.command_line,
            json.dumps(event.event_data, sort_keys=True, default=str, ensure_ascii=True),
        )
        key = hashlib.sha256(repr(identity).encode("utf-8", errors="replace")).hexdigest()
        unique.setdefault(key, event)
    return sorted(unique.values(), key=lambda item: item.timestamp or datetime.min.replace(tzinfo=timezone.utc))


def synthetic_demo_events() -> tuple[list[NormalizedEvent], LogSourceCoverage]:
    base = datetime(2026, 10, 12, 12, 0, tzinfo=timezone.utc)
    events: list[NormalizedEvent] = []
    records = []
    for index in range(5):
        records.append({
            "EventID": 4625,
            "TimeCreated": (base + timedelta(seconds=index * 15)).isoformat(),
            "Computer": "SYNTHETIC-HOST",
            "Channel": "Security",
            "EventRecordID": f"DEMO-4625-{index}",
            "EventData": {"TargetUserName": "demo-user", "IpAddress": "203.0.113.20", "LogonType": "3"},
        })
    records.extend((
        {
            "EventID": 4624, "TimeCreated": (base + timedelta(seconds=90)).isoformat(),
            "Computer": "SYNTHETIC-HOST", "Channel": "Security", "EventRecordID": "DEMO-4624",
            "EventData": {"TargetUserName": "demo-user", "IpAddress": "203.0.113.20", "LogonType": "3"},
        },
        {
            "EventID": 4728, "TimeCreated": (base + timedelta(minutes=2)).isoformat(),
            "Computer": "SYNTHETIC-DC", "Channel": "Security", "EventRecordID": "DEMO-4728",
            "EventData": {"SubjectUserName": "demo-operator", "TargetUserName": "Domain Admins", "MemberName": "EXAMPLE\\demo-user"},
        },
        {
            "EventID": 4104, "TimeCreated": (base + timedelta(minutes=3)).isoformat(),
            "Computer": "SYNTHETIC-HOST", "Channel": "Microsoft-Windows-PowerShell/Operational", "EventRecordID": "DEMO-4104",
            "EventData": {"SubjectUserName": "demo-user", "ScriptBlockText": "Invoke-Expression (Get-Content synthetic-demo.txt)"},
        },
    ))
    for record in records:
        events.append(NormalizedEvent(
            **normalize_synthetic_fields(record), provenance="SYNTHETIC DEMO (not observed)", synthetic=True,
        ))
    timestamps = [event.timestamp for event in events if event.timestamp]
    source = LogSourceCoverage(
        source_name="SYNTHETIC DEMO (not observed)", format="synthetic", status="Completed",
        imported_at=datetime.now(timezone.utc), event_count=len(events),
        channels=sorted({event.channel for event in events}),
        event_ids=sorted({event.event_id for event in events}),
        first_seen=min(timestamps) if timestamps else None,
        last_seen=max(timestamps) if timestamps else None,
        synthetic=True,
    )
    return events, source


def normalize_synthetic_fields(record: dict[str, Any]) -> dict[str, Any]:
    from core.telemetry import normalize_record

    event = normalize_record(record, "SYNTHETIC DEMO (not observed)", synthetic=True)
    return {
        "timestamp": event.timestamp, "host": event.host, "channel": event.channel,
        "provider": event.provider, "event_id": event.event_id, "record_id": event.record_id,
        "user": event.user, "target_account": event.target_account, "target_group": event.target_group,
        "member": event.member, "source_ip": event.source_ip, "logon_type": event.logon_type,
        "process_name": event.process_name, "command_line": event.command_line,
        "parent_process": event.parent_process, "description": event.description,
        "event_data": event.event_data,
    }
