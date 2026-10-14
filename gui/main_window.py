"""Main dashboard window."""

import logging
from datetime import datetime
from threading import Event

from PySide6.QtCore import QObject, QThread, Signal, Slot
from PySide6.QtWidgets import (
    QFormLayout,
    QGroupBox,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
    QFileDialog,
)

from config.settings import ConnectionSettings
from core.findings import FindingEngine
from core.ldap_connection import LDAPConnectionManager
from core.models import Finding, Severity
from core.scanner import AssessmentCancelled, AssessmentScanner
from core.security_report import build_security_report, write_json_report, write_pdf_report
from gui.findings_view import FindingsDashboard
from gui.directory_security_views import OUAssessmentView, ProtocolAssessmentView, TrustAssessmentView
from gui.gpo_view import GPOAssessmentView
from gui.purple_team_view import PurpleTeamDashboard
from gui.result_views import CollectionResultView, domain_controller_name
from utils.validators import validate_host, validate_required

logger = logging.getLogger(__name__)


class LDAPTestWorker(QObject):
    """Run the blocking LDAP test outside the Qt event thread."""

    completed = Signal(object)
    progress = Signal(int, str)
    finalizing = Signal()

    def __init__(
        self,
        manager: LDAPConnectionManager,
        cancellation_event: Event | None = None,
    ) -> None:
        super().__init__()
        self.manager = manager
        self.cancellation_event = cancellation_event or Event()
        self.last_progress = 0

    def _emit_progress(self, value: int, message: str) -> None:
        self.last_progress = value
        self.progress.emit(value, message)

    def _on_hostname_resolved(self, hostname: str, address: str) -> None:
        self._emit_progress(15, f"{hostname} resolved to {address}; connecting to LDAP...")

    def _scan_progress(self, value: int, message: str) -> None:
        self._emit_progress(20 + round(value * 0.68), message)

    def _emit_cancelled(
        self,
        partial_data: dict[str, object],
        diagnostics: dict[str, str],
    ) -> None:
        self.completed.emit({
            "success": False,
            "status": "cancelled",
            "partial_data": partial_data,
            "progress": self.last_progress,
            "connection_diagnostics": diagnostics,
        })

    @Slot()
    def run(self) -> None:
        diagnostics = {
            "hostname": self.manager.settings.server,
            "resolved_ip": "Not resolved",
            "ldap": "Unreachable",
            "result": "Cancelled",
        }
        scanner: AssessmentScanner | None = None
        try:
            if self.cancellation_event.is_set():
                self._emit_cancelled({}, diagnostics)
                return

            self._emit_progress(10, f"Connecting to LDAP at {self.manager.settings.server}...")
            connection_result = self.manager.connect(self._on_hostname_resolved)
            diagnostics = connection_result.as_diagnostics()
            if not connection_result.success:
                self.completed.emit({
                    "success": False,
                    "status": "failed",
                    "message": connection_result.message,
                    "error_type": connection_result.error_type,
                    "diagnostic": connection_result.diagnostic,
                    "connection_diagnostics": diagnostics,
                    "progress": self.last_progress,
                })
                return

            scanner = AssessmentScanner(self.manager)
            inventory = scanner.run_assessment(self._scan_progress, self.cancellation_event)
            if self.cancellation_event.is_set():
                self._emit_cancelled(scanner.partial_data, diagnostics)
                return

            self._emit_progress(90, "Analyzing collected directory evidence...")
            findings = FindingEngine().analyze(inventory)
            if self.cancellation_event.is_set():
                self._emit_cancelled(inventory, diagnostics)
                return

            result_data = {
                **inventory,
                "connection_diagnostics": diagnostics,
                "findings": findings,
                "finding_counts": FindingEngine.severity_counts(findings),
            }
            self.finalizing.emit()
            self._emit_progress(99, "Finalizing assessment results...")
            self.completed.emit({"success": True, "status": "completed", "data": result_data})
        except AssessmentCancelled as exc:
            self._emit_cancelled(exc.partial_data, diagnostics)
        except Exception as exc:
            if self.cancellation_event.is_set():
                self._emit_cancelled(scanner.partial_data if scanner else {}, diagnostics)
                return
            logger.warning(
                "Directory assessment failed",
                extra={"server": self.manager.settings.server, "error_type": type(exc).__name__},
            )
            self.completed.emit({
                "success": False,
                "status": "failed",
                "message": "LDAP connected, but assessment processing failed.",
                "error_type": type(exc).__name__,
                "connection_diagnostics": diagnostics,
                "progress": self.last_progress,
            })
        finally:
            self.manager.disconnect()


class MainWindow(QMainWindow):
    """Professional shell for connection, assessment, and result views."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("AD Vigil — Active Directory Security Assessment & Purple Team Platform")
        self.resize(1100, 700)
        self._ldap_thread: QThread | None = None
        self._ldap_worker: LDAPTestWorker | None = None
        self._cancellation_event: Event | None = None
        self._stop_requested = False
        self._finalizing = False
        self.result_panels: dict[str, QTextEdit] = {}
        self.collection_views: dict[str, CollectionResultView] = {}
        self.findings_view: FindingsDashboard | None = None
        self.gpo_view: GPOAssessmentView | None = None
        self.ou_view: OUAssessmentView | None = None
        self.trust_view: TrustAssessmentView | None = None
        self.protocol_view: ProtocolAssessmentView | None = None
        self.purple_team_view: PurpleTeamDashboard | None = None
        self.workspace_tabs: QTabWidget | None = None
        self.assessment_tabs: QTabWidget | None = None
        self.scan_history: list[dict[str, object]] = []
        self._build_ui()

    def _build_ui(self) -> None:
        root = QWidget()
        layout = QVBoxLayout(root)
        layout.setContentsMargins(0, 4, 0, 4)
        layout.setSpacing(2)

        header = QLabel("AD VIGIL")
        header.setObjectName("header")
        layout.addWidget(header)
        tagline = QLabel("Find the weakness. Detect the activity. Strengthen the domain.")
        tagline.setObjectName("tagline")
        layout.addWidget(tagline)

        connection_box = QGroupBox("Connection")
        form = QFormLayout(connection_box)
        self.server_input = QLineEdit()
        self.server_input.setPlaceholderText("dc01.example.local")
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("EXAMPLE")
        self.username_input = QLineEdit()
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("Domain controller", self.server_input)
        form.addRow("Domain / NetBIOS", self.domain_input)
        form.addRow("Username", self.username_input)
        form.addRow("Password", self.password_input)
        layout.addWidget(connection_box)

        actions = QHBoxLayout()
        self.assess_button = QPushButton("Start assessment")
        self.assess_button.clicked.connect(self._start_assessment)
        actions.addWidget(self.assess_button)
        self.stop_button = QPushButton("Stop Assessment")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self._stop_assessment)
        actions.addWidget(self.stop_button)
        self.report_button = QPushButton("Generate Security Report")
        self.report_button.clicked.connect(self._generate_security_report)
        self.report_button.setEnabled(False)
        actions.addWidget(self.report_button)
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        actions.addWidget(self.progress)
        layout.addLayout(actions)

        self.status = QLabel("Ready for an authorized lab connection")
        self.status.setObjectName("status")
        layout.addWidget(self.status)

        self.workspace_tabs = QTabWidget()
        self.workspace_tabs.setObjectName("workspaces")
        self.assessment_tabs = QTabWidget()
        self.assessment_tabs.setObjectName("assessmentTabs")
        for name, key in (
            ("Overview", "overview"),
            ("Users", "users"),
            ("Groups", "groups"),
            ("Computers", "computers"),
            ("Domain Controllers", "domain_controllers"),
            ("SPNs", "spns"),
            ("GPOs", "gpos"),
            ("OUs", "ous"),
            ("Trusts", "trusts"),
            ("Protocols", "protocols"),
            ("Findings", "findings"),
            ("Scan History", "scan_history"),
        ):
            if key in {"users", "groups", "computers", "domain_controllers", "spns"}:
                view = CollectionResultView(key, name)
                self.assessment_tabs.addTab(view, name)
                self.collection_views[key] = view
            elif key == "findings":
                self.findings_view = FindingsDashboard()
                self.assessment_tabs.addTab(self.findings_view, name)
            elif key == "gpos":
                self.gpo_view = GPOAssessmentView()
                self.assessment_tabs.addTab(self.gpo_view, name)
            elif key == "ous":
                self.ou_view = OUAssessmentView()
                self.assessment_tabs.addTab(self.ou_view, name)
            elif key == "trusts":
                self.trust_view = TrustAssessmentView()
                self.assessment_tabs.addTab(self.trust_view, name)
            elif key == "protocols":
                self.protocol_view = ProtocolAssessmentView()
                self.assessment_tabs.addTab(self.protocol_view, name)
            else:
                panel = QTextEdit()
                panel.setReadOnly(True)
                panel.setPlainText(f"{name} results will appear here after an assessment.")
                self.assessment_tabs.addTab(panel, name)
                self.result_panels[key] = panel
        self.purple_team_view = PurpleTeamDashboard()
        self.workspace_tabs.addTab(self.assessment_tabs, "AD Assessment")
        self.workspace_tabs.addTab(self.purple_team_view, "Purple Team")
        self.workspace_tabs.setCurrentIndex(0)
        layout.addWidget(self.workspace_tabs, 1)
        self.setCentralWidget(root)
        if self.purple_team_view is not None and self.findings_view is not None:
            self.purple_team_view.correlationsChanged.connect(
                self.findings_view.set_purple_correlations
            )
        self.setStyleSheet(self._stylesheet())

    def _start_assessment(self) -> None:
        try:
            settings = ConnectionSettings(
                server=validate_host(self.server_input.text()),
                domain=validate_required(self.domain_input.text(), "Domain"),
                username=validate_required(self.username_input.text(), "Username"),
                password=self.password_input.text(),
            )
            if not settings.password:
                raise ValueError("Password is required")
        except ValueError as exc:
            QMessageBox.warning(self, "Invalid connection", str(exc))
            return

        self.assess_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self._stop_requested = False
        self._finalizing = False
        self._cancellation_event = Event()
        self.progress.setValue(0)
        self.status.setText(f"Assessing {settings.server}...")
        self._ldap_thread = QThread(self)
        self._ldap_worker = LDAPTestWorker(
            LDAPConnectionManager(settings), self._cancellation_event
        )
        self._ldap_worker.moveToThread(self._ldap_thread)
        self._ldap_thread.started.connect(self._ldap_worker.run)
        self._ldap_worker.progress.connect(self._handle_progress)
        self._ldap_worker.finalizing.connect(self._handle_finalizing)
        self._ldap_worker.completed.connect(self._handle_assessment_result)
        self._ldap_worker.completed.connect(self._ldap_thread.quit)
        self._ldap_worker.completed.connect(self._ldap_worker.deleteLater)
        self._ldap_thread.finished.connect(self._ldap_thread.deleteLater)
        self._ldap_thread.finished.connect(self._connection_thread_finished)
        self._ldap_thread.start()

    def _generate_security_report(self) -> None:
        if self.purple_team_view is None or not self.purple_team_view.assessment:
            QMessageBox.information(self, "No assessment results", "Complete an assessment before generating a security report.")
            return
        dialog = QDialog(self)
        dialog.setWindowTitle("Generate Security Report")
        form = QFormLayout(dialog)
        title = QLineEdit("AD Vigil — Active Directory Security Assessment")
        organization = QLineEdit()
        organization.setPlaceholderText("Optional")
        classification = QComboBox()
        classification.addItems(["Confidential", "Internal", "Restricted", "Public"])
        format_box = QComboBox()
        format_box.addItems(["PDF", "JSON"])
        inventory = QCheckBox("Include inventory summaries")
        inventory.setChecked(True)
        details = QCheckBox("Include detailed findings and evidence")
        details.setChecked(True)
        defensive = QCheckBox("Include defensive detections and Purple Team correlations")
        defensive.setChecked(True)
        recommendations = QCheckBox("Include remediation recommendations")
        recommendations.setChecked(True)
        coverage = QCheckBox("Include telemetry coverage and limitations")
        coverage.setChecked(True)
        for label, widget in (("Report title", title), ("Organization / lab", organization),
                              ("Classification", classification), ("Format", format_box)):
            form.addRow(label, widget)
        for check in (inventory, details, defensive, recommendations, coverage):
            form.addRow(check)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        form.addRow(buttons)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        fmt = format_box.currentText().lower()
        domain = str(self.purple_team_view.assessment.get("domain") or "assessment")
        safe_domain = "".join(c if c.isalnum() or c in "-_." else "_" for c in domain)
        path, _ = QFileDialog.getSaveFileName(self, "Save Security Report", f"ad-vigil-{safe_domain}-security-report.{fmt}", f"{fmt.upper()} report (*.{fmt})")
        if not path:
            return
        from pathlib import Path
        target = Path(path)
        if target.exists():
            answer = QMessageBox.question(self, "Replace existing report?", f"{target.name} already exists. Replace it?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No)
            if answer != QMessageBox.StandardButton.Yes:
                return
        try:
            view = self.purple_team_view
            report = build_security_report(
                view.assessment, view.findings, view.sources, view.alerts, view.correlations,
                title=title.text().strip() or "AD Vigil — Active Directory Security Assessment",
                organization=organization.text().strip(), classification=classification.currentText(),
                include_inventory=inventory.isChecked(), include_details=details.isChecked(),
                include_defensive=defensive.isChecked(), include_recommendations=recommendations.isChecked(),
                include_coverage=coverage.isChecked(),
            )
            (write_pdf_report if fmt == "pdf" else write_json_report)(report, target)
            self.status.setText(f"Security report generated: {target.name}")
            QMessageBox.information(self, "Report generated", f"Saved {fmt.upper()} security report to:\n{target}")
        except Exception as exc:
            logger.warning("Security report generation failed", extra={"error_type": type(exc).__name__})
            QMessageBox.warning(self, "Report generation failed", f"Unable to generate report ({type(exc).__name__}).")

    @Slot(int, str)
    def _handle_progress(self, value: int, message: str) -> None:
        self.progress.setValue(value)
        if not self._stop_requested and not self._finalizing:
            self.status.setText(message)

    @Slot()
    def _stop_assessment(self) -> None:
        if self._cancellation_event is None or self._stop_requested or self._finalizing:
            return
        self._stop_requested = True
        self._cancellation_event.set()
        self.stop_button.setEnabled(False)
        self.status.setText("Stopping assessment...")

    @Slot()
    def _handle_finalizing(self) -> None:
        self._finalizing = True
        self.stop_button.setEnabled(False)
        self.status.setText("Finalizing assessment results...")

    @Slot(object)
    def _handle_assessment_result(self, result: dict[str, object]) -> None:
        if result.get("status") == "cancelled":
            self._handle_cancelled(result)
            return
        if not result.get("success"):
            self.progress.setValue(0)
            self.stop_button.setEnabled(False)
            self._finalizing = True
            message = str(result.get("message", "Assessment failed."))
            error_type = str(result.get("error_type") or "Unknown error")
            self.status.setText(f"{message} ({error_type})")
            diagnostics = result.get("connection_diagnostics", {})
            detail = result.get("diagnostic")
            diagnostic_lines = [
                "Connection diagnostics:",
                f"Hostname: {diagnostics.get('hostname', 'Not available')}",
                f"Resolved IP: {diagnostics.get('resolved_ip', 'Not available')}",
                f"LDAP: {diagnostics.get('ldap', 'Unreachable')}",
                f"Result: {diagnostics.get('result', 'Failure')}",
            ]
            if detail:
                diagnostic_lines.append(f"Exception: {detail}")
            zero_counts = {severity.value: 0 for severity in Severity}
            failed_host = str(diagnostics.get("hostname", self.server_input.text()))
            self._record_scan_history(
                {"domain": self.domain_input.text(), "server": failed_host},
                {key: 0 for key in ("users", "groups", "computers", "domain_controllers", "spns")},
                0,
                zero_counts,
                failed_host,
                str(diagnostics.get("resolved_ip", "Not resolved")),
                status="Failed",
                progress=int(result.get("progress", 0)),
            )
            QMessageBox.warning(
                self,
                "Assessment failed",
                f"{message}\n\n" + "\n".join(diagnostic_lines),
            )
            return

        data = result["data"]
        diagnostics = data.get("connection_diagnostics") or {
            "hostname": data.get("server", "Not available"),
            "resolved_ip": data.get("server", "Not available"),
            "ldap": "Reachable",
            "result": "Success",
        }
        counts = {
            key: len(data[key])
            for key in ("users", "groups", "computers", "domain_controllers", "spns")
        }
        counts.update({
            "gpos": len(data.get("gpos", [])),
            "ous": len(data.get("ous", [])),
            "trusts": len(data.get("trusts", [])),
            "protocols": len(data.get("protocols", [])),
        })
        findings: list[Finding] = data.get("findings", [])
        finding_counts = data.get("finding_counts") or FindingEngine.severity_counts(findings)
        controller_name = domain_controller_name(data)
        self.result_panels["overview"].setPlainText(
            "\n".join((
                "Connection diagnostics:",
                f"Hostname: {diagnostics['hostname']}",
                f"Resolved IP: {diagnostics['resolved_ip']}",
                f"LDAP: {diagnostics['ldap']}",
                f"Result: {diagnostics['result']}",
                "",
                f"Domain: {data['domain']}",
                f"Domain controller: {controller_name} ({diagnostics['resolved_ip']})",
                f"Base DN: {data['base_dn']}",
                "",
                "Inventory totals:",
                f"Users: {counts['users']}",
                f"Groups: {counts['groups']}",
                f"Computers: {counts['computers']}",
                f"Domain controllers: {counts['domain_controllers']}",
                f"Objects with SPNs: {counts['spns']}",
                f"GPOs discovered: {counts['gpos']}",
                f"GPO content coverage: {data.get('gpo_content_status', 'Not assessed')}",
                f"OU discovery / DACL: {data.get('ou_discovery_status', 'Not assessed')} / {data.get('ou_acl_status', 'Not assessed')} ({counts['ous']})",
                f"Trust discovery: {data.get('trust_discovery_status', 'Not assessed')} ({counts['trusts']})",
                f"Protocol checks: {data.get('protocol_assessment_status', 'Not assessed')} ({counts['protocols']} observations)",
                "",
                f"Security Findings: {len(findings)}",
                f"Critical: {finding_counts[Severity.CRITICAL.value]}",
                f"High: {finding_counts[Severity.HIGH.value]}",
                f"Medium: {finding_counts[Severity.MEDIUM.value]}",
                f"Low: {finding_counts[Severity.LOW.value]}",
                f"Info: {finding_counts[Severity.INFO.value]}",
            ))
        )
        for key in ("users", "groups", "computers", "domain_controllers", "spns"):
            self.collection_views[key].set_results(data[key], data)
        if self.gpo_view is not None:
            self.gpo_view.set_results(
                data.get("gpos", []), data.get("gpo_links", []), findings,
                str(data.get("gpo_discovery_status", "Not assessed")),
            )
        if self.ou_view is not None:
            self.ou_view.set_results(
                data.get("ous", []), findings,
                str(data.get("ou_discovery_status", "Not assessed")),
                str(data.get("ou_acl_status", "Not assessed")),
            )
        if self.trust_view is not None:
            self.trust_view.set_results(
                data.get("trusts", []), findings,
                str(data.get("trust_discovery_status", "Not assessed")),
            )
        if self.protocol_view is not None:
            self.protocol_view.set_results(
                data.get("protocols", []), findings,
                str(data.get("protocol_assessment_status", "Not assessed")),
            )
        if self.findings_view is not None:
            self.findings_view.set_findings(findings)
        if self.purple_team_view is not None:
            self.purple_team_view.set_assessment(data, findings)
            self.report_button.setEnabled(True)
        self._record_scan_history(
            data,
            counts,
            len(findings),
            finding_counts,
            controller_name,
            diagnostics["resolved_ip"],
        )
        self.progress.setValue(100)
        self.status.setText(
            "Assessment complete; " + ", ".join(f"{count} {name}" for name, count in (
                ("users", counts["users"]),
                ("groups", counts["groups"]),
                ("computers", counts["computers"]),
                ("domain controllers", counts["domain_controllers"]),
                ("SPN objects", counts["spns"]),
                ("GPOs", counts["gpos"]),
                ("OUs", counts["ous"]),
                ("trusts", counts["trusts"]),
                ("findings", len(findings)),
            ))
        )
        logger.info("Directory assessment rendered", extra={"server": data["server"]})

    def _handle_cancelled(self, result: dict[str, object]) -> None:
        self.progress.setValue(int(result.get("progress", self.progress.value())))
        self.status.setText("Assessment stopped by user.")
        partial = result.get("partial_data") or {}
        diagnostics = result.get("connection_diagnostics") or {}
        completed = set(partial.get("completed_categories", []))
        current = partial.get("in_progress_category", "")
        categories = (
            ("users", "Users"),
            ("groups", "Groups"),
            ("computers", "Computers"),
            ("domain_controllers", "Domain Controllers"),
            ("spns", "SPNs"),
            ("ous", "OUs"),
            ("trusts", "Trusts"),
            ("protocols", "Protocol checks"),
        )
        partial_counts = {key: len(partial.get(key, [])) for key, _label in categories}
        partial_lines = []
        for key, label in categories:
            count = partial_counts[key]
            if key in completed:
                partial_lines.append(f"{label}: {count}")
            elif key == current:
                partial_lines.append(f"{label}: {count} (partial)")
            else:
                partial_lines.append(f"{label}: Not scanned")

        self.result_panels["overview"].setPlainText(
            "\n".join((
                "PARTIAL / CANCELLED",
                "Assessment stopped by user.",
                "",
                "Partial inventory summary (not committed to the inventory tabs):",
                *partial_lines,
                "",
                "Previously completed inventory views remain unchanged.",
                "Findings were not committed because the assessment was cancelled before completion.",
            ))
        )
        if self.findings_view is not None:
            self.findings_view.set_cancelled()

        host = str(partial.get("server", self.server_input.text()))
        controller_name = domain_controller_name(partial)
        if controller_name == "Not available":
            controller_name = str(partial.get("server_name") or host)
        resolved_ip = str(diagnostics.get("resolved_ip", "Not resolved"))
        zero_counts = {severity.value: 0 for severity in Severity}
        self._record_scan_history(
            partial,
            partial_counts,
            0,
            zero_counts,
            controller_name,
            resolved_ip,
            status="Cancelled",
            progress=self.progress.value(),
        )

    @Slot()
    def _connection_thread_finished(self) -> None:
        self.assess_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self._ldap_worker = None
        self._ldap_thread = None
        self._cancellation_event = None
        self._stop_requested = False
        self._finalizing = False

    def closeEvent(self, event) -> None:
        assessment_active = self._ldap_thread is not None and self._ldap_thread.isRunning()
        if assessment_active and self._cancellation_event is not None:
            self._cancellation_event.set()
        telemetry_stopped = (
            self.purple_team_view.cancel_import_and_wait(1000)
            if self.purple_team_view is not None else True
        )
        if assessment_active or not telemetry_stopped:
            self.status.setText("Waiting for active assessment/import cleanup; close again when it finishes.")
            event.ignore()
            return
        event.accept()

    def _record_scan_history(
        self,
        data: dict[str, object],
        inventory_counts: dict[str, int],
        finding_total: int,
        finding_counts: dict[str, int],
        controller_name: str,
        resolved_ip: str,
        status: str = "Completed",
        progress: int = 100,
    ) -> None:
        completed = datetime.now().astimezone().isoformat(timespec="seconds")
        counts = {
            key: int(inventory_counts.get(key, len(data.get(key, []))))
            for key in (
                "users", "groups", "computers", "domain_controllers", "spns", "ous", "trusts", "protocols",
            )
        }
        self.scan_history.append({
            "timestamp": completed,
            "status": status,
            "progress": progress,
            "domain": data.get("domain", self.domain_input.text()),
            "domain_controller": controller_name,
            "resolved_ip": resolved_ip,
            **counts,
            "finding_count": finding_total,
            "severity_counts": dict(finding_counts),
            "gpo_count": len(data.get("gpos", [])),
            "gpo_discovery_status": data.get("gpo_discovery_status", "Not assessed"),
            "gpo_content_status": data.get("gpo_content_status", "Not assessed"),
            "gpo_assessed": sum(
                gpo.get("assessment_status") == "Assessed successfully"
                for gpo in data.get("gpos", [])
            ),
            "gpo_partial": sum(
                gpo.get("assessment_status") == "Partially assessed"
                for gpo in data.get("gpos", [])
            ),
            "gpo_inaccessible": sum(
                gpo.get("assessment_status") == "Inaccessible"
                for gpo in data.get("gpos", [])
            ),
            "gpo_failed": sum(
                gpo.get("assessment_status") == "Failed"
                for gpo in data.get("gpos", [])
            ),
            "ou_discovery_status": data.get("ou_discovery_status", "Not assessed"),
            "ou_acl_status": data.get("ou_acl_status", "Not assessed"),
            "trust_discovery_status": data.get("trust_discovery_status", "Not assessed"),
            "protocol_assessment_status": data.get("protocol_assessment_status", "Not assessed"),
        })
        lines: list[str] = []
        for index, scan in enumerate(self.scan_history, 1):
            time_label = "Completed" if scan["status"] == "Completed" else "Recorded"
            lines.extend((
                f"Scan {index}  |  Status: {scan['status']}  |  Progress: {scan['progress']}%",
                f"{time_label}: {scan['timestamp']}",
                f"Domain: {scan['domain']}",
                f"Domain controller: {scan['domain_controller']} ({scan['resolved_ip']})",
                f"Users: {scan['users']}  Groups: {scan['groups']}  "
                f"Computers: {scan['computers']}  DCs: {scan['domain_controllers']}  "
                f"SPNs: {scan['spns']}",
                f"OUs: {scan['ous']}  Trusts: {scan['trusts']}  Protocol checks: {scan['protocols']}  "
                f"OU: {scan['ou_discovery_status']} / DACL {scan['ou_acl_status']}  "
                f"Trust: {scan['trust_discovery_status']}  Protocols: {scan['protocol_assessment_status']}",
                f"GPOs: {scan['gpo_count']}  Assessed: {scan['gpo_assessed']}  "
                f"Partial: {scan['gpo_partial']}  Inaccessible: {scan['gpo_inaccessible']}  "
                f"Failed: {scan['gpo_failed']}  "
                f"Discovery: {scan['gpo_discovery_status']}  Content: {scan['gpo_content_status']}",
                f"Findings: {scan['finding_count']}  "
                + "  ".join(
                    f"{severity}: {scan['severity_counts'][severity]}"
                    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
                ),
                "",
            ))
        self.result_panels["scan_history"].setPlainText("\n".join(lines))

    @staticmethod
    def _stylesheet() -> str:
        return """
            QMainWindow, QWidget { background: #101722; color: #d9e2ef; }
            QGroupBox { border: 1px solid #2a3a4f; margin-top: 12px; padding: 12px; }
            QGroupBox::title { color: #63d7c8; subcontrol-origin: margin; left: 12px; padding: 0 5px; }
            QLineEdit, QTextEdit, QPlainTextEdit { background: #172333; border: 1px solid #344962; padding: 7px; }
            QTableView { background: #172333; alternate-background-color: #1b2a3c; border: 1px solid #344962; gridline-color: #2a3a4f; }
            QTableView::item { padding: 5px; }
            QTableView::item:selected { background: #274257; }
            QHeaderView::section { background: #1d2d3e; color: #b9c9d9; border: 0; border-bottom: 1px solid #344962; padding: 7px; }
            QPushButton { background: #177d78; border: 0; padding: 9px 18px; font-weight: bold; }
            QPushButton:hover { background: #209c95; }
            QPushButton[viewToggle="true"] { background: #172333; border: 1px solid #344962; padding: 6px 12px; }
            QPushButton[viewToggle="true"]:checked { background: #274257; color: #63d7c8; }
            QProgressBar { background: #172333; border: 1px solid #344962; text-align: center; }
            QProgressBar::chunk { background: #63d7c8; }
            QTabBar::tab { background: #172333; padding: 9px 13px; }
            QTabBar::tab:selected { background: #274257; color: #63d7c8; }
            #header { color: #63d7c8; font-size: 24px; font-weight: bold; padding: 8px 0 0; }
            #tagline { color: #aab8c8; font-size: 12px; padding: 0 0 8px; }
            #status { color: #9fb2c8; padding: 4px 0; }
        """
