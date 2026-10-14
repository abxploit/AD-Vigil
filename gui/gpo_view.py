"""Searchable inventory and evidence view for discovered Group Policy Objects."""

import json
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.models import Finding


class GPOAssessmentView(QWidget):
    """Display GPO discovery and content coverage without implying effective scope."""

    HEADERS = ("GPO name", "GUID", "Distinguished Name", "SYSVOL path", "Linked objects", "Link state", "Status")

    def __init__(self) -> None:
        super().__init__()
        self.gpos: list[dict[str, Any]] = []
        self.links: list[dict[str, Any]] = []
        self.findings: list[Finding] = []
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.coverage = QLabel("GPO assessment has not run.")
        layout.addWidget(self.coverage)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search GPO name, GUID, path, link, or status...")
        self.search.textChanged.connect(self._apply_filter)
        layout.addWidget(self.search)
        self.table = QTableWidget(0, len(self.HEADERS))
        self.table.setHorizontalHeaderLabels(self.HEADERS)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.itemSelectionChanged.connect(self._show_selected)
        layout.addWidget(self.table, 2)
        self.details = QTabWidget()
        self.readable = self._text_panel()
        self.finding_details = self._text_panel()
        self.link_details = self._text_panel()
        self.raw_attributes = self._text_panel()
        self.source_evidence = self._text_panel()
        for panel, label in (
            (self.readable, "Summary"),
            (self.finding_details, "Findings"),
            (self.link_details, "Links"),
            (self.raw_attributes, "Raw LDAP"),
            (self.source_evidence, "Source evidence"),
        ):
            self.details.addTab(panel, label)
        layout.addWidget(self.details, 3)

    @staticmethod
    def _text_panel() -> QPlainTextEdit:
        panel = QPlainTextEdit()
        panel.setReadOnly(True)
        return panel

    def set_results(
        self,
        gpos: list[dict[str, Any]],
        links: list[dict[str, Any]],
        findings: list[Finding],
        discovery_status: str = "Completed",
    ) -> None:
        self.gpos = gpos
        self.links = links
        self.findings = [finding for finding in findings if finding.category == "GPO Security"]
        statuses: dict[str, int] = {}
        for gpo in gpos:
            status = str(gpo.get("assessment_status", "Discovered"))
            statuses[status] = statuses.get(status, 0) + 1
        status_text = ", ".join(f"{name}: {count}" for name, count in sorted(statuses.items())) or "No GPOs discovered"
        self.coverage.setText(
            f"Discovery: {discovery_status}    GPOs: {len(gpos)}    "
            f"Content coverage: {status_text}    Findings: {len(self.findings)}"
        )
        self.search.clear()
        self._populate_rows()

    def _populate_rows(self) -> None:
        query = self.search.text().strip().casefold()
        visible = []
        for gpo in self.gpos:
            row_text = json.dumps(gpo, sort_keys=True, default=str).casefold()
            if not query or query in row_text:
                visible.append(gpo)
        self.table.setRowCount(len(visible))
        for row, gpo in enumerate(visible):
            values = (
                str(gpo.get("displayName") or gpo.get("name") or "Unnamed GPO"),
                str(gpo.get("objectGUID") or "Not available"),
                str(gpo.get("distinguishedName") or "Not available"),
                str(gpo.get("gPCFileSysPath") or "Not available"),
                "; ".join(str(item) for item in gpo.get("linked_objects", [])) or "No discovered links",
                "; ".join(
                    f"order {link.get('link_order', '?')}: "
                    f"{'enabled' if link.get('enabled') is True else 'disabled' if link.get('enabled') is False else 'state unknown'}"
                    f"{', enforced' if link.get('enforced') else ''}"
                    for link in gpo.get("links", [])
                ) or "No discovered link state",
                str(gpo.get("assessment_status", "Discovered")),
            )
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setData(Qt.ItemDataRole.UserRole, gpo)
                self.table.setItem(row, column, item)
                item.setToolTip(value)
        self.table.resizeColumnsToContents()
        if visible:
            self.table.selectRow(0)
        else:
            self._clear_details()

    def _apply_filter(self, _text: str = "") -> None:
        self._populate_rows()

    def _show_selected(self) -> None:
        row = self.table.currentRow()
        if row < 0 or self.table.item(row, 0) is None:
            self._clear_details()
            return
        gpo = self.table.item(row, 0).data(Qt.ItemDataRole.UserRole)
        guid = str(gpo.get("objectGUID", "")).casefold()
        links = gpo.get("links", [])
        findings = [item for item in self.findings if str(item.evidence.get("gpo_guid", "")).casefold() == guid]
        readable_lines = [
            f"Name: {gpo.get('displayName') or gpo.get('name') or 'Not available'}",
            f"GUID: {gpo.get('objectGUID') or 'Not available'}",
            f"Distinguished Name: {gpo.get('distinguishedName') or 'Not available'}",
            f"SYSVOL path: {gpo.get('gPCFileSysPath') or 'Not available'}",
            f"Assessment status: {gpo.get('assessment_status', 'Discovered')}",
            f"Content status: {gpo.get('content_status', 'Not assessed')}",
            f"Content note: {gpo.get('content_assessment_reason') or 'No additional limitation recorded.'}",
            f"Parsed setting records: {len(gpo.get('settings', []))}",
            f"Findings: {len(findings)}",
            "Scope: linked-policy observation only; effective endpoint processing was not evaluated.",
        ]
        self.readable.setPlainText("\n".join(readable_lines))
        self.finding_details.setPlainText("\n\n".join(
            f"{item.severity.value}: {item.title}\n{item.description}\nEvidence: "
            f"{json.dumps(item.evidence, indent=2, default=str)}"
            for item in findings
        ) or "No rule findings for this GPO. This does not imply uninspected settings are safe.")
        self.link_details.setPlainText(json.dumps(links, indent=2, sort_keys=True, default=str) or "No discovered links.")
        self.raw_attributes.setPlainText(json.dumps(gpo.get("source_attributes", {}), indent=2, sort_keys=True, default=str))
        self.source_evidence.setPlainText(json.dumps(gpo.get("settings", []), indent=2, sort_keys=True, default=str))

    def _clear_details(self) -> None:
        for panel in (self.readable, self.finding_details, self.link_details, self.raw_attributes, self.source_evidence):
            panel.clear()
