"""Read-only OU, trust, and protocol result views."""

import json
from typing import Any

from PySide6.QtCore import QSortFilterProxyModel, Qt
from PySide6.QtGui import QStandardItem, QStandardItemModel
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTreeView,
    QVBoxLayout,
    QWidget,
)

from core.models import Finding


class OUAssessmentView(QWidget):
    """Virtualized/searchable hierarchy with safe parsed-DACL summaries."""

    def __init__(self) -> None:
        super().__init__()
        self.ous: list[dict[str, Any]] = []
        self.findings: list[Finding] = []
        root = QVBoxLayout(self)
        self.coverage = QLabel("OU assessment has not run.")
        root.addWidget(self.coverage)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search OU name or distinguished name...")
        root.addWidget(self.search)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        self.tree = QTreeView()
        self.tree.setUniformRowHeights(True)
        self.source_model = QStandardItemModel(self)
        self.source_model.setHorizontalHeaderLabels(["Organizational Unit", "Distinguished Name"])
        self.proxy = QSortFilterProxyModel(self)
        self.proxy.setSourceModel(self.source_model)
        self.proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.proxy.setFilterRole(Qt.ItemDataRole.UserRole)
        self.proxy.setRecursiveFilteringEnabled(True)
        self.tree.setModel(self.proxy)
        self.search.textChanged.connect(self.proxy.setFilterFixedString)
        self.tree.selectionModel().currentChanged.connect(self._show_ou)
        splitter.addWidget(self.tree)
        self.details = QTabWidget()
        self.summary = self._panel()
        self.finding_panel = self._panel()
        self.link_panel = self._panel()
        self.raw_panel = self._panel()
        self.acl_panel = self._panel()
        for panel, title in (
            (self.summary, "Details"),
            (self.finding_panel, "Findings"),
            (self.link_panel, "GPO Links"),
            (self.raw_panel, "Raw LDAP"),
            (self.acl_panel, "Parsed DACL"),
        ):
            self.details.addTab(panel, title)
        splitter.addWidget(self.details)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 2)
        root.addWidget(splitter, 1)
        self._by_dn: dict[str, dict[str, Any]] = {}

    @staticmethod
    def _panel() -> QPlainTextEdit:
        panel = QPlainTextEdit()
        panel.setReadOnly(True)
        return panel

    def set_results(
        self,
        ous: list[dict[str, Any]],
        findings: list[Finding],
        discovery_status: str,
        acl_status: str,
    ) -> None:
        self.ous = ous
        self.findings = [item for item in findings if item.category == "OU Security"]
        self._by_dn = {str(item.get("distinguishedName", "")).casefold(): item for item in ous}
        self.coverage.setText(
            f"OU discovery: {discovery_status}    OUs: {len(ous)}    "
            f"DACL coverage: {acl_status}    Findings: {len(self.findings)}"
        )
        self.source_model.removeRows(0, self.source_model.rowCount())
        items_by_dn: dict[str, QStandardItem] = {}
        children: dict[str, list[dict[str, Any]]] = {}
        for ou in ous:
            children.setdefault(str(ou.get("parent_ou_dn", "")).casefold(), []).append(ou)
        self.tree.setUpdatesEnabled(False)
        try:
            roots = children.get("", [])
            stack = [(ou, self.source_model.invisibleRootItem()) for ou in roots]
            while stack:
                ou, parent_item = stack.pop()
                dn = str(ou.get("distinguishedName", ""))
                display_name = str(ou.get("name") or dn or "Unnamed OU")
                name_item = QStandardItem(display_name)
                dn_item = QStandardItem(dn)
                name_item.setData(f"{display_name} {dn}".casefold(), Qt.ItemDataRole.UserRole)
                name_item.setData(dn.casefold(), Qt.ItemDataRole.UserRole + 1)
                parent_item.appendRow([name_item, dn_item])
                items_by_dn[dn.casefold()] = name_item
                for child in reversed(children.get(dn.casefold(), [])):
                    stack.append((child, name_item))
        finally:
            self.tree.setUpdatesEnabled(True)
        if ous:
            first = self.source_model.index(0, 0)
            current = self.proxy.mapFromSource(first)
            self.tree.setCurrentIndex(current)
            self.tree.expandToDepth(0)
            self._show_ou(current, current)
        else:
            self._clear()

    def _show_ou(self, current, _previous) -> None:
        source = self.proxy.mapToSource(current)
        dn = str(self.source_model.data(source.siblingAtColumn(0), Qt.ItemDataRole.UserRole + 1) or "")
        ou = self._by_dn.get(dn)
        if ou is None:
            self._clear()
            return
        ou_findings = [item for item in self.findings if item.evidence.get("ou_dn", "").casefold() == dn]
        counts = ou.get("contained_counts", {})
        lines = [
            f"Name: {ou.get('name') or 'Not available'}",
            f"Distinguished Name: {dn}",
            f"Parent OU: {ou.get('parent_ou_dn') or 'Domain root'}",
            f"Domain placement: {ou.get('domain_dn') or 'Not available'}",
            f"Child OUs: {len(ou.get('child_ous', []))}",
            f"Known direct contained objects: {sum(counts.values())}",
            f"Contained counts: {json.dumps(counts, sort_keys=True)}",
            f"Managed by: {ou.get('managedBy') or 'Not returned'}",
            f"Created: {ou.get('whenCreated') or 'Not returned'}",
            f"Changed: {ou.get('whenChanged') or 'Not returned'}",
            f"Description: {ou.get('description') or 'Not returned'}",
            f"Security descriptor: {ou.get('security_descriptor_status', 'Not assessed')}",
            f"Findings: {len(ou_findings)}",
            "Policy scope note: direct links are not effective policy; inheritance and processing were not evaluated.",
        ]
        self.summary.setPlainText("\n".join(lines))
        self.finding_panel.setPlainText("\n\n".join(
            f"{item.severity.value}: {item.title}\n{item.description}\n"
            f"Evidence: {json.dumps(item.evidence, indent=2, default=str)}"
            for item in ou_findings
        ) or "No findings for this OU. Uncollected ACL data is not considered safe.")
        self.link_panel.setPlainText(json.dumps({
            "gPLink": ou.get("gPLink"), "gPOptions": ou.get("gPOptions"),
            "parsed_direct_links": ou.get("direct_gpo_links", []),
            "child_ous": ou.get("child_ous", []),
        }, indent=2, sort_keys=True, default=str))
        self.raw_panel.setPlainText(json.dumps(ou.get("source_attributes", {}), indent=2, sort_keys=True, default=str))
        self.acl_panel.setPlainText(json.dumps({
            "status": ou.get("security_descriptor_status"),
            "parsed_descriptor": ou.get("security_descriptor"),
            "error": ou.get("security_descriptor_error"),
        }, indent=2, sort_keys=True, default=str))

    def _clear(self) -> None:
        for panel in (self.summary, self.finding_panel, self.link_panel, self.raw_panel, self.acl_panel):
            panel.clear()


class TrustAssessmentView(QWidget):
    """Trust inventory with direction explained relative to the source domain."""

    HEADERS = ("Trust partner", "Type", "Direction", "Transitive", "SID filtering", "Status")

    def __init__(self) -> None:
        super().__init__()
        self.trusts: list[dict[str, Any]] = []
        self.findings: list[Finding] = []
        layout = QVBoxLayout(self)
        self.coverage = QLabel("Trust discovery has not run.")
        layout.addWidget(self.coverage)
        explanation = QLabel("Inbound means the source domain accepts authentication from the partner; outbound means the source domain can authenticate to the partner. This does not prove reachability or successful authentication.")
        explanation.setWordWrap(True)
        layout.addWidget(explanation)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search trust partner, type, direction, or flags...")
        self.search.textChanged.connect(self._filter)
        layout.addWidget(self.search)
        self.table = QTableWidget(0, len(self.HEADERS))
        self.table.setHorizontalHeaderLabels(self.HEADERS)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.itemSelectionChanged.connect(self._show_selected)
        layout.addWidget(self.table, 2)
        self.details = self._panel()
        layout.addWidget(self.details, 1)

    @staticmethod
    def _panel() -> QPlainTextEdit:
        panel = QPlainTextEdit()
        panel.setReadOnly(True)
        return panel

    def set_results(self, trusts: list[dict[str, Any]], findings: list[Finding], status: str) -> None:
        self.trusts = trusts
        self.findings = [item for item in findings if item.category == "Trust Security"]
        self.coverage.setText(f"Trust discovery: {status}    Relationships: {len(trusts)}    Findings: {len(self.findings)}")
        self.search.clear()
        self._filter()

    def _filter(self, _text: str = "") -> None:
        query = self.search.text().casefold().strip()
        visible = [item for item in self.trusts if not query or query in json.dumps(item, default=str).casefold()]
        self.table.setRowCount(len(visible))
        for row, trust in enumerate(visible):
            direction = str(trust.get("direction", "unknown"))
            values = (
                str(trust.get("trustPartner") or "Not returned"),
                str(trust.get("type", "unknown")),
                f"{direction} (relative to {trust.get('source_domain', 'source domain')})",
                _yes_no_unknown(trust.get("transitive")),
                _yes_no_unknown(trust.get("sid_filtering_enabled")),
                str(trust.get("collection_status", "Discovered")),
            )
            for column, value in enumerate(values):
                cell = QTableWidgetItem(value)
                cell.setData(Qt.ItemDataRole.UserRole, trust)
                cell.setToolTip(value)
                self.table.setItem(row, column, cell)
        if visible:
            self.table.selectRow(0)
        else:
            self.details.clear()

    def _show_selected(self) -> None:
        row = self.table.currentRow()
        trust = self.table.item(row, 0).data(Qt.ItemDataRole.UserRole) if row >= 0 else None
        if trust is None:
            self.details.clear()
            return
        partner = str(trust.get("trustPartner", "")).casefold()
        findings = [item for item in self.findings if item.affected_object.casefold() == partner]
        self.details.setPlainText(
            f"Trust evidence:\n{json.dumps(trust, indent=2, sort_keys=True, default=str)}\n\n"
            f"Findings:\n" + ("\n".join(f"{item.severity.value}: {item.title}\n{item.description}" for item in findings) or "No findings.")
        )


class ProtocolAssessmentView(QWidget):
    """Searchable protocol observations, with unknown configuration kept visible."""

    HEADERS = ("Check", "Status", "Port", "Target", "Evidence source")

    def __init__(self) -> None:
        super().__init__()
        self.protocols: list[dict[str, Any]] = []
        self.findings: list[Finding] = []
        layout = QVBoxLayout(self)
        self.coverage = QLabel("Protocol checks have not run.")
        layout.addWidget(self.coverage)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search service, result, hostname, or evidence...")
        self.search.textChanged.connect(self._filter)
        layout.addWidget(self.search)
        self.table = QTableWidget(0, len(self.HEADERS))
        self.table.setHorizontalHeaderLabels(self.HEADERS)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.itemSelectionChanged.connect(self._show_selected)
        layout.addWidget(self.table, 2)
        self.details = QPlainTextEdit()
        self.details.setReadOnly(True)
        layout.addWidget(self.details, 1)

    def set_results(self, protocols: list[dict[str, Any]], findings: list[Finding], status: str) -> None:
        self.protocols = protocols
        self.findings = [item for item in findings if item.category == "Protocol Security"]
        self.coverage.setText(f"Protocol assessment: {status}    Checks: {len(protocols)}    Findings: {len(self.findings)}")
        self.search.clear()
        self._filter()

    def _filter(self, _text: str = "") -> None:
        query = self.search.text().casefold().strip()
        visible = [item for item in self.protocols if not query or query in json.dumps(item, default=str).casefold()]
        self.table.setRowCount(len(visible))
        for row, protocol in enumerate(visible):
            values = (
                str(protocol.get("check", "Unknown")),
                str(protocol.get("status", "Unknown")),
                str(protocol.get("port", "Not applicable")),
                str(protocol.get("target_hostname") or protocol.get("target_ip") or "Not specified"),
                str(protocol.get("evidence_source", "Not recorded")),
            )
            for column, value in enumerate(values):
                cell = QTableWidgetItem(value)
                cell.setData(Qt.ItemDataRole.UserRole, protocol)
                cell.setToolTip(value)
                self.table.setItem(row, column, cell)
        if visible:
            self.table.selectRow(0)
        else:
            self.details.clear()

    def _show_selected(self) -> None:
        row = self.table.currentRow()
        protocol = self.table.item(row, 0).data(Qt.ItemDataRole.UserRole) if row >= 0 else None
        if protocol is None:
            self.details.clear()
            return
        check = str(protocol.get("check", ""))
        findings = [item for item in self.findings if item.evidence.get("check") == check]
        self.details.setPlainText(
            f"Observation:\n{json.dumps(protocol, indent=2, sort_keys=True, default=str)}\n\n"
            "LDAP signing and channel-binding policy remain unknown unless expressly reported.\n\n"
            f"Related findings:\n" + ("\n".join(f"{item.severity.value}: {item.title}\n{item.description}" for item in findings) or "No finding for this observation.")
        )


def _yes_no_unknown(value: Any) -> str:
    if value is True:
        return "Yes"
    if value is False:
        return "No"
    return "Unknown"
