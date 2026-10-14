"""Readable and raw views over the existing LDAP inventory records."""

import json
import ipaddress
from datetime import datetime, timezone
from typing import Any

from PySide6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QRegularExpression,
    QSortFilterProxyModel,
    QTimer,
    Qt,
)
from PySide6.QtGui import QColor, QFontDatabase
from PySide6.QtWidgets import (
    QAbstractItemView,
    QButtonGroup,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QStackedWidget,
    QTableView,
    QVBoxLayout,
    QWidget,
    QHeaderView,
)


TABLE_HEADERS = {
    "users": ("Username", "Display name", "Status", "Email"),
    "groups": ("Group name", "Type", "SAM account name"),
    "computers": ("Hostname", "Role", "Operating system", "Computer account"),
    "domain_controllers": (
        "Hostname", "IP address", "Domain", "Operating system", "Computer account"
    ),
    "spns": ("Account", "SPN count", "Hostname"),
}


def _values(record: dict[str, Any], key: str) -> list[Any]:
    if key not in record or record[key] is None:
        return []
    value = record[key]
    if isinstance(value, (list, tuple)):
        return list(value)
    if value == "":
        return []
    return [value]


def _value(record: dict[str, Any], key: str, empty: str = "Not available") -> str:
    if key not in record or record[key] is None:
        return "Not available"
    values = _values(record, key)
    if not values:
        return "None detected" if isinstance(record[key], (list, tuple)) else empty
    return ", ".join(str(value) for value in values)


def format_last_logon(record: dict[str, Any]) -> str:
    values = _values(record, "lastLogonTimestamp")
    if not values:
        return "Not available"
    value = values[0]
    if isinstance(value, datetime):
        timestamp = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return timestamp.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    try:
        number = int(value)
        if number == 0:
            return "Never"
        seconds = number / 10_000_000 - 11_644_473_600 if number > 10**14 else number
        timestamp = datetime.fromtimestamp(seconds, timezone.utc)
        return timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
    except (TypeError, ValueError, OverflowError, OSError):
        pass
    try:
        timestamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        return timestamp.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except ValueError:
        return str(value)


def _user_status(record: dict[str, Any]) -> str:
    values = _values(record, "userAccountControl")
    if not values:
        return "Not available"
    try:
        return "Disabled" if int(values[0]) & 2 else "Enabled"
    except (TypeError, ValueError):
        return "Not available"


def _group_type(record: dict[str, Any]) -> tuple[str, str]:
    values = _values(record, "groupType")
    if not values:
        return "Not available", "Not available"
    try:
        flags = int(values[0]) & 0xFFFFFFFF
    except (TypeError, ValueError):
        return "Not available", "Not available"
    kind = "Security group" if flags & 0x80000000 else "Distribution group"
    scope = next(
        (label for bit, label in ((2, "Global"), (4, "Domain local"), (8, "Universal")) if flags & bit),
        "Not available",
    )
    return kind, scope


def _domain_controller_ip(record: dict[str, Any], context: dict[str, Any]) -> str:
    address = _value(record, "ipAddress")
    if address != "Not available" and address != "None detected":
        return address
    controllers = context.get("domain_controllers", [])
    record_dn = record.get("dn")
    if len(controllers) == 1 and record_dn and controllers[0].get("dn") == record_dn:
        try:
            return str(ipaddress.ip_address(str(context.get("server", ""))))
        except ValueError:
            pass
    return address


def _computer_role(record: dict[str, Any], context: dict[str, Any]) -> str:
    dn = _value(record, "dn")
    if dn != "Not available" and dn.casefold() in {
        str(item.get("dn", "")).casefold()
        for item in context.get("domain_controllers", [])
    }:
        return "Domain Controller"
    flags = _values(record, "userAccountControl")
    try:
        if flags and int(flags[0]) & 8192:
            return "Domain Controller"
    except (TypeError, ValueError):
        pass
    operating_system = _value(record, "operatingSystem").casefold()
    if "windows server" in operating_system:
        return "Member Server"
    if "windows 10" in operating_system or "windows 11" in operating_system:
        return "Workstation"
    return "Not available"


def _table_values(kind: str, record: dict[str, Any], context: dict[str, Any]) -> list[str]:
    if kind == "users":
        return [
            _value(record, "sAMAccountName"),
            _value(record, "displayName"),
            _user_status(record),
            _value(record, "mail"),
        ]
    if kind == "groups":
        group_type, scope = _group_type(record)
        return [
            _value(record, "name"),
            f"{group_type} / {scope}" if scope != "Not available" else group_type,
            _value(record, "sAMAccountName"),
        ]
    if kind == "computers":
        return [
            _value(record, "dNSHostName"),
            _computer_role(record, context),
            _value(record, "operatingSystem"),
            _value(record, "sAMAccountName"),
        ]
    if kind == "domain_controllers":
        return [
            _value(record, "dNSHostName"),
            _domain_controller_ip(record, context),
            _value(context, "domain"),
            _value(record, "operatingSystem"),
            _value(record, "sAMAccountName"),
        ]
    spns = _values(record, "servicePrincipalName")
    return [
        _value(record, "sAMAccountName"),
        str(len(spns)) if spns else "None detected",
        _value(record, "dNSHostName"),
    ]


def format_user_details(record: dict[str, Any]) -> str:
    lines = [
        f"Username: {_value(record, 'sAMAccountName')}",
        f"Display name: {_value(record, 'displayName')}",
        f"Status: {_user_status(record)}",
        f"Description: {_value(record, 'description')}",
        f"Email: {_value(record, 'mail')}",
        f"Distinguished Name: {_value(record, 'dn')}",
        f"Last Logon: {format_last_logon(record)}",
        f"User Account Control: {_value(record, 'userAccountControl')}",
    ]
    if "memberOf" in record:
        lines.append(f"Groups / memberships: {_value(record, 'memberOf')}")
    if "servicePrincipalName" in record:
        lines.append(f"Service Principal Names: {_value(record, 'servicePrincipalName')}")
    return "\n".join(lines)


def format_group_details(record: dict[str, Any]) -> str:
    group_type, scope = _group_type(record)
    lines = [
        f"Group name: {_value(record, 'name')}",
        f"Type: {group_type}",
        f"Scope: {scope}",
        f"Description: {_value(record, 'description')}",
        f"SAM account name: {_value(record, 'sAMAccountName')}",
        f"Distinguished Name: {_value(record, 'dn')}",
    ]
    if "member" in record:
        lines.append(f"Members: {_value(record, 'member')}")
    return "\n".join(lines)


def format_computer_details(record: dict[str, Any], context: dict[str, Any]) -> str:
    return "\n".join((
        f"Hostname: {_value(record, 'dNSHostName')}",
        f"Role: {_computer_role(record, context)}",
        f"Operating System: {_value(record, 'operatingSystem')}",
        f"OS Version: {_value(record, 'operatingSystemVersion')}",
        f"Computer account: {_value(record, 'sAMAccountName')}",
        f"Distinguished Name: {_value(record, 'dn')}",
        f"Last Logon: {format_last_logon(record)}",
    ))


def format_domain_controller_details(record: dict[str, Any], context: dict[str, Any]) -> str:
    return "\n".join((
        f"DC hostname: {_value(record, 'dNSHostName')}",
        f"IP address: {_domain_controller_ip(record, context)}",
        f"Domain: {_value(context, 'domain')}",
        f"Operating System: {_value(record, 'operatingSystem')}",
        f"OS Version: {_value(record, 'operatingSystemVersion')}",
        f"Distinguished Name: {_value(record, 'dn')}",
        f"Computer account: {_value(record, 'sAMAccountName')}",
    ))


def format_spn_details(record: dict[str, Any]) -> str:
    spns = _values(record, "servicePrincipalName")
    spn_text = "\n".join(f"- {value}" for value in spns) if spns else "None detected"
    return "\n".join((
        f"Account: {_value(record, 'sAMAccountName')}",
        f"Hostname: {_value(record, 'dNSHostName')}",
        "SPNs:",
        spn_text,
        f"Distinguished Name: {_value(record, 'dn')}",
    ))


def format_details(kind: str, record: dict[str, Any], context: dict[str, Any]) -> str:
    if kind == "users":
        return format_user_details(record)
    if kind == "groups":
        return format_group_details(record)
    if kind == "computers":
        return format_computer_details(record, context)
    if kind == "domain_controllers":
        return format_domain_controller_details(record, context)
    return format_spn_details(record)


def domain_controller_name(data: dict[str, Any]) -> str:
    for record in data.get("domain_controllers", []):
        hostname = _value(record, "dNSHostName")
        if hostname != "Not available":
            return hostname
    server_name = data.get("server_name")
    if server_name and str(server_name).casefold() != "unknown":
        return str(server_name)
    return "Not available"


def serialize_raw_records(records: list[dict[str, Any]]) -> str:
    """Format the original result objects without projecting or dropping fields."""
    return json.dumps(records, indent=2, sort_keys=True, default=str)


class _CollectionTableModel(QAbstractTableModel):
    def __init__(self, kind: str, records: list[dict[str, Any]], context: dict[str, Any]) -> None:
        super().__init__()
        self.kind = kind
        self.records = records
        self.context = context
        self.search_values = [serialize_raw_records([record]).casefold() for record in records]

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.records)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(TABLE_HEADERS[self.kind])

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return None
        record = self.records[index.row()]
        values = _table_values(self.kind, record, self.context)
        if role == Qt.ItemDataRole.DisplayRole:
            return values[index.column()]
        if role == Qt.ItemDataRole.UserRole:
            return self.search_values[index.row()]
        if role == Qt.ItemDataRole.TextAlignmentRole:
            return int(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
        if role == Qt.ItemDataRole.BackgroundRole and self.kind == "users" and index.column() == 2:
            if values[2] == "Enabled":
                return QColor("#174b42")
            if values[2] == "Disabled":
                return QColor("#582f36")
        if role == Qt.ItemDataRole.ToolTipRole:
            return format_details(self.kind, record, self.context)
        return None

    def headerData(
        self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole
    ) -> Any:
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        if orientation == Qt.Orientation.Horizontal:
            return TABLE_HEADERS[self.kind][section]
        return section + 1


class CollectionResultView(QWidget):
    """A filterable readable view plus a lossless raw JSON view."""

    def __init__(self, kind: str, title: str) -> None:
        super().__init__()
        self.kind = kind
        self.title = title
        self.records: list[dict[str, Any]] = []
        self.context: dict[str, Any] = {}
        self.source_model: _CollectionTableModel | None = None
        self.raw_text = "[]"
        self._build_ui()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(6)

        toggle_row = QHBoxLayout()
        toggle_row.addStretch(1)
        self.readable_button = QPushButton("Readable")
        self.raw_button = QPushButton("Raw")
        self.readable_button.setCheckable(True)
        self.raw_button.setCheckable(True)
        self.readable_button.setProperty("viewToggle", True)
        self.raw_button.setProperty("viewToggle", True)
        self.view_group = QButtonGroup(self)
        self.view_group.setExclusive(True)
        self.view_group.addButton(self.readable_button, 0)
        self.view_group.addButton(self.raw_button, 1)
        self.readable_button.setChecked(True)
        toggle_row.addWidget(self.readable_button)
        toggle_row.addWidget(self.raw_button)
        root.addLayout(toggle_row)

        self.stack = QStackedWidget()
        self.readable_page = self._build_readable_page()
        self.raw_page = self._build_raw_page()
        self.stack.addWidget(self.readable_page)
        self.stack.addWidget(self.raw_page)
        root.addWidget(self.stack, 1)

        self.readable_button.toggled.connect(lambda checked: checked and self.stack.setCurrentIndex(0))
        self.raw_button.toggled.connect(lambda checked: checked and self.stack.setCurrentIndex(1))

    def _build_readable_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        self.search = QLineEdit()
        self.search.setPlaceholderText(f"Filter {self.title.lower()}...")
        layout.addWidget(self.search)

        self.table = QTableView()
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.setSortingEnabled(True)
        self.proxy = QSortFilterProxyModel(self)
        self.proxy.setFilterRole(Qt.ItemDataRole.UserRole)
        self.proxy.setFilterKeyColumn(-1)
        self.proxy.setSortCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.table.setModel(self.proxy)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table.horizontalHeader().setDefaultSectionSize(170)
        self.table.horizontalHeader().setMinimumSectionSize(100)
        self.table.horizontalHeader().setStretchLastSection(True)

        self.empty_state = QLabel("No matching records")
        self.empty_state.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.table_stack = QStackedWidget()
        self.table_stack.addWidget(self.table)
        self.table_stack.addWidget(self.empty_state)
        layout.addWidget(self.table_stack, 1)

        self.details = QPlainTextEdit()
        self.details.setReadOnly(True)
        self.details.setMaximumHeight(175)
        self.details.setPlaceholderText("Select a row to inspect readable details.")
        layout.addWidget(self.details)

        self.filter_timer = QTimer(self)
        self.filter_timer.setSingleShot(True)
        self.filter_timer.setInterval(140)
        self.filter_timer.timeout.connect(self._apply_filter)
        self.search.textChanged.connect(lambda _: self.filter_timer.start())
        self.proxy.rowsInserted.connect(self._sync_empty_state)
        self.proxy.rowsRemoved.connect(self._sync_empty_state)
        self.table.selectionModel().currentRowChanged.connect(self._show_selected_record)
        return page

    def _build_raw_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        toolbar = QHBoxLayout()
        toolbar.addStretch(1)
        self.copy_button = QPushButton("Copy JSON")
        self.copy_button.clicked.connect(self._copy_raw_json)
        toolbar.addWidget(self.copy_button)
        layout.addLayout(toolbar)
        self.raw_editor = QPlainTextEdit()
        self.raw_editor.setReadOnly(True)
        self.raw_editor.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.raw_editor.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        layout.addWidget(self.raw_editor, 1)
        return page

    def set_results(self, records: list[dict[str, Any]], context: dict[str, Any]) -> None:
        self.records = records
        self.context = context
        self.raw_text = serialize_raw_records(records)
        self.raw_editor.setPlainText(self.raw_text)
        model = _CollectionTableModel(self.kind, records, context)
        self.source_model = model
        self.proxy.setSourceModel(model)
        self.search.clear()
        self.readable_button.setChecked(True)
        self._sync_empty_state()
        if self.proxy.rowCount():
            self.table.selectRow(0)

    def _apply_filter(self) -> None:
        expression = QRegularExpression(
            QRegularExpression.escape(self.search.text()),
            QRegularExpression.PatternOption.CaseInsensitiveOption,
        )
        self.proxy.setFilterRegularExpression(expression)
        self._sync_empty_state()
        if self.proxy.rowCount():
            self.table.selectRow(0)
        else:
            self.details.clear()

    def _sync_empty_state(self, *_args: Any) -> None:
        empty = self.proxy.rowCount() == 0
        self.table_stack.setCurrentIndex(1 if empty else 0)
        if empty:
            self.details.setPlainText("No entries found." if not self.records else "No matching records.")

    def _show_selected_record(self, current: QModelIndex, _previous: QModelIndex) -> None:
        if not current.isValid():
            return
        source_index = self.proxy.mapToSource(current)
        record = self.records[source_index.row()]
        self.details.setPlainText(format_details(self.kind, record, self.context))

    def _copy_raw_json(self) -> None:
        from PySide6.QtWidgets import QApplication

        QApplication.clipboard().setText(self.raw_text)