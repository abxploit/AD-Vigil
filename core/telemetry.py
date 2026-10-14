"""Safe Windows event-log ingestion and normalization for defensive analysis."""

import csv
import hashlib
import io
import json
import logging
import re
import xml.etree.ElementTree as ET
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)
MAX_LOG_BYTES = 64 * 1024 * 1024
MAX_EVENTS = 100_000
MAX_TEXT_FIELD = 16_000
_SECRET_KEY = re.compile(r"password|passwd|credential|secret|token|cpassword|private.?key", re.IGNORECASE)
_SECRET_ASSIGNMENT = re.compile(
    r'(?i)\b(password|passwd|credential|secret|token|api[_-]?key)\b(\s*[:=]\s*|[ \t]+)("[^\"]*"|\'[^\']*\'|[^\s,;&]+)'
)


@dataclass(frozen=True, slots=True)
class NormalizedEvent:
    timestamp: datetime | None
    host: str = ""
    channel: str = ""
    provider: str = ""
    event_id: str = ""
    version: str = ""
    record_id: str = ""
    user: str = ""
    target_account: str = ""
    target_group: str = ""
    member: str = ""
    source_ip: str = ""
    logon_type: str = ""
    process_name: str = ""
    command_line: str = ""
    parent_process: str = ""
    description: str = ""
    event_data: dict[str, Any] = field(default_factory=dict)
    provenance: str = ""
    parse_status: str = "Normalized"
    synthetic: bool = False

    @property
    def account_key(self) -> str:
        return _normalize_identity(self.target_account or self.user)


@dataclass(slots=True)
class LogSourceCoverage:
    source_name: str
    format: str
    status: str
    imported_at: datetime
    event_count: int = 0
    incomplete_event_count: int = 0
    duplicate_count: int = 0
    parse_error_count: int = 0
    parse_errors: list[str] = field(default_factory=list)
    channels: list[str] = field(default_factory=list)
    event_ids: list[str] = field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    synthetic: bool = False


@dataclass(slots=True)
class IngestionResult:
    events: list[NormalizedEvent]
    source: LogSourceCoverage


ProgressCallback = Callable[[int, str], None]


def parse_timestamp(value: Any) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, dict):
        value = _lookup(value, "SystemTime", "TimeCreated", "Timestamp", "Value", "#text", "text")
        if value is None:
            return None
    if isinstance(value, datetime):
        parsed = value
    else:
        text = str(value).strip()
        if not text:
            return None
        if text.isdigit():
            return None
        parsed = None
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            for date_format in (
                "%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S",
                "%m-%d-%Y %H:%M:%S", "%d-%m-%Y %H:%M:%S",
                "%m/%d/%Y %I:%M %p", "%m/%d/%Y %H:%M",
            ):
                try:
                    parsed = datetime.strptime(text, date_format)
                    break
                except ValueError:
                    continue
        if parsed is None:
            return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _local_name(value: Any) -> str:
    return str(value).rsplit("}", 1)[-1].lstrip("@").casefold()


def _canonical_name(value: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", _local_name(value))


def _string(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, dict):
        for key in ("#text", "text", "value", "Value"):
            if key in value:
                return _string(value[key])
        nested = [_string(item) for key, item in value.items() if not str(key).startswith("@")]
        return " ".join(item for item in nested if item)[:MAX_TEXT_FIELD]
    if isinstance(value, list):
        return _string(value[0]) if value else ""
    return str(value).strip()[:MAX_TEXT_FIELD]


def _lookup(mapping: dict[str, Any], *names: str) -> Any:
    wanted = {_canonical_name(name) for name in names}
    for key, value in mapping.items():
        if _canonical_name(key) in wanted:
            return value
    return None


def _flatten_event(record: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    system: dict[str, Any] = {}
    data: dict[str, Any] = {}
    for key, value in record.items():
        local = _local_name(key)
        if local == "system" and isinstance(value, dict):
            system = value
        elif local in {"eventdata", "userdata"}:
            if isinstance(value, dict):
                data.update(_event_data_mapping(value))
            elif isinstance(value, list):
                data.update(_event_data_sequence(value))
    if not system:
        system = record
    if not data:
        for key, value in record.items():
            if isinstance(value, dict):
                for child_key, child_value in value.items():
                    if isinstance(child_value, (str, int, float, list, dict)):
                        data.setdefault(_local_name(child_key), child_value)
    return system, data


def _event_data_mapping(value: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, item in value.items():
        if _local_name(key) == "data":
            sequence = item if isinstance(item, list) else [item]
            for entry in sequence:
                if isinstance(entry, dict):
                    name = _lookup(entry, "Name") or _lookup(entry, "@Name") or _lookup(entry, "name")
                    text = _lookup(entry, "#text", "Value", "text")
                    if name:
                        nested = {
                            str(nested_key): nested_value for nested_key, nested_value in entry.items()
                            if _canonical_name(nested_key) not in {"name", "text", "value"}
                            and not str(nested_key).startswith("@")
                        }
                        if nested:
                            if text is not None:
                                nested.setdefault("#text", text)
                            result[str(name)] = nested
                        else:
                            result[str(name)] = text if text is not None else entry
        elif isinstance(item, dict):
            result[_local_name(key)] = item
        else:
            result[str(key)] = item
    return result


def _event_data_sequence(value: list[Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for entry in value:
        if not isinstance(entry, dict):
            continue
        name = _lookup(entry, "Name", "Field", "Key")
        if name:
            text = _lookup(entry, "#text", "Value", "Data", "text")
            nested = {
                str(key): item for key, item in entry.items()
                if _canonical_name(key) not in {"name", "field", "key", "text", "value", "data"}
                and not str(key).startswith("@")
            }
            if nested:
                if text is not None:
                    nested.setdefault("#text", text)
                result[str(name)] = nested
            else:
                result[str(name)] = text
        else:
            result.update({str(key): item for key, item in entry.items() if isinstance(item, (str, int, float))})
    return result


def _safe_value(key: str, value: Any) -> Any:
    if _SECRET_KEY.search(key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(child): _safe_value(str(child), item) for child, item in value.items()}
    if isinstance(value, list):
        return [_safe_value(key, item) for item in value[:100]]
    if isinstance(value, str):
        return _SECRET_ASSIGNMENT.sub(r"\1\2[REDACTED]", value[:MAX_TEXT_FIELD])
    return value


def _field(data: dict[str, Any], *names: str) -> str:
    value = _lookup(data, *names)
    return _string(value)


def _account_creation_message_fields(record: dict[str, Any]) -> dict[str, str]:
    """Extract named account fields from Event Viewer's flattened 4720 message."""
    overflow = _lookup(record, "__extra_columns__")
    values = overflow if isinstance(overflow, list) else [overflow]
    message = "\n".join(str(value) for value in values if value is not None)
    if not message:
        return {}

    fields: dict[str, str] = {}
    sections = (
        ("SubjectUserName", r"Subject\s*:", r"New\s+Account\s*:"),
        ("TargetUserName", r"New\s+Account\s*:", r"Attributes\s*:"),
    )
    for field_name, start_label, end_label in sections:
        section_match = re.search(
            rf"(?is)(?:^|\n)\s*{start_label}\s*(.*?)(?=(?:\n\s*{end_label})|$)",
            message,
        )
        if not section_match:
            continue
        account_match = re.search(r"(?im)^\s*Account\s+Name\s*:\s*([^\r\n]*)", section_match.group(1))
        if account_match:
            value = account_match.group(1).strip()
            if value and value not in {"-", "N/A", "n/a"}:
                fields[field_name] = value
    return fields


def normalize_record(record: dict[str, Any], provenance: str, synthetic: bool = False) -> NormalizedEvent:
    system, event_data = _flatten_event(record)
    event_id = _field(system, "EventID", "EventId", "Event ID", "Id")
    if not event_id and system is not record:
        event_id = _field(record, "EventID", "EventId", "Event ID", "Id")
    provider = _field(system, "ProviderName", "Provider", "Source")
    if not provider:
        provider_value = _lookup(system, "Provider")
        if isinstance(provider_value, dict):
            provider = _field(provider_value, "Name")
    raw_timestamp = _lookup(system, "SystemTime", "TimeCreated", "TimeCreatedSystemTime", "Timestamp", "TimeGenerated", "Date and Time", "DateTime", "Date")
    timestamp = parse_timestamp(raw_timestamp)
    if timestamp is None:
        raw_timestamp = _lookup(record, "TimeCreated", "Timestamp", "TimeGenerated", "Date and Time", "DateTime", "Date")
        timestamp = parse_timestamp(raw_timestamp)
    channel = _field(system, "Channel", "LogName", "ChannelName") or _field(record, "Channel", "LogName")
    host = _field(system, "Computer", "ComputerName", "Host") or _field(record, "Computer", "ComputerName", "Host")
    record_id = _field(system, "EventRecordID", "RecordId", "RecordID") or _field(record, "EventRecordID", "RecordId")
    provider = provider or _field(record, "ProviderName", "Provider")
    if not event_data:
        event_data = {key: value for key, value in record.items() if _local_name(key) not in {
            "system", "eventdata", "userdata", "renderinginfo",
        }}
    if event_id == "4720":
        for key, value in _account_creation_message_fields(record).items():
            event_data.setdefault(key, value)
    safe_data = {str(key): _safe_value(str(key), value) for key, value in event_data.items()}
    command_line = _field(safe_data, "CommandLine", "ScriptBlockText", "HostApplication", "ScriptBlock")
    message = _lookup(record, "Message", "Description")
    if not message:
        rendering = _lookup(record, "RenderingInfo")
        message = _lookup(rendering, "Message") if isinstance(rendering, dict) else None
    user = _field(safe_data, "SubjectUserName", "SubjectAccount", "User", "AccountName")
    target = _field(safe_data, "TargetUserName", "TargetAccount", "AccountTarget")
    if not target and event_id in {"4624", "4625", "4768", "4769"}:
        target = _field(safe_data, "TargetUserName", "AccountName")
    parse_warnings = []
    if not event_id:
        parse_warnings.append("Event ID missing")
    if timestamp is None:
        warning = "Timestamp missing" if raw_timestamp in (None, "") else "Timestamp lacks a supported timezone or format"
        parse_warnings.append(warning)
    safe_message = _safe_value("description", message)
    normalized = NormalizedEvent(
        timestamp=timestamp,
        host=host,
        channel=channel,
        provider=provider,
        event_id=event_id,
        version=_field(system, "Version"),
        record_id=record_id,
        user=user,
        target_account=target,
        target_group=_field(safe_data, "TargetGroupName", "TargetUserName", "GroupName"),
        member=_field(safe_data, "MemberName", "MemberSid", "TargetMemberName"),
        source_ip=_field(safe_data, "IpAddress", "SourceAddress", "SourceIp", "ClientAddress"),
        logon_type=_field(safe_data, "LogonType"),
        process_name=_field(safe_data, "NewProcessName", "ProcessName", "Image"),
        command_line=command_line,
        parent_process=_field(safe_data, "ParentProcessName", "ParentImage", "CreatorProcessName"),
        description=_string(safe_message),
        event_data=safe_data,
        provenance=provenance,
        parse_status="Partial: " + "; ".join(parse_warnings) if parse_warnings else "Normalized",
        synthetic=synthetic,
    )
    if event_id == "4720":
        logger.debug(
            "Normalized Windows account-creation event",
            extra={
                "telemetry_stage": "normalized",
                "event_id": event_id,
                "has_timestamp": normalized.timestamp is not None,
                "has_host": bool(normalized.host),
                "has_record_id": bool(normalized.record_id),
                "has_target_account": bool(normalized.target_account),
                "has_subject_user": bool(normalized.user),
                "event_data_keys": sorted(normalized.event_data),
            },
        )
    return normalized


def _xml_record(element: ET.Element) -> dict[str, Any]:
    def local(tag: str) -> str:
        return tag.rsplit("}", 1)[-1]

    record: dict[str, Any] = {}
    system: dict[str, Any] = {}
    event_data: list[dict[str, Any]] = []
    for child in element:
        child_name = local(child.tag)
        if child_name == "System":
            for system_item in child:
                key = local(system_item.tag)
                if key == "Provider":
                    system[key] = dict(system_item.attrib)
                elif key == "TimeCreated":
                    system["SystemTime"] = system_item.attrib.get("SystemTime", "")
                elif key == "EventID":
                    system[key] = system_item.text or ""
                else:
                    system[key] = system_item.text or ""
        elif child_name == "EventData":
            for data_item in child:
                value: dict[str, Any] = {"@Name": data_item.attrib.get("Name", "")}
                text = "".join(data_item.itertext()).strip()
                if text:
                    value["#text"] = text
                for nested in data_item:
                    value[local(nested.tag)] = _xml_nested_value(nested)
                event_data.append(value)
        elif child_name == "UserData":
            stack = list(child)
            while stack:
                node = stack.pop()
                children = list(node)
                if children:
                    stack.extend(reversed(children))
                else:
                    event_data.append({"@Name": local(node.tag), "#text": node.text or ""})
        elif child_name == "RenderingInfo":
            record[child_name] = {local(item.tag): item.text or "" for item in child}
    if system:
        record["System"] = system
    if event_data:
        record["EventData"] = {"Data": event_data}
    return record


def _xml_nested_value(element: ET.Element) -> Any:
    children = list(element)
    text = (element.text or "").strip()
    if not children:
        return text
    result: dict[str, Any] = {}
    if text:
        result["#text"] = text
    for child in children:
        key = child.tag.rsplit("}", 1)[-1]
        value = _xml_nested_value(child)
        if key in result:
            existing = result[key] if isinstance(result[key], list) else [result[key]]
            existing.append(value)
            result[key] = existing
        else:
            result[key] = value
    tail = (element.tail or "").strip()
    if tail:
        result.setdefault("#text", "")
        result["#text"] = f"{result['#text']} {tail}".strip()
    return result


def _records_from_xml(text: str) -> Iterable[dict[str, Any]]:
    if re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", text, re.IGNORECASE):
        raise ValueError("DTD and entity declarations are not supported")
    root = ET.fromstring(text)
    elements = [node for node in root.iter() if _local_name(node.tag) == "event"]
    for element in elements:
        yield _xml_record(element)


def _records_from_json(text: str, json_lines: bool) -> tuple[list[dict[str, Any]], list[str]]:
    errors: list[str] = []
    if json_lines:
        records: list[dict[str, Any]] = []
        for line_number, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
                records.extend(_unwrap_records(value))
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                errors.append(f"Line {line_number}: {type(exc).__name__}")
        return records, errors
    value = json.loads(text)
    return _unwrap_records(value), errors


def _unwrap_records(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        for key, item in value.items():
            if _local_name(key) in {"events", "records", "items"} and isinstance(item, list):
                return [entry for entry in item if isinstance(entry, dict)]
        return [value]
    return []


def _event_key(event: NormalizedEvent) -> str:
    if event.record_id and event.host and event.channel:
        identity = (event.host.casefold(), event.channel.casefold(), event.record_id, event.event_id)
    else:
        identity = (
            event.timestamp.isoformat() if event.timestamp else "",
            event.host.casefold(), event.channel.casefold(), event.provider.casefold(), event.event_id,
            event.user.casefold(), event.target_account.casefold(), event.source_ip,
            event.logon_type, event.target_group.casefold(), event.member.casefold(),
            event.process_name.casefold(), event.command_line,
            json.dumps(event.event_data, sort_keys=True, default=str, ensure_ascii=True),
        )
    return hashlib.sha256(repr(identity).encode("utf-8", errors="replace")).hexdigest()


def ingest_log_file(
    path: str | Path,
    cancellation_event: Any = None,
    progress: ProgressCallback | None = None,
    max_bytes: int = MAX_LOG_BYTES,
    max_events: int = MAX_EVENTS,
) -> IngestionResult:
    source_path = Path(path)
    coverage = LogSourceCoverage(
        source_name=source_path.name,
        format=source_path.suffix.casefold().lstrip(".") or "unknown",
        status="Failed",
        imported_at=datetime.now(timezone.utc),
    )
    if source_path.suffix.casefold() == ".evtx":
        coverage.format = "evtx"
        coverage.status = "Unsupported"
        coverage.parse_errors.append("EVTX parsing is unavailable; export the selected channels to XML or CSV.")
        coverage.parse_error_count = 1
        return IngestionResult([], coverage)
    try:
        size = source_path.stat().st_size
        if size > max_bytes:
            coverage.parse_errors.append(f"File exceeds {max_bytes} byte import limit.")
            coverage.parse_error_count = 1
            return IngestionResult([], coverage)
        payload = source_path.read_bytes()
    except OSError as exc:
        coverage.parse_errors.append(f"Unable to read file: {type(exc).__name__}")
        coverage.parse_error_count = 1
        return IngestionResult([], coverage)
    try:
        if payload.startswith((b"\xff\xfe", b"\xfe\xff")):
            text = payload.decode("utf-16")
        else:
            text = payload.decode("utf-8-sig")
    except UnicodeDecodeError:
        coverage.status = "Unsupported"
        coverage.parse_errors.append("File encoding is unsupported; EVTX and binary inputs are not parsed.")
        coverage.parse_error_count = 1
        return IngestionResult([], coverage)
    extension = source_path.suffix.casefold()
    raw_records: list[dict[str, Any]] = []
    try:
        if extension in {".json", ".jsonl", ".ndjson"}:
            json_lines = extension in {".jsonl", ".ndjson"}
            if extension == ".json":
                try:
                    raw_records, _errors = _records_from_json(text, False)
                except json.JSONDecodeError:
                    raw_records, _errors = _records_from_json(text, True)
                    json_lines = True
            else:
                raw_records, _errors = _records_from_json(text, json_lines)
            if json_lines:
                _records, parse_errors = _records_from_json(text, True)
            else:
                parse_errors = []
        elif extension == ".csv":
            reader = csv.DictReader(io.StringIO(text), strict=True, restkey="__extra_columns__")
            headers = {re.sub(r"[^a-z0-9]", "", str(name).casefold()) for name in (reader.fieldnames or [])}
            if not headers.intersection({"eventid", "id"}):
                raise ValueError("CSV is missing a recognizable event ID column")
            raw_records = [dict(row) for row in reader]
            parse_errors = []
            overflow_rows = sum(bool(row.get("__extra_columns__")) for row in raw_records)
            if overflow_rows:
                parse_errors.append(
                    f"{overflow_rows} CSV row(s) contained unheaded extra columns; values were retained but not mapped to event fields."
                )
        elif extension == ".xml":
            raw_records = list(_records_from_xml(text))
            parse_errors = []
        else:
            coverage.status = "Unsupported"
            coverage.parse_errors.append(f"Unsupported file format: {extension or 'unknown'}")
            coverage.parse_error_count = 1
            return IngestionResult([], coverage)
    except (ET.ParseError, json.JSONDecodeError, csv.Error, ValueError) as exc:
        detail = str(exc) if isinstance(exc, ValueError) and str(exc) else type(exc).__name__
        coverage.parse_errors.append(f"Malformed {coverage.format.upper()} input: {detail}")
        coverage.parse_error_count = 1
        return IngestionResult([], coverage)

    coverage.parse_errors.extend(parse_errors)
    events: list[NormalizedEvent] = []
    seen: set[str] = set()
    total = min(len(raw_records), max_events)
    if len(raw_records) > max_events:
        coverage.parse_errors.append(f"Event limit reached ({max_events}); remaining records were not loaded.")
    for index, record in enumerate(raw_records[:max_events]):
        if cancellation_event is not None and cancellation_event.is_set():
            coverage.status = "Cancelled"
            break
        if _field(record, "EventID", "EventId", "Event ID", "Id") == "4720":
            raw_message = _lookup(record, "__extra_columns__")
            raw_values = raw_message if isinstance(raw_message, list) else [raw_message]
            message_text = "\n".join(str(value) for value in raw_values if value is not None)
            logger.debug(
                "Parsed Windows account-creation input record",
                extra={
                    "telemetry_stage": "parsed",
                    "event_id": "4720",
                    "record_keys": sorted(str(key) for key in record),
                    "has_timestamp_field": _lookup(record, "SystemTime", "TimeCreated", "Date and Time") is not None,
                    "has_host_field": _lookup(record, "Computer", "ComputerName", "Host") is not None,
                    "has_record_id_field": _lookup(record, "EventRecordID", "RecordId") is not None,
                    "has_target_field": _lookup(record, "TargetUserName") is not None,
                    "has_subject_field": _lookup(record, "SubjectUserName") is not None,
                    "has_subject_message_label": bool(re.search(r"(?im)^\s*Subject\s*:", message_text)),
                    "has_new_account_message_label": bool(re.search(r"(?im)^\s*New\s+Account\s*:", message_text)),
                    "message_chars": len(message_text),
                },
            )
        event = normalize_record(record, coverage.source_name)
        key = _event_key(event)
        if key in seen:
            coverage.duplicate_count += 1
            continue
        seen.add(key)
        events.append(event)
        if progress and (index % 500 == 0 or index + 1 == total):
            progress(round((index + 1) * 100 / max(total, 1)), f"Normalized {index + 1} events")
    coverage.event_count = len(events)
    coverage.incomplete_event_count = sum(event.parse_status != "Normalized" for event in events)
    coverage.parse_error_count = len(coverage.parse_errors)
    coverage.channels = sorted({event.channel for event in events if event.channel})
    coverage.event_ids = sorted({event.event_id for event in events if event.event_id})
    timestamps = [event.timestamp for event in events if event.timestamp is not None]
    coverage.first_seen = min(timestamps) if timestamps else None
    coverage.last_seen = max(timestamps) if timestamps else None
    if coverage.status != "Cancelled":
        coverage.status = "Partial" if coverage.parse_errors or coverage.incomplete_event_count else "Completed"
    logger.info(
        "Telemetry import completed",
        extra={"format": coverage.format, "event_count": coverage.event_count, "status": coverage.status},
    )
    return IngestionResult(events, coverage)


def _normalize_identity(value: str) -> str:
    return str(value or "").strip().casefold().split("\\")[-1]
