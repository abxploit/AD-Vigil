"""Evidence-linked defensive correlation and combined JSON reporting."""

import json
from collections import defaultdict
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from core.defensive_detections import DETECTION_RULE_EVENT_IDS, DetectionAlert, alert_to_dict
from core.models import Finding
from core.telemetry import LogSourceCoverage, NormalizedEvent

NOT_EVALUATED = "Not evaluated"
TELEMETRY_UNAVAILABLE = "Telemetry unavailable"
NO_MATCH = "No matching events observed"
MATCHED = "Matching events found"
INCONCLUSIVE = "Inconclusive"

RULE_COVERAGE: dict[str, dict[str, Any]] = {
    "DET-AUTH-001": {"event_ids": DETECTION_RULE_EVENT_IDS["DET-AUTH-001"], "channels": ["Security"]},
    "DET-AUTH-002": {"event_ids": DETECTION_RULE_EVENT_IDS["DET-AUTH-002"], "channels": ["Security"]},
    "DET-AD-001": {"event_ids": DETECTION_RULE_EVENT_IDS["DET-AD-001"], "channels": ["Security"]},
    "DET-AD-002": {"event_ids": DETECTION_RULE_EVENT_IDS["DET-AD-002"], "channels": ["Security"]},
    "DET-PS-001": {"event_ids": DETECTION_RULE_EVENT_IDS["DET-PS-001"], "channels": ["PowerShell Operational", "Security process creation", "Sysmon"]},
    "DET-KRB-001": {"event_ids": DETECTION_RULE_EVENT_IDS["DET-KRB-001"], "channels": ["Security"]},
    "DET-KRB-002": {"event_ids": DETECTION_RULE_EVENT_IDS["DET-KRB-002"], "channels": ["Security"]},
    "DET-KRB-003": {"event_ids": DETECTION_RULE_EVENT_IDS["DET-KRB-003"], "channels": ["Security"]},
    "DET-AD-003": {"event_ids": DETECTION_RULE_EVENT_IDS["DET-AD-003"], "channels": ["Security"]},
    "DET-AD-004": {"event_ids": DETECTION_RULE_EVENT_IDS["DET-AD-004"], "channels": ["Security"]},
}

FINDING_RULES: dict[str, tuple[str, ...]] = {
    "Account Security": ("DET-AUTH-001", "DET-AUTH-002", "DET-AD-002", "DET-AD-001", "DET-AD-004"),
    "Privilege": ("DET-AD-001", "DET-AD-004", "DET-AUTH-002"),
    "Kerberos": ("DET-KRB-001", "DET-KRB-002", "DET-KRB-003", "DET-AUTH-002"),
    "Kerberos / Privilege": ("DET-KRB-001", "DET-KRB-002", "DET-KRB-003", "DET-AD-001"),
    "Delegation": ("DET-KRB-001", "DET-KRB-002", "DET-KRB-003", "DET-AUTH-002"),
    "GPO Security": ("DET-AD-003", "DET-PS-001"),
    "OU Security": ("DET-AD-001", "DET-AD-003"),
    "Trust Security": ("DET-AUTH-001", "DET-AUTH-002", "DET-KRB-001", "DET-KRB-002"),
    "Protocol Security": ("DET-AUTH-001", "DET-AUTH-002"),
    "Configuration": ("DET-AD-003", "DET-PS-001"),
}

INVESTIGATION_GUIDANCE = {
    "Account Security": ["Review authentication failures, successful logons, and account lifecycle events for the affected identity."],
    "Privilege": ["Review privileged group membership changes, the actor, approvals, and subsequent sign-ins."],
    "Kerberos": ["Review 4768/4769 details, source host, requested service, encryption type, and endpoint process context."],
    "Kerberos / Privilege": ["Review Kerberos ticket activity and privileged group changes for the affected identity."],
    "Delegation": ["Review Kerberos ticket events and endpoint process telemetry; the configuration alone does not show use."],
    "GPO Security": ["Review directory change events for gPLink, gPOptions, or nTSecurityDescriptor and correlate process activity."],
    "OU Security": ["Review directory change events and privileged membership changes associated with the OU and its objects."],
    "Trust Security": ["Review sign-in and Kerberos records on both sides through authorized domain monitoring; partner logs were not imported unless listed."],
    "Protocol Security": ["Review authentication telemetry and server-side policy/event logs; client negotiation does not reveal all server settings."],
    "Configuration": ["Review relevant directory change and process telemetry around the configuration object's change window."],
}


def _normalize(value: Any) -> str:
    return str(value or "").strip().casefold().split("\\")[-1]


def _channel_matches(actual: str, expected: str) -> bool:
    value = actual.casefold()
    expected = expected.casefold()
    if expected == "security process creation":
        return value == "security"
    if expected == "powershell operational":
        return "powershell" in value and "operational" in value
    if expected == "sysmon":
        return "sysmon" in value
    return value == expected.casefold() or value.endswith("/" + expected.casefold())


def _finding_identifiers(finding: Finding) -> set[str]:
    identifiers = {_normalize(finding.affected_object)}
    keys = (
        "sAMAccountName", "user", "target_account", "gpo_dn", "ou_dn", "dn",
        "distinguishedName", "object_dn", "gpo_name", "name", "source_ip",
    )
    for key in keys:
        value = finding.evidence.get(key)
        if isinstance(value, str) and value:
            identifiers.add(_normalize(value))
    return {value for value in identifiers if value}


def _alert_matches_finding(alert: DetectionAlert, finding: Finding) -> bool:
    identity = _finding_identifiers(finding)
    alert_identity = {
        _normalize(value)
        for value in (alert.account, alert.target_group, alert.member, alert.target_object, alert.host, *alert.affected_accounts)
        if value
    }
    if not identity or not alert_identity:
        return False
    return bool(identity & alert_identity)


def _alert_tokens(alert: DetectionAlert) -> set[str]:
    return {
        _normalize(value)
        for value in (alert.account, alert.target_group, alert.member, alert.target_object, alert.host)
        if value
    }


def _rule_state(
    rule_id: str,
    rule_events: list[NormalizedEvent],
    rule_alerts: list[DetectionAlert],
    finding: Finding,
    matching_sources: list[LogSourceCoverage],
    analysis_complete: bool,
    fields_inconclusive: bool,
) -> tuple[str, list[DetectionAlert], str]:
    profile = RULE_COVERAGE[rule_id]
    channel_available = bool(matching_sources)
    if not rule_events and not channel_available:
        return TELEMETRY_UNAVAILABLE, [], "Required event IDs/channels were not represented in imported sources."
    matched = [
        alert for alert in rule_alerts if _alert_matches_finding(alert, finding)
    ]
    if matched:
        return MATCHED, matched, "A detection alert with matching identity evidence was found."
    if not analysis_complete:
        return INCONCLUSIVE, [], "Detection analysis was cancelled before all applicable rules completed."
    if any(source.status in {"Partial", "Cancelled", "Failed"} or source.parse_error_count for source in matching_sources):
        return INCONCLUSIVE, [], "Relevant sources were present but parsing or collection coverage was incomplete."
    if rule_events and fields_inconclusive:
        return INCONCLUSIVE, [], "Relevant events exist, but required identity or behavior fields are missing."
    if channel_available or rule_events:
        return NO_MATCH, [], "No matching event pattern was observed in the imported data range; this does not establish that no activity occurred."
    return TELEMETRY_UNAVAILABLE, [], "No sufficient telemetry coverage was supplied."


def _events_inconclusive(rule_id: str, events: list[NormalizedEvent]) -> bool:
    def has_field(event: NormalizedEvent, *names: str) -> bool:
        wanted = {re.sub(r"[^a-z0-9]", "", name.casefold()) for name in names}
        return any(re.sub(r"[^a-z0-9]", "", str(key).casefold().lstrip("@")) in wanted for key in event.event_data)

    if rule_id in {"DET-AUTH-001", "DET-AUTH-002"}:
        return any(not (event.target_account and event.host and event.source_ip and event.timestamp) for event in events)
    if rule_id == "DET-AD-001":
        return any(not (event.target_group or event.event_data.get("TargetSid")) for event in events)
    if rule_id == "DET-AD-002":
        return any(not (event.target_account or event.user) for event in events)
    if rule_id == "DET-PS-001":
        return any(not (event.command_line or event.description) for event in events)
    if rule_id == "DET-KRB-001":
        return any(not has_field(event, "PreAuthType", "PreAuthenticationType") for event in events)
    if rule_id == "DET-KRB-002":
        return any(not has_field(event, "TicketEncryptionType", "TicketEncryption") for event in events)
    if rule_id == "DET-KRB-003":
        return any(not (event.target_account and event.host and event.source_ip and event.timestamp) for event in events)
    if rule_id == "DET-AD-003":
        return any(
            not (has_field(event, "AttributeLDAPDisplayName", "AttributeName") and has_field(event, "ObjectDN", "ObjectDistinguishedName"))
            for event in events
        )
    if rule_id == "DET-AD-004":
        return any(
            (event.event_id == "4720" and not event.target_account)
            or (event.event_id in {"4728", "4732", "4756"} and not (event.member and event.target_group))
            for event in events
        )
    return False


def correlate_findings(
    findings: list[Finding],
    events: list[NormalizedEvent],
    alerts: list[DetectionAlert],
    sources: list[LogSourceCoverage],
    analysis_complete: bool = True,
    cancellation_event: Any = None,
) -> list[dict[str, Any]]:
    correlations: list[dict[str, Any]] = []
    events_by_id: dict[str, list[NormalizedEvent]] = defaultdict(list)
    for event in events:
        if cancellation_event is not None and cancellation_event.is_set():
            analysis_complete = False
            break
        events_by_id[event.event_id].append(event)
    alerts_by_rule: dict[str, list[DetectionAlert]] = defaultdict(list)
    alerts_by_identity: dict[str, dict[str, list[DetectionAlert]]] = defaultdict(lambda: defaultdict(list))
    for alert in alerts:
        alerts_by_rule[alert.rule_id].append(alert)
        for token in _alert_tokens(alert):
            alerts_by_identity[alert.rule_id][token].append(alert)
    sources_by_rule = {
        rule_id: [
            source for source in sources
                if (
                    bool(set(source.event_ids) & profile["event_ids"])
                    or any(_channel_matches(actual, expected) for actual in source.channels for expected in profile["channels"])
                )
        ]
        for rule_id, profile in RULE_COVERAGE.items()
    }
    events_by_rule = {
        rule_id: [event for event_id in profile["event_ids"] for event in events_by_id.get(event_id, [])]
        for rule_id, profile in RULE_COVERAGE.items()
    }
    fields_inconclusive_by_rule = {
        rule_id: _events_inconclusive(rule_id, rule_events)
        for rule_id, rule_events in events_by_rule.items()
    }
    for finding in findings:
        if cancellation_event is not None and cancellation_event.is_set():
            break
        rule_ids = FINDING_RULES.get(finding.category)
        if not rule_ids:
            correlations.append({
                "finding_id": finding.finding_id,
                "finding_title": finding.title,
                "affected_object": finding.affected_object,
                "category": finding.category,
                "state": NOT_EVALUATED,
                "applicable_rules": [],
                "rule_assessments": [],
                "related_alert_ids": [],
                "investigation_steps": ["No detection mapping is configured for this finding category."],
                "remediation": finding.recommended_remediation,
                "retest_guidance": "Reassess the configuration after remediation and evaluate relevant telemetry separately.",
                "limitation": "No applicable correlation rule was evaluated.",
            })
            continue
        assessments: list[dict[str, Any]] = []
        related: list[DetectionAlert] = []
        for rule_id in rule_ids:
            if cancellation_event is not None and cancellation_event.is_set():
                analysis_complete = False
                break
            profile = RULE_COVERAGE[rule_id]
            rule_events = events_by_rule[rule_id]
            identities = _finding_identifiers(finding)
            candidate_alerts = {
                alert.alert_id: alert
                for token in identities
                for alert in alerts_by_identity[rule_id].get(token, [])
            }
            state, matched, reason = _rule_state(
                rule_id, rule_events, list(candidate_alerts.values()), finding,
                sources_by_rule[rule_id], analysis_complete,
                fields_inconclusive_by_rule[rule_id],
            )
            related.extend(matched)
            covered_sources = sources_by_rule[rule_id]
            ranges = [source for source in covered_sources if source.first_seen or source.last_seen]
            assessments.append({
                "rule_id": rule_id,
                "state": state,
                "required_event_ids": sorted(profile["event_ids"]),
                "required_channels": list(profile["channels"]),
                "observed_event_ids": sorted({event.event_id for event in rule_events}),
                "coverage_sources": [source.source_name for source in covered_sources],
                "evaluated_time_range": {
                    "first_seen": min((source.first_seen for source in ranges if source.first_seen), default=None),
                    "last_seen": max((source.last_seen for source in ranges if source.last_seen), default=None),
                },
                "reason": reason,
            })
        assessed_rules = {item["rule_id"] for item in assessments}
        for rule_id in rule_ids:
            if rule_id not in assessed_rules:
                profile = RULE_COVERAGE[rule_id]
                assessments.append({
                    "rule_id": rule_id,
                    "state": INCONCLUSIVE,
                    "required_event_ids": sorted(profile["event_ids"]),
                    "required_channels": list(profile["channels"]),
                    "observed_event_ids": [],
                    "coverage_sources": [],
                    "evaluated_time_range": {"first_seen": None, "last_seen": None},
                    "reason": "Correlation was cancelled before this rule was evaluated.",
                })
        states = {item["state"] for item in assessments}
        if MATCHED in states:
            overall = MATCHED
        elif INCONCLUSIVE in states:
            overall = INCONCLUSIVE
        elif TELEMETRY_UNAVAILABLE in states:
            overall = TELEMETRY_UNAVAILABLE
        else:
            overall = NO_MATCH
        alerts_by_id = {item.alert_id: item for item in related}
        correlations.append({
            "finding_id": finding.finding_id,
            "finding_title": finding.title,
            "affected_object": finding.affected_object,
            "category": finding.category,
            "severity": finding.severity.value,
            "finding_evidence": finding.evidence,
            "threat_scenario": finding.description,
            "state": overall,
            "applicable_rules": list(rule_ids),
            "rule_assessments": assessments,
            "related_alert_ids": sorted(alerts_by_id),
            "required_telemetry": sorted({
                f"{channel}: {', '.join(sorted(RULE_COVERAGE[rule_id]['event_ids']))}"
                for rule_id in rule_ids for channel in RULE_COVERAGE[rule_id]["channels"]
            }),
            "investigation_steps": INVESTIGATION_GUIDANCE.get(finding.category, []),
            "remediation": finding.recommended_remediation,
            "retest_guidance": "After remediation, confirm the AD configuration through a fresh read-only assessment; verify monitoring and alert generation using synthetic fixtures or approved lab telemetry.",
            "limitation": "An absent alert is not proof that the behavior did not occur. Export scope, retention, auditing policy, missing fields, and timestamps can limit conclusions.",
        })
    return correlations


def _jsonable(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat() if value.tzinfo else value.replace(tzinfo=timezone.utc).isoformat()
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, (bytes, bytearray, memoryview)):
        return {"encoding": "hex", "value": bytes(value).hex()}
    if is_dataclass(value):
        return _jsonable(asdict(value))
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(item) for item in value]
    return value


def build_json_report(
    assessment: dict[str, Any] | None,
    findings: list[Finding],
    sources: list[LogSourceCoverage],
    alerts: list[DetectionAlert],
    correlations: list[dict[str, Any]],
) -> dict[str, Any]:
    assessment = assessment or {}
    inventory_counts = {
        key: len(assessment.get(key, []))
        for key in (
            "users", "groups", "computers", "domain_controllers", "spns", "gpos", "ous", "trusts",
        )
    }
    finding_records = [{
        "finding_id": finding.finding_id,
        "title": finding.title,
        "severity": finding.severity.value,
        "category": finding.category,
        "affected_object": finding.affected_object,
        "affected_type": finding.affected_type,
        "description": finding.description,
        "evidence": finding.evidence,
        "remediation": finding.recommended_remediation,
        "confidence": finding.confidence,
        "detected_at": finding.detected_at,
        "detection_limitations": finding.detection_limitations,
    } for finding in findings]
    source_records = [{
        "source_name": source.source_name,
        "format": source.format,
        "status": source.status,
        "imported_at": source.imported_at,
        "event_count": source.event_count,
        "incomplete_event_count": source.incomplete_event_count,
        "duplicate_count": source.duplicate_count,
        "parse_error_count": source.parse_error_count,
        "parse_errors": source.parse_errors,
        "channels": source.channels,
        "event_ids": source.event_ids,
        "first_seen": source.first_seen,
        "last_seen": source.last_seen,
        "synthetic": source.synthetic,
    } for source in sources]
    return _jsonable({
        "schema_version": 1,
        "product": {
            "name": "AD Vigil",
            "title": "AD Vigil — Active Directory Security Assessment & Purple Team Platform",
            "tagline": "Find the weakness. Detect the activity. Strengthen the domain.",
        },
        "generated_at": datetime.now(timezone.utc),
        "assessment_scope": {
            "domain": assessment.get("domain"),
            "domain_controller": assessment.get("server"),
            "base_dn": assessment.get("base_dn"),
            "assessment_completed_at": assessment.get("assessment_completed_at"),
        },
        "inventory_counts": inventory_counts,
        "findings": finding_records,
        "defensive": {
            "log_sources": source_records,
            "alerts": [alert_to_dict(alert) for alert in alerts],
            "correlations": correlations,
            "limitations": [
                "No matching event is not proof of absence.",
                "Imported telemetry reflects only its recorded sources and time range.",
                "Raw event payloads and full command lines are excluded from this report.",
            ],
        },
    })


def report_json_text(*args: Any, **kwargs: Any) -> str:
    return json.dumps(build_json_report(*args, **kwargs), indent=2, sort_keys=True, ensure_ascii=True)
