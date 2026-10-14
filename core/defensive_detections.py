"""Focused rule-based detections over imported, normalized Windows events."""

import hashlib
import json
import logging
import re
from bisect import bisect_left
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from core.models import Severity
from core.telemetry import NormalizedEvent

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class DetectionAlert:
    alert_id: str
    rule_id: str
    title: str
    severity: Severity
    first_seen: datetime | None
    last_seen: datetime | None
    host: str = ""
    account: str = ""
    source_ip: str = ""
    target_group: str = ""
    member: str = ""
    target_object: str = ""
    affected_accounts: list[str] = field(default_factory=list)
    event_count: int = 0
    event_refs: list[dict[str, Any]] = field(default_factory=list)
    explanation: str = ""
    confidence: str = "Medium"
    investigation_steps: list[str] = field(default_factory=list)
    defensive_actions: list[str] = field(default_factory=list)
    mitre_attack: str = ""
    data_source: str = "Windows event telemetry"


def _identity(value: str) -> str:
    value = str(value or "").strip().casefold()
    return value.split("\\")[-1]


def _data(event: NormalizedEvent, *names: str) -> str:
    wanted = {re.sub(r"[^a-z0-9]", "", name.casefold()) for name in names}
    for key, value in event.event_data.items():
        if re.sub(r"[^a-z0-9]", "", str(key).casefold().lstrip("@")) in wanted:
            if isinstance(value, dict):
                return str(value.get("#text", value.get("value", "")))
            return str(value or "")
    return ""


def _reference(event: NormalizedEvent) -> dict[str, Any]:
    reference = {
        "source": event.provenance,
        "event_id": event.event_id,
        "record_id": event.record_id or None,
        "timestamp": event.timestamp.isoformat() if event.timestamp else None,
        "host": event.host or None,
        "channel": event.channel or None,
    }
    if not event.record_id:
        reference["event_fingerprint"] = hashlib.sha256(
            json.dumps(event.event_data, sort_keys=True, default=str, ensure_ascii=True).encode("utf-8", errors="replace")
        ).hexdigest()[:16]
    return reference


def _alert(
    rule_id: str,
    title: str,
    severity: Severity,
    events: list[NormalizedEvent],
    *,
    account: str = "",
    host: str = "",
    source_ip: str = "",
    target_group: str = "",
    member: str = "",
    target_object: str = "",
    affected_accounts: list[str] | None = None,
    explanation: str,
    confidence: str = "Medium",
    investigation: list[str],
    actions: list[str],
    mitre: str = "",
    identity_key: str = "",
) -> DetectionAlert:
    ordered = sorted((event for event in events if event.timestamp), key=lambda event: event.timestamp)
    first = ordered[0].timestamp if ordered else None
    last = ordered[-1].timestamp if ordered else None
    refs = sorted(
        (_reference(event) for event in events),
        key=lambda ref: (
            str(ref.get("timestamp") or ""), str(ref.get("host") or ""),
            str(ref.get("channel") or ""), str(ref.get("event_id") or ""),
            str(ref.get("record_id") or ""), str(ref.get("source") or ""),
        ),
    )
    seed = "|".join((rule_id, host.casefold(), account.casefold(), source_ip, target_group.casefold(), identity_key, repr(refs)))
    digest = hashlib.sha256(seed.encode("utf-8", errors="replace")).hexdigest()[:12].upper()
    return DetectionAlert(
        alert_id=f"{rule_id}-{digest}",
        rule_id=rule_id,
        title=title,
        severity=severity,
        first_seen=first,
        last_seen=last,
        host=host,
        account=account,
        source_ip=source_ip,
        target_group=target_group,
        member=member,
        target_object=target_object,
        affected_accounts=affected_accounts or [],
        event_count=len(events),
        event_refs=refs,
        explanation=explanation,
        confidence=confidence,
        investigation_steps=investigation,
        defensive_actions=actions,
        mitre_attack=mitre,
    )


def _valid_auth_key(event: NormalizedEvent) -> tuple[str, str, str, str] | None:
    account = _identity(event.target_account)
    host = _identity(event.host)
    source = event.source_ip.strip()
    if not account or not host or not source or source.casefold() in {"-", "unknown", "n/a", "0.0.0.0", "::"} or not event.timestamp:
        return None
    return account, host, source, str(event.logon_type or "").strip()


def _failure_clusters(
    events: list[NormalizedEvent], threshold: int, window: timedelta, cancellation_event: Any = None
) -> list[list[NormalizedEvent]]:
    grouped: dict[tuple[str, str, str, str], list[NormalizedEvent]] = defaultdict(list)
    for event in events:
        if cancellation_event is not None and cancellation_event.is_set():
            break
        key = _valid_auth_key(event)
        if event.event_id == "4625" and key:
            grouped[key].append(event)
    clusters: list[list[NormalizedEvent]] = []
    for key_events in grouped.values():
        if cancellation_event is not None and cancellation_event.is_set():
            break
        ordered = sorted(key_events, key=lambda item: item.timestamp)
        start = 0
        while start < len(ordered):
            if cancellation_event is not None and cancellation_event.is_set():
                break
            first_time = ordered[start].timestamp
            end = start + 1
            while end < len(ordered) and ordered[end].timestamp - first_time <= window:
                end += 1
            cluster = ordered[start:end]
            if len(cluster) >= threshold:
                clusters.append(cluster)
                start = end
            else:
                start += 1
    return clusters


def _authentication_alerts(
    events: list[NormalizedEvent], threshold: int, window: timedelta, cancellation_event: Any = None
) -> list[DetectionAlert]:
    alerts: list[DetectionAlert] = []
    for cluster in _failure_clusters(events, threshold, window, cancellation_event):
        if cancellation_event is not None and cancellation_event.is_set():
            break
        first = cluster[0]
        key = _valid_auth_key(first)
        account, host, source, _logon = key
        alerts.append(_alert(
            "DET-AUTH-001", "Repeated authentication failures observed", Severity.MEDIUM, cluster,
            account=first.target_account or first.user, host=first.host, source_ip=first.source_ip,
            explanation=f"{len(cluster)} event 4625 failures for the same account, host, source IP, and logon type occurred within {int(window.total_seconds())} seconds.",
            confidence="High" if len(cluster) >= threshold * 2 else "Medium",
            investigation=["Verify whether the account owner recognizes the source and time window.", "Review adjacent 4624/4625 events, logon type, and endpoint context."],
            actions=["Apply account protection and source restrictions consistent with policy if activity is unauthorized."],
            mitre="T1110",
            identity_key=f"{account}|{host}|{source}|{_logon}",
        ))

    successes: dict[tuple[str, str, str, str], list[NormalizedEvent]] = defaultdict(list)
    for event in events:
        if cancellation_event is not None and cancellation_event.is_set():
            break
        key = _valid_auth_key(event)
        if not key:
            continue
        if event.event_id == "4624":
            successes[key].append(event)
    success_times: dict[tuple[str, str, str, str], list[datetime]] = {}
    for key, success_events in successes.items():
        success_events.sort(key=lambda item: item.timestamp)
        success_times[key] = [event.timestamp for event in success_events]
    required_failures = min(threshold, 3)
    for cluster in _failure_clusters(events, required_failures, window, cancellation_event):
        if cancellation_event is not None and cancellation_event.is_set():
            break
        key = _valid_auth_key(cluster[0])
        if key is None:
            continue
        success_events = successes.get(key, [])
        times = success_times.get(key, [])
        if not success_events:
            continue
        threshold_time = cluster[required_failures - 1].timestamp
        start_index = bisect_left(times, threshold_time)
        end_time = cluster[0].timestamp + window
        end_index = bisect_left(times, end_time + timedelta(microseconds=1), lo=start_index)
        following = success_events[start_index:end_index]
        if not following:
            continue
        preceding_failures = [event for event in cluster if event.timestamp < following[0].timestamp]
        if len(preceding_failures) < required_failures:
            continue
        account, host, source, logon_type = key
        alerts.append(_alert(
            "DET-AUTH-002", "Successful logon followed repeated failures", Severity.MEDIUM,
            [*preceding_failures, *following], account=cluster[0].target_account,
            host=cluster[0].host, source_ip=cluster[0].source_ip,
            explanation=(
                f"{len(following)} event 4624 success record(s) followed at least {required_failures} event 4625 failures "
                f"for the same account, host, source IP, and logon type within {int(window.total_seconds())} seconds. "
                "This is suspicious for review, not proof of compromise."
            ),
            confidence="High" if len(cluster) >= threshold else "Medium",
            investigation=["Confirm the successful logon with the account owner and endpoint telemetry.", "Review authentication method, MFA result, source reputation, and subsequent activity."],
            actions=["Contain or reset credentials only through the incident-response process if the activity is confirmed unauthorized."],
            mitre="T1110",
            identity_key=f"{account}|{host}|{source}|{logon_type}|{following[0].record_id}",
        ))
    return alerts


_PRIVILEGED_GROUPS = {
    "administrators", "domain admins", "enterprise admins", "schema admins",
    "account operators", "server operators", "backup operators", "print operators",
    "dnsadmins", "key admins", "enterprise key admins",
}
_PRIVILEGED_RIDS = {"512", "518", "519", "544", "548", "549", "550", "551", "552"}


def _is_privileged_group(event: NormalizedEvent) -> bool:
    group = event.target_group or _data(event, "TargetUserName", "TargetGroupName", "GroupName")
    sid = _data(event, "TargetSid", "GroupSid")
    normalized = _identity(group).replace("$", "")
    first_cn = re.search(r"(?i)CN=([^,]+)", group)
    if first_cn:
        normalized = first_cn.group(1).casefold()
    return normalized in _PRIVILEGED_GROUPS or (sid and sid.rsplit("-", 1)[-1] in _PRIVILEGED_RIDS)


def _time_clusters(
    events: list[NormalizedEvent],
    key_function,
    window: timedelta,
    cancellation_event: Any = None,
) -> list[list[NormalizedEvent]]:
    groups: dict[tuple[str, ...], list[NormalizedEvent]] = defaultdict(list)
    untimed: list[NormalizedEvent] = []
    for event in events:
        if cancellation_event is not None and cancellation_event.is_set():
            break
        if event.timestamp is None:
            untimed.append(event)
        else:
            groups[key_function(event)].append(event)
    clusters = [[event] for event in untimed]
    for group in groups.values():
        ordered = sorted(group, key=lambda item: item.timestamp)
        start = 0
        while start < len(ordered):
            if cancellation_event is not None and cancellation_event.is_set():
                break
            end = start + 1
            while end < len(ordered) and ordered[end].timestamp - ordered[start].timestamp <= window:
                end += 1
            clusters.append(ordered[start:end])
            start = end
    return clusters


def _group_change_alerts(
    events: list[NormalizedEvent], cancellation_event: Any = None
) -> list[DetectionAlert]:
    descriptions = {
        "4728": "member added to a security-enabled global group",
        "4729": "member removed from a security-enabled global group",
        "4732": "member added to a security-enabled local group",
        "4733": "member removed from a security-enabled local group",
        "4756": "member added to a security-enabled universal group",
        "4757": "member removed from a security-enabled universal group",
    }
    relevant = []
    for event in events:
        if cancellation_event is not None and cancellation_event.is_set():
            break
        if event.event_id not in descriptions or not _is_privileged_group(event):
            continue
        relevant.append(event)
    clusters = _time_clusters(
        relevant,
        lambda event: (
            event.event_id,
            event.host.casefold(),
            _identity(event.user) or event.record_id or _identity(event.member),
            _identity(event.target_group or _data(event, "TargetUserName", "TargetGroupName", "GroupName", "TargetSid", "GroupSid")),
        ),
        timedelta(minutes=10),
        cancellation_event,
    )
    alerts: list[DetectionAlert] = []
    for cluster in clusters:
        if cancellation_event is not None and cancellation_event.is_set():
            break
        event = cluster[0]
        group = event.target_group or _data(event, "TargetUserName", "TargetGroupName", "GroupName", "TargetSid", "GroupSid")
        members = sorted({item.member or _data(item, "MemberName", "MemberSid") for item in cluster if item.member or _data(item, "MemberName", "MemberSid")})
        member = members[0] if len(members) == 1 else f"{len(cluster)} membership changes"
        added = event.event_id in {"4728", "4732", "4756"}
        alerts.append(_alert(
            "DET-AD-001", "Privileged group membership change recorded",
            Severity.HIGH if added else Severity.INFO, cluster,
            account=member, host=event.host, target_group=group, member=member,
            affected_accounts=members,
            explanation=f"{len(cluster)} event record(s) document {descriptions[event.event_id]} for recognized privileged group {group or _data(event, 'TargetSid')}.",
            confidence="High",
            investigation=["Verify the actor, member, target group, change ticket, and timestamp.", "Review surrounding directory-service events and account sign-in activity."],
            actions=["If unauthorized, follow approved incident response to reverse access and secure the affected identity."],
            mitre="T1098.007",
            identity_key=f"{event.event_id}|{group}|{','.join(members)}|{cluster[0].record_id}",
        ))
    return alerts


def _account_creation_alerts(events: list[NormalizedEvent], cancellation_event: Any = None) -> list[DetectionAlert]:
    creations: list[NormalizedEvent] = []
    for event in events:
        if cancellation_event is not None and cancellation_event.is_set():
            break
        if event.event_id != "4720":
            continue
        creations.append(event)
    clusters = _time_clusters(
        creations,
        lambda event: (
            event.host.casefold(),
            _identity(event.user) or event.record_id or _identity(event.target_account),
        ),
        timedelta(minutes=10),
        cancellation_event,
    )
    alerts: list[DetectionAlert] = []
    for cluster in clusters:
        if cancellation_event is not None and cancellation_event.is_set():
            break
        event = cluster[0]
        accounts = sorted({item.target_account or _data(item, "TargetUserName", "NewAccount") for item in cluster if item.target_account or _data(item, "TargetUserName", "NewAccount")})
        actor = event.user or _data(event, "SubjectUserName")
        if accounts:
            account_label = accounts[0] if len(accounts) == 1 else f"{len(accounts)} accounts"
        else:
            account_label = "Account unavailable" if len(cluster) == 1 else f"Accounts unavailable ({len(cluster)} events)"
        alert = _alert(
            "DET-AD-002", "User account creation recorded", Severity.INFO, cluster,
            account=account_label, host=event.host, affected_accounts=accounts,
            explanation=f"{len(cluster)} event 4720 record(s) document account creation by {actor or 'unknown actor'}. Account creation is not inherently malicious.",
            confidence="Low",
            investigation=["Verify the request, approving owner, creator, naming, and intended account purpose.", "Review later group changes and first logon activity for this account."],
            actions=["Apply the standard provisioning, ownership, authentication, and expiry controls."],
            identity_key=f"{','.join(accounts)}|{actor}|{cluster[0].record_id}",
        )
        alerts.append(alert)
        logger.debug(
            "Aggregated account-creation detection evidence",
            extra={
                "telemetry_stage": "aggregated",
                "rule_id": alert.rule_id,
                "event_count": alert.event_count,
                "confidence": alert.confidence,
                "has_timestamp": alert.first_seen is not None and alert.last_seen is not None,
                "has_host": bool(alert.host),
                "has_target_account": bool(alert.affected_accounts),
                "has_subject_user": bool(actor),
                "source_event_ids": [event.event_id for event in cluster],
            },
        )
    return alerts


_POWERSHELL_PATTERNS = (
    ("encoded_command", re.compile(r"(?i)(?:^|\s)-(?:enc|encodedcommand)(?:\s|$)")),
    ("dynamic_code_execution", re.compile(r"(?i)(?:frombase64string|invoke-expression|\biex\b)")),
    ("remote_content_execution", re.compile(r"(?i)(?:downloadstring|downloadfile|invoke-webrequest).{0,160}(?:invoke-expression|\biex\b)")),
)


def _powershell_alerts(events: list[NormalizedEvent], cancellation_event: Any = None) -> list[DetectionAlert]:
    grouped: dict[tuple[str, str, tuple[str, ...]], list[NormalizedEvent]] = defaultdict(list)
    for event in events:
        if cancellation_event is not None and cancellation_event.is_set():
            break
        if event.event_id not in {"4103", "4104", "4688", "1"}:
            continue
        command = " ".join((event.command_line, event.process_name, event.description, *(
            str(value) for key, value in event.event_data.items()
            if any(token in str(key).casefold() for token in ("scriptblock", "hostapplication", "commandline"))
        )))[:MAX_EVIDENCE_TEXT]
        matched = tuple(label for label, pattern in _POWERSHELL_PATTERNS if pattern.search(command))
        if not matched:
            continue
        if event.event_id not in {"4103", "4104"} and not any(
            marker in command.casefold() for marker in ("powershell", "pwsh")
        ):
            continue
        fallback = event.record_id or hashlib.sha256(command.encode("utf-8", errors="replace")).hexdigest()[:12]
        grouped[(event.host.casefold(), _identity(event.user) or fallback, matched)].append(event)
    alerts: list[DetectionAlert] = []
    for (host_key, account_key, patterns), group in grouped.items():
        first = group[0]
        alerts.append(_alert(
            "DET-PS-001", "PowerShell activity contains an investigative indicator", Severity.MEDIUM,
            group, account=first.user, host=first.host,
            explanation=f"Collected PowerShell/process telemetry matched indicator(s): {', '.join(patterns)}. The command was not executed and this is not proof of malicious activity.",
            confidence="Medium",
            investigation=["Review the full script/process chain in the secured source log and identify the operator.", "Validate command intent, parent process, signing, and change authorization."],
            actions=["Use normal endpoint response controls only after analyst validation."],
            mitre="T1059.001",
            identity_key=f"{host_key}|{account_key}|{patterns}",
        ))
    return alerts


MAX_EVIDENCE_TEXT = 1200


def _kerberos_alerts(
    events: list[NormalizedEvent], window: timedelta, cancellation_event: Any = None
) -> list[DetectionAlert]:
    alerts: list[DetectionAlert] = []
    service_tickets: dict[tuple[str, str, str], list[NormalizedEvent]] = defaultdict(list)
    for event in events:
        if cancellation_event is not None and cancellation_event.is_set():
            break
        if event.event_id == "4768":
            preauth = _data(event, "PreAuthType", "PreAuthenticationType")
            if preauth.strip().casefold() in {"0", "0x0"}:
                account = event.target_account or event.user
                alerts.append(_alert(
                    "DET-KRB-001", "Kerberos TGT request without pre-authentication data observed", Severity.INFO,
                    [event], account=account, host=event.host, source_ip=event.source_ip,
                    explanation="Event 4768 reports pre-authentication type 0. This observation is not proof of AS-REP roasting or credential compromise.",
                    confidence="Low",
                    investigation=["Correlate the event with the account's current Kerberos policy and nearby authentication events."],
                    actions=["Review pre-authentication configuration through approved AD administration if the behavior is unexpected."],
                    identity_key=f"{account}|{event.host}|{event.record_id}",
                ))
        elif event.event_id == "4769":
            encryption = _data(event, "TicketEncryptionType", "TicketEncryption")
            if encryption.strip().casefold() in {"23", "0x17", "0x00000017"}:
                alerts.append(_alert(
                    "DET-KRB-002", "Kerberos service ticket used RC4 encryption", Severity.INFO,
                    [event], account=event.target_account or event.user, host=event.host,
                    source_ip=event.source_ip,
                    explanation="Event 4769 reports ticket encryption type 0x17 (RC4). Legacy encryption may merit review but does not establish Kerberoasting.",
                    confidence="High",
                    investigation=["Verify the service account and application compatibility requirements.", "Correlate service-ticket volume and requester identity with approved activity."],
                    actions=["Plan migration to modern encryption according to the organization's compatibility policy."],
                    identity_key=f"{event.target_account}|{event.host}|{event.record_id}",
                ))
            account = _identity(event.target_account or event.user)
            key = (account, event.host.casefold(), event.source_ip)
            if account and event.host and event.source_ip and event.timestamp:
                service_tickets[key].append(event)
    for key, group in service_tickets.items():
        if cancellation_event is not None and cancellation_event.is_set():
            break
        ordered = sorted(group, key=lambda item: item.timestamp)
        start = 0
        while start < len(ordered):
            if cancellation_event is not None and cancellation_event.is_set():
                break
            end = start + 1
            while end < len(ordered) and ordered[end].timestamp - ordered[start].timestamp <= window:
                end += 1
            cluster = ordered[start:end]
            if len(cluster) >= 10:
                first = cluster[0]
                alerts.append(_alert(
                    "DET-KRB-003", "High volume of Kerberos service-ticket requests observed", Severity.INFO,
                    cluster, account=first.target_account or first.user, host=first.host,
                    source_ip=first.source_ip,
                    explanation=f"{len(cluster)} event 4769 records for the same account, host, and source IP occurred within {int(window.total_seconds())} seconds. This does not prove Kerberoasting.",
                    confidence="Medium",
                    investigation=["Validate the requester, service names, timing, and expected application behavior.", "Review ticket encryption types and endpoint process telemetry."],
                    actions=["Escalate only if the volume or context is inconsistent with expected service use."],
                    identity_key=f"{key}|{first.timestamp.isoformat()}",
                ))
                start = end
            else:
                start += 1
    return alerts


def _directory_change_alerts(events: list[NormalizedEvent], cancellation_event: Any = None) -> list[DetectionAlert]:
    alerts: list[DetectionAlert] = []
    watched_attributes = {"gplink", "gpoptions", "ntsecuritydescriptor"}
    for event in events:
        if cancellation_event is not None and cancellation_event.is_set():
            break
        if event.event_id != "5136":
            continue
        attribute = _data(event, "AttributeLDAPDisplayName", "AttributeName").casefold()
        if attribute not in watched_attributes:
            continue
        target = _data(event, "ObjectDN", "ObjectDistinguishedName")
        actor = event.user or _data(event, "SubjectUserName")
        alerts.append(_alert(
            "DET-AD-003", "Group Policy or directory permission attribute change recorded", Severity.INFO,
            [event], account=actor, host=event.host,
            target_object=target,
            explanation=f"Event 5136 records a change to {attribute} on {target or 'an object not identified in the event'}.",
            confidence="High",
            investigation=["Validate the actor, object, change ticket, and before/after values using the secured source log."],
            actions=["Use approved directory change control to revert only if the change is confirmed unauthorized."],
            identity_key=f"{target}|{attribute}|{actor}|{event.record_id}",
        ))
    return alerts


def _member_identity(value: str) -> str:
    normalized = _identity(value)
    common_name = re.match(r"(?i)^CN=([^,]+)", str(value or "").strip())
    return common_name.group(1).casefold() if common_name else normalized


def _account_privilege_sequence_alerts(
    events: list[NormalizedEvent], cancellation_event: Any = None
) -> list[DetectionAlert]:
    creations = [event for event in events if event.event_id == "4720" and event.target_account and event.timestamp]
    additions = [
        event for event in events
        if event.event_id in {"4728", "4732", "4756"}
        and event.member and event.timestamp and _is_privileged_group(event)
    ]
    additions_by_member: dict[str, list[NormalizedEvent]] = defaultdict(list)
    for addition in additions:
        additions_by_member[_member_identity(addition.member)].append(addition)
    alerts: list[DetectionAlert] = []
    for creation in creations:
        if cancellation_event is not None and cancellation_event.is_set():
            break
        account = _member_identity(creation.target_account)
        if not account:
            continue
        for addition in additions_by_member.get(account, []):
            if cancellation_event is not None and cancellation_event.is_set():
                break
            if not (creation.timestamp <= addition.timestamp <= creation.timestamp + timedelta(hours=24)):
                continue
            group = addition.target_group or _data(addition, "TargetUserName", "TargetGroupName", "GroupName")
            alerts.append(_alert(
                "DET-AD-004", "New account added to a privileged group shortly after creation", Severity.MEDIUM,
                [creation, addition], account=creation.target_account, host=addition.host,
                target_group=group, member=addition.member,
                explanation="Event 4720 account creation was followed within 24 hours by a matching member addition to a recognized privileged group. Validate provisioning context; this sequence is suspicious for review, not proof of malicious activity.",
                confidence="High",
                investigation=["Verify the provisioning request, creator, group-change actor, approvals, and account owner.", "Review the new account's first sign-in and subsequent privileged actions."],
                actions=["If unauthorized, follow incident response to disable the account and remove inappropriate access after evidence preservation."],
                mitre="T1136.002",
                identity_key=f"{account}|{group}|{creation.record_id}|{addition.record_id}",
            ))
    return alerts


def run_detections(
    events: list[NormalizedEvent],
    failure_threshold: int = 5,
    window_minutes: int = 10,
    severity_overrides: dict[str, Severity | str] | None = None,
    cancellation_event: Any = None,
) -> list[DetectionAlert]:
    if failure_threshold < 2:
        raise ValueError("failure_threshold must be at least 2")
    if window_minutes < 1:
        raise ValueError("window_minutes must be positive")
    window = timedelta(minutes=window_minutes)
    alerts: list[DetectionAlert] = []
    detectors = (
        lambda: _authentication_alerts(events, failure_threshold, window, cancellation_event),
        lambda: _group_change_alerts(events, cancellation_event),
        lambda: _account_creation_alerts(events, cancellation_event),
        lambda: _powershell_alerts(events, cancellation_event),
        lambda: _kerberos_alerts(events, window, cancellation_event),
        lambda: _directory_change_alerts(events, cancellation_event),
        lambda: _account_privilege_sequence_alerts(events, cancellation_event),
    )
    for detector in detectors:
        if cancellation_event is not None and cancellation_event.is_set():
            break
        alerts.extend(detector())
    for alert in alerts:
        if severity_overrides and alert.rule_id in severity_overrides:
            override = severity_overrides[alert.rule_id]
            alert.severity = override if isinstance(override, Severity) else Severity(str(override).upper())
    unique: dict[str, DetectionAlert] = {}
    for alert in alerts:
        unique.setdefault(alert.alert_id, alert)
    return sorted(
        unique.values(),
        key=lambda alert: (alert.first_seen or datetime.min.replace(tzinfo=timezone.utc), alert.rule_id),
    )


DETECTION_RULE_EVENT_IDS: dict[str, set[str]] = {
    "DET-AUTH-001": {"4625"},
    "DET-AUTH-002": {"4624", "4625"},
    "DET-AD-001": {"4728", "4729", "4732", "4733", "4756", "4757"},
    "DET-AD-002": {"4720"},
    "DET-PS-001": {"4103", "4104", "4688", "1"},
    "DET-KRB-001": {"4768"},
    "DET-KRB-002": {"4769"},
    "DET-KRB-003": {"4769"},
    "DET-AD-003": {"5136"},
    "DET-AD-004": {"4720", "4728", "4732", "4756"},
}


def _rule_fields_available(rule_id: str, event: NormalizedEvent) -> bool:
    if rule_id in {"DET-AUTH-001", "DET-AUTH-002"}:
        return _valid_auth_key(event) is not None
    if rule_id == "DET-AD-001":
        return bool(event.target_group or _data(event, "TargetUserName", "TargetGroupName", "GroupName", "TargetSid", "GroupSid"))
    if rule_id == "DET-AD-002":
        return True  # Event ID 4720 alone is sufficient for the recorded-creation rule.
    if rule_id == "DET-PS-001":
        return bool(event.command_line or event.process_name or event.description or any(
            any(token in str(key).casefold() for token in ("scriptblock", "hostapplication", "commandline"))
            for key in event.event_data
        ))
    if rule_id == "DET-KRB-001":
        return bool(_data(event, "PreAuthType", "PreAuthenticationType"))
    if rule_id == "DET-KRB-002":
        return bool(_data(event, "TicketEncryptionType", "TicketEncryption"))
    if rule_id == "DET-KRB-003":
        return bool((event.target_account or event.user) and event.host and event.source_ip and event.timestamp)
    if rule_id == "DET-AD-003":
        return bool(
            _data(event, "AttributeLDAPDisplayName", "AttributeName")
            and _data(event, "ObjectDN", "ObjectDistinguishedName")
        )
    if rule_id == "DET-AD-004":
        if event.event_id == "4720":
            return bool(event.target_account and event.timestamp)
        return bool(event.member and event.timestamp and _is_privileged_group(event))
    return False


def detection_coverage(events: list[NormalizedEvent], alerts: list[DetectionAlert]) -> list[dict[str, Any]]:
    """Summarize rule event eligibility, minimum-field evaluability, and matches."""
    rows = []
    for rule_id, event_ids in DETECTION_RULE_EVENT_IDS.items():
        eligible = [event for event in events if event.event_id in event_ids]
        evaluated = sum(_rule_fields_available(rule_id, event) for event in eligible)
        match_count = sum(alert.rule_id == rule_id for alert in alerts)
        rows.append({
            "rule_id": rule_id,
            "event_ids": sorted(event_ids),
            "eligible_events": len(eligible),
            "evaluated_events": evaluated,
            "not_evaluated_events": len(eligible) - evaluated,
            "matches": match_count,
            "status": "Matched" if match_count else "No eligible events" if not eligible else "Evaluated, no alert" if evaluated == len(eligible) else "Partially evaluated",
        })
    return rows


def alert_to_dict(alert: DetectionAlert) -> dict[str, Any]:
    result = asdict(alert)
    result["severity"] = alert.severity.value
    return result
