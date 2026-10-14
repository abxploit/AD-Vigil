"""Shared evidence helpers for pure finding rules."""

import hashlib
from collections.abc import Iterable
from typing import Any

from core.models import Finding, Severity


def values(record: dict[str, Any], key: str) -> list[Any]:
    value = record.get(key)
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def text(record: dict[str, Any], key: str, default: str = "") -> str:
    items = values(record, key)
    return str(items[0]) if items else default


def account_control(record: dict[str, Any]) -> int | None:
    try:
        return int(text(record, "userAccountControl"))
    except (TypeError, ValueError):
        return None


def is_disabled(record: dict[str, Any]) -> bool | None:
    flags = account_control(record)
    return None if flags is None else bool(flags & 0x2)


def sid_string(record: dict[str, Any], key: str = "objectSid") -> str | None:
    sid = values(record, key)
    if not sid:
        return None
    value = sid[0]
    if isinstance(value, str):
        return value if value.startswith("S-") else None
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        if len(raw) < 12:
            return None
        count = raw[1]
        if count < 1 or len(raw) < 8 + count * 4:
            return None
        authority = int.from_bytes(raw[2:8], "big")
        subauthorities = [
            int.from_bytes(raw[8 + index * 4: 12 + index * 4], "little")
            for index in range(count)
        ]
        return "-".join((f"S-{raw[0]}-{authority}", *(str(item) for item in subauthorities)))
    return None


def sid_rid(record: dict[str, Any]) -> int | None:
    sid = sid_string(record)
    if sid is None:
        return None
    try:
        return int(sid.rsplit("-", 1)[1])
    except (IndexError, ValueError):
        return None


def make_finding(
    rule_id: str,
    unique_key: str,
    *,
    title: str,
    severity: Severity,
    category: str,
    affected_object: str,
    affected_type: str,
    description: str,
    evidence: dict[str, Any],
    impact: str,
    remediation: str,
    confidence: str = "High",
    technique: str = "",
    mitre_attack: str = "",
    source_attributes: list[str] | None = None,
    raw_evidence: dict[str, Any] | None = None,
    detection_limitations: str | None = None,
) -> Finding:
    stable_key = f"{rule_id}|{affected_type}|{unique_key}".casefold()
    digest = hashlib.sha256(stable_key.encode("utf-8")).hexdigest()[:10].upper()
    normalized_source = list(source_attributes) if source_attributes else sorted(evidence.keys())
    raw_data = raw_evidence if raw_evidence is not None else dict(evidence)
    if detection_limitations is None:
        detection_limitations = (
            "This assessment is evidence-based and does not confirm exploitation, ticket forgery, "
            "password cracking, or credential theft."
        )
    return Finding(
        finding_id=f"{rule_id}-{digest}",
        title=title,
        category=category,
        severity=severity,
        affected_object=affected_object,
        affected_type=affected_type,
        description=description,
        evidence=evidence,
        security_impact=impact,
        recommended_remediation=remediation,
        confidence=confidence,
        source=rule_id,
        technique=technique,
        mitre_attack=mitre_attack,
        source_attributes=normalized_source,
        raw_evidence=raw_data,
        detection_limitations=detection_limitations,
    )


def unique_findings(findings: Iterable[Finding]) -> list[Finding]:
    unique: dict[str, Finding] = {}
    for finding in findings:
        unique.setdefault(finding.finding_id, finding)
    return list(unique.values())