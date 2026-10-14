"""Shared typed models used by the assessment engine."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    """Supported finding severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    INFORMATIONAL = "INFO"


@dataclass(slots=True)
class Finding:
    """A traceable security observation produced by an assessment module."""

    finding_id: str
    title: str
    category: str
    severity: Severity
    affected_object: str
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)
    security_impact: str = ""
    recommended_remediation: str = ""
    reference: str = ""
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    affected_type: str = "Object"
    confidence: str = "High"
    source: str = ""
    technique: str = ""
    mitre_attack: str = ""
    source_attributes: list[str] = field(default_factory=list)
    raw_evidence: dict[str, Any] = field(default_factory=dict)
    detection_limitations: str = (
        "This assessment is evidence-based and does not confirm exploitation, ticket forgery, "
        "password cracking, or credential theft."
    )

    @property
    def id(self) -> str:
        """Expose the concise field name used by reporting clients."""
        return self.finding_id

    @property
    def remediation(self) -> str:
        return self.recommended_remediation