"""Configuration rules for broad membership in legacy compatibility groups."""

from typing import Any

from core.models import Finding, Severity
from core.findings.rules.common import make_finding, text, values


def analyze_pre_windows_2000_access(data: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for group in data.get("groups", []):
        name = text(group, "name")
        if name.casefold() != "pre-windows 2000 compatible access" or "member" not in group:
            continue
        members = [str(member) for member in values(group, "member")]
        broad_members = [
            member for member in members
            if "cn=anonymous logon," in member.casefold()
            or "cn=everyone," in member.casefold()
            or member.casefold() in {"s-1-5-7", "s-1-1-0"}
        ]
        if not broad_members:
            continue
        anonymous_present = any(
            "cn=anonymous logon," in member.casefold() or member.casefold() == "s-1-5-7"
            for member in broad_members
        )
        severity = Severity.HIGH if anonymous_present else Severity.MEDIUM
        dn = text(group, "dn") or name
        findings.append(make_finding(
            "AD-CFG-001", dn,
            title="Pre-Windows 2000 compatibility group includes a broad principal",
            severity=severity,
            category="Configuration",
            affected_object=name,
            affected_type="Group",
            description="Collected membership includes a broad security principal in the legacy compatibility group.",
            evidence={
                "name": group.get("name", name),
                "dn": group.get("dn", ""),
                "member": broad_members,
            },
            impact="This may broaden legacy-compatible directory reads; actual access also depends on directory permissions.",
            remediation="Review whether the broad principal is required and remove it when legacy compatibility does not require it.",
        ))
    return findings