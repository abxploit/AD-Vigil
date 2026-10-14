"""Structured, sanitized reporting for collected AD and Purple Team results."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.defensive_detections import alert_to_dict
from core.models import Finding, Severity
from core.telemetry import LogSourceCoverage

SECRET = re.compile(r"password|passwd|credential|secret|token|cpassword|private.?key", re.I)
COMMAND = re.compile(r"(?i)\b(?:command.?line|process.?command.?line)\b")


def _safe(value: Any, key: str = "") -> Any:
    """Convert report values to JSON-safe data while filtering sensitive fields."""
    if SECRET.search(key):
        return "[REDACTED]"
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Severity):
        return value.value
    if isinstance(value, Finding):
        return finding_record(value)
    if hasattr(value, "__dataclass_fields__"):
        value = {field: getattr(value, field) for field in value.__dataclass_fields__}
    if isinstance(value, dict):
        out = {}
        for name, item in value.items():
            if SECRET.search(str(name)):
                out[str(name)] = "[REDACTED]"
            elif COMMAND.search(str(name)):
                out[str(name)] = "[OMITTED]"
            else:
                out[str(name)] = _safe(item, str(name))
        return out
    if isinstance(value, (list, tuple, set)):
        return [_safe(item, key) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        if isinstance(value, str) and COMMAND.search(key):
            return "[OMITTED]"
        return value
    return str(value)


def finding_record(f: Finding) -> dict[str, Any]:
    return _safe({
        "finding_id": f.finding_id, "title": f.title, "severity": f.severity,
        "category": f.category, "affected_object": f.affected_object,
        "affected_type": f.affected_type, "description": f.description,
        "security_impact": f.security_impact, "evidence": f.evidence,
        "evidence_source": f.source, "confidence": f.confidence,
        "remediation": f.recommended_remediation, "reference": f.reference,
        "detected_at": f.detected_at, "limitations": f.detection_limitations,
        "mitre_attack": f.mitre_attack, "technique": f.technique,
    })


def build_security_report(
    assessment: dict[str, Any] | None,
    findings: list[Finding] | None = None,
    sources: list[LogSourceCoverage] | None = None,
    alerts: list[Any] | None = None,
    correlations: list[dict[str, Any]] | None = None,
    *, title: str = "AD Vigil — Active Directory Security Assessment",
    organization: str = "", classification: str = "Confidential",
    include_inventory: bool = True, include_details: bool = True,
    include_defensive: bool = True, include_recommendations: bool = True,
    include_coverage: bool = True,
) -> dict[str, Any]:
    data = assessment or {}
    findings = list(findings if findings is not None else data.get("findings", []))
    sources, alerts, correlations = list(sources or []), list(alerts or []), list(correlations or [])
    generated = datetime.now(timezone.utc).isoformat()
    count_keys = ("users", "groups", "computers", "domain_controllers", "spns", "ous", "gpos", "trusts")
    counts = {k: len(data[k]) for k in count_keys if isinstance(data.get(k), (list, tuple))}
    severity = {s.value: sum(str(getattr(f.severity, "value", f.severity)) == s.value for f in findings) for s in Severity}
    modules = {
        "Inventory": "Assessed" if "users" in data else "Not assessed",
        "GPO discovery": data.get("gpo_discovery_status", "Not assessed"),
        "GPO content / SYSVOL": data.get("gpo_content_status", "Not assessed"),
        "OU discovery": data.get("ou_discovery_status", "Not assessed"),
        "OU ACL": data.get("ou_acl_status", "Not assessed"),
        "Trusts": data.get("trust_discovery_status", "Not assessed"),
        "Protocol checks": data.get("protocol_assessment_status", "Not assessed"),
        "Attack paths": data.get("attack_path_status", "Not assessed"),
    }
    result: dict[str, Any] = {
        "schema_version": 1, "generated_at": generated,
        "cover": {"title": title, "organization": organization or None,
                  "tagline": "Find the weakness. Detect the activity. Strengthen the domain.",
                  "classification": classification, "tool": "AD Vigil",
                  "project_title": "AD Vigil — Active Directory Security Assessment & Purple Team Platform",
                  "report_version": "1.0", "target": data.get("domain"),
                  "scope": data.get("base_dn") or data.get("domain"),
                  "assessment_time": data.get("assessment_completed_at")},
        "executive_summary": {"status": data.get("assessment_status", "Completed" if data else "No assessment data"),
                              "finding_counts": severity, "finding_total": len(findings),
                              "no_score_assigned": True},
        "scope_methodology": {"domain": data.get("domain"), "server": data.get("server"),
                              "base_dn": data.get("base_dn"), "completed_modules": data.get("completed_categories", []),
                              "modules": modules, "connection_diagnostics": data.get("connection_diagnostics", {})},
        "inventory_counts": counts if include_inventory else {},
        "findings": [finding_record(f) for f in findings] if include_details else [],
        "module_results": _safe({k: data.get(k) for k in ("gpos", "gpo_links", "ous", "trusts", "protocols") if k in data}) if include_details else {},
        "defensive": ({"source_type": "synthetic" if sources and all(s.synthetic for s in sources) else "imported telemetry" if sources else "no telemetry imported",
                       "log_sources": [_safe(s) for s in sources], "alerts": [_safe(alert_to_dict(a)) for a in alerts],
                       "correlations": _safe(correlations),
                       "limitation": "No matching events in imported telemetry do not prove the activity did not occur."} if include_defensive else {}),
        "remediation_plan": ([{"priority": f.severity.value, "finding_id": f.finding_id,
                               "affected_object": f.affected_object,
                               "action": f.recommended_remediation,
                               "validation": f"Retest finding {f.finding_id} after the approved change."}
                              for f in sorted(findings, key=lambda x: list(severity).index(x.severity.value))
                              if f.recommended_remediation] if include_recommendations else []),
        "coverage_limitations": ({"modules": modules, "gpo_content_status": data.get("gpo_content_status", "Not assessed"),
                                  "sources": [{"name": s.source_name, "status": s.status,
                                               "format": s.format, "parse_error_count": s.parse_error_count,
                                               "incomplete_event_count": s.incomplete_event_count,
                                               "synthetic": s.synthetic} for s in sources],
                                  "assessment_errors": {k: v for k, v in data.items() if k.endswith("_error")}}
                                 if include_coverage else {}),
    }
    return _safe(result)


def write_json_report(report: dict[str, Any], path: str | Path) -> None:
    Path(path).write_text(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True), encoding="utf-8")


def write_pdf_report(report: dict[str, Any], path: str | Path) -> None:
    """Render a paginated PDF using the application's existing PySide6 dependency."""
    from html import escape
    from PySide6.QtCore import QMarginsF, QRectF, QSizeF
    from PySide6.QtGui import QColor, QPageLayout, QPageSize, QPdfWriter, QPainter, QTextDocument

    cover = report["cover"]
    title = str(cover.get("title") or "AD Vigil Security Report")
    doc_title = str(cover.get("project_title") or "AD Vigil — Active Directory Security Assessment & Purple Team Platform")
    pieces = ["""<html><head><style>
      body { font-family: 'Arial'; color: #202b38; font-size: 9pt; }
      h1 { color: #16324f; font-size: 23pt; } h2 { color: #16324f; border-bottom: 1px solid #63b7ad; padding-top: 10px; }
      h3 { color: #16324f; margin-bottom: 3px; } .tagline { color: #397f79; font-size: 11pt; }
      table { border-collapse: collapse; width: 100%; } td, th { border: 1px solid #b7c3cf; padding: 5px; }
      th { background: #dce7f1; } pre { white-space: pre-wrap; font-size: 8pt; }
    </style></head><body>""",
        f"<h1>{escape(title)}</h1><p class='tagline'>{escape(str(cover.get('tagline') or 'Find the weakness. Detect the activity. Strengthen the domain.'))}</p>",
        f"<p><b>{escape(doc_title)}</b></p>"]
    for label, value in (("Organization", cover.get("organization")), ("Target", cover.get("target")),
                         ("Scope", cover.get("scope")), ("Assessment time", cover.get("assessment_time")),
                         ("Classification", cover.get("classification")),
                         ("Report version", cover.get("report_version")), ("Generated", report.get("generated_at"))):
        if value:
            pieces.append(f"<p><b>{escape(label)}:</b> {escape(str(value))}</p>")
    def section(name: str) -> None:
        pieces.append(f"<h2>{escape(name)}</h2>")
    def para(value: Any) -> None:
        pieces.append(f"<p>{escape(str(value or 'Not available')).replace(chr(10), '<br>')}</p>")
    section("Executive summary")
    summary = report["executive_summary"]
    para(f"Assessment status: {summary['status']}. Findings: {summary['finding_total']}. No overall score is assigned.")
    pieces.append("<table><tr><th>Severity</th><th>Count</th></tr>" + "".join(
        f"<tr><td>{escape(str(level))}</td><td>{count}</td></tr>" for level, count in summary["finding_counts"].items()) + "</table>")
    section("Scope and module status")
    pieces.append(f"<pre>{escape(json.dumps(report['scope_methodology'], indent=2, ensure_ascii=True))}</pre>")
    if report.get("inventory_counts"):
        section("Active Directory inventory")
        pieces.append("<table><tr><th>Object type</th><th>Count</th></tr>" + "".join(
            f"<tr><td>{escape(k.replace('_',' ').title())}</td><td>{v}</td></tr>" for k,v in report["inventory_counts"].items()) + "</table>")
    section("Security findings")
    rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    for finding in sorted(report.get("findings", []), key=lambda item: rank.get(item.get("severity"), 5)):
        pieces.append(f"<h3>{escape(str(finding.get('severity','')))} — {escape(str(finding.get('title','')))} ({escape(str(finding.get('finding_id','')))} )</h3>")
        para(f"Affected: {finding.get('affected_object') or 'Not specified'}")
        para(finding.get("description"))
        para("Evidence: " + json.dumps(finding.get("evidence", {}), ensure_ascii=True))
        para("Remediation: " + str(finding.get("remediation") or "Not available"))
    if report.get("defensive"):
        section("Defensive detections and Purple Team correlations")
        para(f"Telemetry classification: {report['defensive']['source_type']}")
        for alert in report["defensive"].get("alerts", []):
            para(f"{alert.get('rule_id','')} — {alert.get('title','')} | severity {alert.get('severity','')} | events {alert.get('event_count',0)} | {alert.get('explanation','')}")
        for correlation in report["defensive"].get("correlations", []):
            para(f"{correlation.get('finding_id','')}: {correlation.get('state','Not evaluated')} — {correlation.get('limitation','')}")
        para(report["defensive"].get("limitation"))
    if report.get("remediation_plan"):
        section("Remediation plan")
        for item in report["remediation_plan"]:
            para(f"{item['priority']} | {item['finding_id']} | {item['affected_object']}: {item['action']} Validation: {item['validation']}")
    if report.get("coverage_limitations"):
        section("Coverage, limitations, and assumptions")
        pieces.append(f"<pre>{escape(json.dumps(report['coverage_limitations'], indent=2, ensure_ascii=True))}</pre>")
    pieces.append("</body></html>")

    writer = QPdfWriter(str(path))
    writer.setTitle(doc_title)
    writer.setCreator("AD Vigil")
    writer.setPageSize(QPageSize(QPageSize.PageSizeId.Letter))
    writer.setPageMargins(QMarginsF(12, 16, 12, 16), QPageLayout.Unit.Millimeter)
    writer.setResolution(96)
    document = QTextDocument()
    document.setHtml("".join(pieces))
    printable = writer.pageLayout().paintRectPixels(writer.resolution())
    document.setPageSize(QSizeF(printable.size()))
    painter = QPainter()
    if not painter.begin(writer):
        raise OSError("Unable to initialize the PDF writer")
    page_height = printable.height()
    page_width = printable.width()
    page_count = max(1, document.pageCount())
    for page in range(page_count):
        if page and not writer.newPage():
            painter.end()
            raise OSError("Unable to create a PDF page")
        painter.save()
        painter.translate(printable.left(), printable.top() - page * page_height)
        document.drawContents(painter, QRectF(0, page * page_height, page_width, page_height))
        painter.restore()
        painter.save()
        painter.setPen(QColor("#6b7785"))
        painter.drawText(36, printable.top() - 5, "AD Vigil | Security Assessment")
        painter.drawText(printable.right() - 85, printable.bottom() + 20, f"Page {page + 1} of {page_count}")
        painter.restore()
    painter.end()
