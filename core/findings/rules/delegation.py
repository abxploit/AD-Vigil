"""Delegation assessment rules for Kerberos and service access controls."""

from typing import Any

from core.findings.rules.common import account_control, is_disabled, make_finding, text, values
from core.models import Finding, Severity


def analyze_unconstrained_delegation(data: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    for key, affected_type in (("users", "User"), ("computers", "Computer")):
        for record in data.get(key, []):
            flags = account_control(record)
            disabled = is_disabled(record)
            dn = text(record, "dn")
            name = text(record, "sAMAccountName") or text(record, "dNSHostName")
            if flags is None or disabled is not False or not dn or not name or not flags & 0x80000:
                continue
            identity = f"{affected_type}|{dn}".casefold()
            if identity in seen:
                continue
            seen.add(identity)
            evidence = {
                field: record[field]
                for field in ("sAMAccountName", "dNSHostName", "userAccountControl", "dn", "operatingSystem")
                if field in record
            }
            evidence.setdefault("servicePrincipalName", values(record, "servicePrincipalName"))
            findings.append(make_finding(
                "AD-DEL-001", identity,
                title="Unconstrained delegation configured",
                severity=Severity.HIGH,
                category="Delegation",
                affected_object=name,
                affected_type=affected_type,
                description="The account's userAccountControl includes TRUSTED_FOR_DELEGATION.",
                evidence=evidence,
                impact="Unconstrained delegation can allow delegated services to act on behalf of authenticating users; this setting alone does not prove abuse.",
                remediation="Review the delegation requirement and prefer constrained or resource-based constrained delegation where feasible.",
                technique="Unconstrained Delegation",
                source_attributes=["sAMAccountName", "dNSHostName", "userAccountControl", "dn", "operatingSystem", "servicePrincipalName"],
                raw_evidence=evidence,
            ))
    return findings


def analyze_constrained_delegation(data: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    for key, affected_type in (("users", "User"), ("computers", "Computer")):
        for record in data.get(key, []):
            allowed_services = values(record, "msDS-AllowedToDelegateTo")
            if not allowed_services:
                continue
            name = text(record, "sAMAccountName") or text(record, "dNSHostName")
            dn = text(record, "dn")
            if not name or not dn:
                continue
            identity = f"{affected_type}|{dn}".casefold()
            if identity in seen:
                continue
            seen.add(identity)
            evidence = {
                "account": name,
                "sAMAccountName": text(record, "sAMAccountName"),
                "dn": dn,
                "allowed_services": allowed_services,
                "servicePrincipalName": values(record, "servicePrincipalName"),
                "userAccountControl": record.get("userAccountControl"),
                "enabled": is_disabled(record) is False,
            }
            findings.append(make_finding(
                "AD-DEL-002", identity,
                title="Constrained delegation configured",
                severity=Severity.MEDIUM,
                category="Delegation",
                affected_object=name,
                affected_type=affected_type,
                description="The object is configured with msDS-AllowedToDelegateTo for explicit service targets and should be reviewed for least-privilege and service ownership.",
                evidence=evidence,
                impact="Constrained delegation is a valid Kerberos design pattern but can be sensitive when allowed service targets are broader than necessary or not maintained.",
                remediation="Review each allowed target and ensure the delegation relationship is justified, limited to the necessary service principals, and regularly audited.",
                technique="Constrained Delegation",
                source_attributes=["sAMAccountName", "dn", "msDS-AllowedToDelegateTo", "servicePrincipalName", "userAccountControl"],
                raw_evidence=evidence,
            ))
    return findings


def analyze_rbdc(data: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    for key, affected_type in (("computers", "Computer"), ("users", "User")):
        for record in data.get(key, []):
            principals = values(record, "msDS-AllowedToActOnBehalfOfOtherIdentity")
            if not principals:
                continue
            name = text(record, "sAMAccountName") or text(record, "dNSHostName")
            dn = text(record, "dn")
            if not name or not dn:
                continue
            identity = f"{affected_type}|{dn}".casefold()
            if identity in seen:
                continue
            seen.add(identity)
            evidence = {
                "target_account": name,
                "dn": dn,
                "source_principals": principals,
                "raw_security_descriptor": principals,
                "enabled": is_disabled(record) is False,
            }
            findings.append(make_finding(
                "AD-DEL-003", identity,
                title="Resource-Based Constrained Delegation configured",
                severity=Severity.HIGH,
                category="Delegation",
                affected_object=name,
                affected_type=affected_type,
                description="The object exposes an msDS-AllowedToActOnBehalfOfOtherIdentity configuration and should be reviewed for the actual delegation relationship it permits. The assessment does not assert misuse or ticket creation.",
                evidence=evidence,
                impact="Resource-based delegation can enable controlled impersonation for approved services, but the relationship should be reviewed to confirm that only the intended principals and targets are present.",
                remediation="Validate that each source principal and target service is necessary, and document the delegation relationship with a least-privilege review.",
                technique="RBCD",
                source_attributes=["sAMAccountName", "dn", "msDS-AllowedToActOnBehalfOfOtherIdentity"],
                raw_evidence=evidence,
            ))
    return findings