"""Orchestrate independent, evidence-based Active Directory rules."""

import logging
from collections.abc import Callable
from typing import Any

from core.findings.rules.accounts import analyze_account_security
from core.findings.rules.configuration import analyze_pre_windows_2000_access
from core.findings.rules.delegation import (
    analyze_constrained_delegation,
    analyze_rbdc,
    analyze_unconstrained_delegation,
)
from core.findings.rules.kerberos import (
    analyze_asrep_exposure,
    analyze_krbtgt_assessment,
    analyze_silver_ticket_exposure,
    analyze_user_spns,
)
from core.findings.rules.privilege import analyze_privileged_membership, analyze_privileged_service_account
from core.findings.rules.gpo import analyze_gpo_security
from core.findings.rules.common import unique_findings
from core.findings.rules.directory_security import (
    analyze_ou_security,
    analyze_protocol_security,
    analyze_trust_security,
)
from core.models import Finding, Severity

logger = logging.getLogger(__name__)
Rule = Callable[[dict[str, Any]], list[Finding]]


class FindingEngine:
    """Run read-only rules against an assessment without mutating its data."""

    def __init__(self, rules: tuple[Rule, ...] | None = None) -> None:
        self.rules = rules or (
            analyze_account_security,
            analyze_asrep_exposure,
            analyze_user_spns,
            analyze_silver_ticket_exposure,
            analyze_krbtgt_assessment,
            analyze_unconstrained_delegation,
            analyze_constrained_delegation,
            analyze_rbdc,
            analyze_privileged_membership,
            analyze_privileged_service_account,
            analyze_pre_windows_2000_access,
            analyze_gpo_security,
            analyze_ou_security,
            analyze_trust_security,
            analyze_protocol_security,
        )

    def analyze(self, assessment_data: dict[str, Any]) -> list[Finding]:
        findings = unique_findings(
            finding
            for rule in self.rules
            for finding in rule(assessment_data)
        )
        logger.info(
            "Security analysis completed",
            extra={
                "finding_count": len(findings),
                "severity_counts": self.severity_counts(findings),
            },
        )
        return findings

    @staticmethod
    def severity_counts(findings: list[Finding]) -> dict[str, int]:
        return {
            severity.value: sum(finding.severity == severity for finding in findings)
            for severity in Severity
        }