"""User account configuration rules based on userAccountControl and SID."""

from typing import Any

from core.models import Finding, Severity
from core.findings.rules.common import account_control, is_disabled, make_finding, sid_rid, text


def analyze_account_security(data: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for user in data.get("users", []):
        username = text(user, "sAMAccountName")
        dn = text(user, "dn")
        flags = account_control(user)
        disabled = is_disabled(user)
        if not username or not dn or flags is None or disabled is None or disabled:
            continue

        evidence = {key: user[key] for key in ("sAMAccountName", "userAccountControl") if key in user}
        if flags & 0x10000:
            findings.append(make_finding(
                "AD-AS-001", dn,
                title="User account configured with password never expires",
                severity=Severity.MEDIUM,
                category="Account Security",
                affected_object=username,
                affected_type="User",
                description="The account's userAccountControl includes DONT_EXPIRE_PASSWORD.",
                evidence=evidence,
                impact="A long-lived password can remain usable after it would otherwise be due for rotation.",
                remediation="Review the account's purpose and apply the organization's password rotation or managed-service-account policy.",
            ))
        if flags & 0x20:
            findings.append(make_finding(
                "AD-AS-002", dn,
                title="User account does not require a password",
                severity=Severity.HIGH,
                category="Account Security",
                affected_object=username,
                affected_type="User",
                description="The account's userAccountControl includes PASSWD_NOTREQD.",
                evidence=evidence,
                impact="The directory configuration does not require a password for this account.",
                remediation="Set a strong password and clear PASSWD_NOTREQD unless a documented exception applies.",
            ))

        rid = sid_rid(user)
        if rid == 500:
            findings.append(make_finding(
                "AD-AS-007", dn,
                title="Built-in Administrator account is enabled",
                severity=Severity.LOW,
                category="Account Security",
                affected_object=username,
                affected_type="User",
                description="The account SID has the built-in Administrator RID and the account is enabled.",
                evidence={**evidence, "objectSid": user["objectSid"], "enabled": True},
                impact="The built-in administrative identity is a well-known privileged account that merits deliberate controls.",
                remediation="Apply the organization's controls for privileged accounts, including strong authentication, monitoring, and restricted use.",
            ))
        elif rid == 501:
            findings.append(make_finding(
                "AD-AS-008", dn,
                title="Guest account is enabled",
                severity=Severity.MEDIUM,
                category="Account Security",
                affected_object=username,
                affected_type="User",
                description="The account SID has the built-in Guest RID and the account is enabled.",
                evidence={**evidence, "objectSid": user["objectSid"], "enabled": True},
                impact="An enabled guest identity may allow access without an individually managed user account.",
                remediation="Disable the built-in Guest account unless a documented requirement exists.",
            ))
    return findings