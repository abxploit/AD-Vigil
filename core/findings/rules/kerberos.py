"""Kerberos pre-authentication and service-principal exposure rules."""

from collections import defaultdict
from typing import Any

from core.findings.rules.common import account_control, is_disabled, make_finding, text, values
from core.models import Finding, Severity


def _is_machine_account(record: dict[str, Any]) -> bool:
    name = text(record, "sAMAccountName")
    object_classes = [str(item).lower() for item in values(record, "objectClass")]
    return bool((name and name.endswith("$")) or "computer" in object_classes)


def analyze_asrep_exposure(data: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for user in data.get("users", []):
        flags = account_control(user)
        username = text(user, "sAMAccountName")
        dn = text(user, "dn")
        if flags is None or not username or not dn or not flags & 0x400000:
            continue
        enabled = is_disabled(user) is False
        evidence = {
            key: user[key]
            for key in ("sAMAccountName", "userAccountControl", "dn", "memberOf", "objectClass")
            if key in user
        }
        evidence["enabled"] = enabled
        findings.append(make_finding(
            "AD-KRB-001", dn,
            title="AS-REP roasting exposure: Kerberos pre-authentication disabled",
            severity=Severity.HIGH,
            category="Kerberos",
            affected_object=username,
            affected_type="User",
            description=(
                "The account is configured with DONT_REQUIRE_PREAUTH and therefore does not require "
                "Kerberos pre-authentication. "
                + ("The account is currently disabled, so the exposure is reduced but still recorded in LDAP."
                   if not enabled else "The account is enabled, which places the configuration in active scope.")
            ),
            evidence=evidence,
            impact="This setting can permit AS-REP roasting because the directory no longer requires Kerberos pre-authentication. The assessment records the configuration and does not request or validate Kerberos tickets.",
            remediation="Review the account's purpose and re-enable Kerberos pre-authentication unless a documented compatibility exception requires otherwise.",
            technique="AS-REP Roasting",
            mitre_attack="T1558.004",
            source_attributes=["sAMAccountName", "userAccountControl", "dn", "memberOf", "objectClass"],
            raw_evidence=evidence,
            detection_limitations="This is a configuration-based assessment of the DONT_REQUIRE_PREAUTH bit; it does not request or validate a Kerberos AS-REP from the account.",
        ))
    return findings


def analyze_user_spns(data: dict[str, Any]) -> list[Finding]:
    users = {
        text(user, "sAMAccountName").casefold(): user
        for user in data.get("users", [])
        if text(user, "sAMAccountName")
    }
    groups_by_dn = {
        str(text(group, "dn")).casefold(): text(group, "name") or text(group, "sAMAccountName")
        for group in data.get("groups", [])
        if text(group, "dn")
    }
    account_spns: dict[str, list[Any]] = defaultdict(list)
    spn_records: dict[str, dict[str, Any]] = {}
    for record in data.get("spns", []):
        account = text(record, "sAMAccountName")
        account_key = account.casefold()
        if not account or account_key not in users:
            continue
        user = users[account_key]
        if _is_machine_account(user) or is_disabled(user) is not False:
            continue
        for spn in values(record, "servicePrincipalName"):
            if spn not in account_spns[account_key]:
                account_spns[account_key].append(spn)
        spn_records[account_key] = record

    findings: list[Finding] = []
    for account_key, spns in account_spns.items():
        if not spns:
            continue
        user = users[account_key]
        record = spn_records[account_key]
        account = text(user, "sAMAccountName")
        dn = text(user, "dn") or text(record, "dn")
        privileged_groups = [
            group_name for group_dn, group_name in groups_by_dn.items()
            if str(group_dn) in {str(member).casefold() for member in values(user, "memberOf")}
            and group_name.lower() in {
                "domain admins",
                "enterprise admins",
                "administrators",
                "account operators",
                "backup operators",
                "server operators",
                "dnsadmins",
                "schema admins",
            }
        ]
        service_classes = list(dict.fromkeys(str(spn).split("/", 1)[0] for spn in spns))
        evidence = {
            "sAMAccountName": record.get("sAMAccountName", account),
            "dn": record.get("dn", user.get("dn", "")),
            "servicePrincipalName": list(spns),
            "account_type": "User/service account",
            "enabled": True,
            "memberOf": user.get("memberOf", []),
            "privileged_groups": privileged_groups,
            "serviceClasses": service_classes,
        }
        severity = Severity.HIGH if privileged_groups else Severity.MEDIUM
        findings.append(make_finding(
            "AD-KRB-002", dn or account_key,
            title="Kerberoasting exposure: user/service account has an SPN",
            severity=severity,
            category="Kerberos",
            affected_object=account,
            affected_type="User",
            description="This account has a Service Principal Name and may be eligible for Kerberos service-ticket password auditing. Password strength and additional controls determine practical exposure.",
            evidence=evidence,
            impact="An SPN on an enabled user or service account may permit offline Kerberos ticket password auditing if the underlying secret is weak or reused. The assessment does not request Kerberos tickets or perform password cracking.",
            remediation="Review whether the SPN is necessary, confirm the account purpose, and prefer a managed service account with strong, non-reused secrets where appropriate.",
            technique="Kerberoasting",
            mitre_attack="T1558.003",
            source_attributes=["sAMAccountName", "dn", "servicePrincipalName", "memberOf", "userAccountControl", "objectClass"],
            raw_evidence=evidence,
            detection_limitations="This is a configuration review of SPN-bearing user/service accounts; it does not prove that a password is crackable or that a ticket was obtained.",
        ))
    return findings


def analyze_silver_ticket_exposure(data: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    users = {
        text(user, "sAMAccountName").casefold(): user
        for user in data.get("users", [])
        if text(user, "sAMAccountName")
    }
    seen: set[str] = set()
    for record in data.get("spns", []):
        account = text(record, "sAMAccountName")
        if not account:
            continue
        account_key = account.casefold()
        found_user = users.get(account_key)
        if found_user is None or _is_machine_account(found_user) or is_disabled(found_user) is not False:
            continue
        identity = f"{account_key}|{text(record, 'dn') or text(found_user, 'dn')}".casefold()
        if identity in seen:
            continue
        seen.add(identity)
        spns = list(values(record, "servicePrincipalName"))
        evidence = {
            "sAMAccountName": account,
            "dn": text(record, "dn") or text(found_user, "dn"),
            "servicePrincipalName": spns,
            "account_type": "User/service account",
            "enabled": True,
            "userAccountControl": found_user.get("userAccountControl"),
            "memberOf": found_user.get("memberOf", []),
        }
        findings.append(make_finding(
            "AD-KRB-003", identity,
            title="Service account may warrant Silver Ticket exposure review",
            severity=Severity.MEDIUM,
            category="Kerberos",
            affected_object=account,
            affected_type="User",
            description="The account owns one or more SPNs and should be reviewed for unnecessary privileges and credential protection. The assessment does not validate Silver Ticket creation or possession of account secrets.",
            evidence=evidence,
            impact="Silver Ticket attacks depend on the service account or computer secret associated with an SPN. This finding documents exposure-prone service-account posture without asserting ticket forgery or secret compromise.",
            remediation="Review whether the SPN-bearing account requires the service and privileges it currently holds, and protect the underlying service secret with managed service-account controls.",
            technique="Silver Ticket",
            mitre_attack="T1558.002",
            source_attributes=["sAMAccountName", "dn", "servicePrincipalName", "userAccountControl", "memberOf"],
            raw_evidence=evidence,
            detection_limitations="This is an exposure review based on SPN ownership and service posture; it does not confirm that a Silver Ticket can be forged or that secrets are compromised.",
        ))
    return findings


def analyze_krbtgt_assessment(data: dict[str, Any]) -> list[Finding]:
    for user in data.get("users", []):
        if str(text(user, "sAMAccountName")).casefold() != "krbtgt":
            continue
        evidence = {
            key: user[key]
            for key in ("sAMAccountName", "dn", "userAccountControl", "pwdLastSet", "objectSid")
            if key in user
        }
        evidence["enabled"] = is_disabled(user) is False
        title = "Golden Ticket assessment requires additional domain/Kerberos security telemetry."
        findings = [make_finding(
            "AD-KRB-004", text(user, "dn") or "krbtgt",
            title=title,
            severity=Severity.INFO,
            category="Kerberos",
            affected_object="krbtgt",
            affected_type="User",
            description="The krbtgt account exists and is a normal Active Directory account. The tool does not attempt to forge or validate Kerberos tickets, and it does not infer a Golden Ticket condition from the presence of the krbtgt account alone.",
            evidence=evidence,
            impact="The account's existence alone is not evidence of ticket forgery; a meaningful Golden Ticket assessment requires additional Kerberos and domain telemetry beyond the collected LDAP inventory.",
            remediation="Review krbtgt protection, privileged domain policy, and Kerberos security telemetry from authoritative domain controls instead of inferring direct compromise from the account's existence.",
            technique="Golden Ticket",
            mitre_attack="T1558.001",
            source_attributes=["sAMAccountName", "dn", "userAccountControl", "pwdLastSet", "objectSid"],
            raw_evidence=evidence,
            detection_limitations="This assessment is informational only and does not infer compromise from krbtgt existence or from password-age metadata alone.",
        )]
        return findings
    return []