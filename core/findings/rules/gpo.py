"""Evidence-based rules for collected Group Policy settings."""

import hashlib
from typing import Any

from core.findings.rules.common import make_finding
from core.models import Finding, Severity


def _number(value: Any) -> int | None:
    try:
        return int(str(value).strip().split(",", 1)[0], 0)
    except (TypeError, ValueError):
        try:
            return int(str(value).strip().split(",", 1)[0])
        except (TypeError, ValueError):
            return None


def _normalized(value: Any) -> str:
    return " ".join(str(value).casefold().split())


def _setting_identity(setting: dict[str, Any]) -> str:
    name = str(setting.get("setting") or "")
    value = setting.get("observed_value")
    if isinstance(value, dict) and name.casefold() in {"registry:properties", "groups:member"}:
        fields = ("key", "keyname", "name", "valuename", "target_group", "member")
        selected = [f"{field}={value[field]}" for field in fields if field in value]
        if selected:
            return f"{name}|{'|'.join(selected)}"
    return name


def analyze_gpo_security(data: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()

    for gpo in data.get("gpos", []):
        guid = str(gpo.get("objectGUID") or gpo.get("distinguishedName") or "unknown")
        label = str(gpo.get("displayName") or gpo.get("name") or guid)
        for setting in gpo.get("settings", []):
            name = str(setting.get("setting") or "")
            value = setting.get("observed_value")
            folded = name.casefold()
            value_text = str(value).strip()
            value_folded = value_text.casefold()
            rule_id = ""
            title = ""
            severity = Severity.INFO
            rationale = ""
            remediation = ""

            if folded == "minimumpasswordlength":
                number = _number(value)
                if number is not None and number < 8:
                    rule_id = "AD-GPO-001"
                    title = "GPO configures a short minimum password length"
                    severity = Severity.MEDIUM
                    rationale = f"The collected MinimumPasswordLength is {number}, below the review threshold of 8 characters."
                    remediation = "Compare the configured minimum with the organization's current authentication standard and raise it where required; prefer modern password and MFA controls."
            elif folded == "passwordcomplexity" and value_folded in {"0", "false", "no"}:
                rule_id = "AD-GPO-001"
                title = "GPO disables password complexity"
                severity = Severity.MEDIUM
                rationale = "The collected PasswordComplexity setting is disabled."
                remediation = "Review the domain password policy and use a modern password policy aligned with organizational requirements."
            elif folded == "cleartextpassword" and value_folded in {"1", "true", "yes"}:
                rule_id = "AD-GPO-003"
                title = "GPO permits reversible password storage"
                severity = Severity.HIGH
                rationale = "The collected security-template setting ClearTextPassword is enabled."
                remediation = "Disable reversible password storage unless a documented legacy requirement has an approved compensating control."
            elif folded == "groups:member" and isinstance(value, dict):
                target_group = str(value.get("target_group", "")).casefold()
                member = str(value.get("member", ""))
                broad_member = any(token in member.casefold() for token in (
                    "everyone", "authenticated users", "domain users", "\\users", "s-1-1-0",
                ))
                privileged_target = any(token in target_group for token in (
                    "administrators", "remote desktop users", "backup operators",
                ))
                if broad_member and privileged_target:
                    rule_id = "AD-GPO-004"
                    title = "GPO adds a broad principal to a privileged local group"
                    severity = Severity.HIGH
                    rationale = f"The collected Group Policy Preferences membership adds {member} to {value.get('target_group')}."
                    remediation = "Remove broad principals from privileged local groups and assign access through a narrowly scoped, approved group."
            elif folded == "lockoutbadcount":
                threshold = _number(value)
                if threshold == 0 or (threshold is not None and threshold > 10):
                    rule_id = "AD-GPO-002"
                    title = "GPO configures a weak account lockout threshold"
                    severity = Severity.MEDIUM
                    rationale = f"The collected LockoutBadCount is {threshold}; zero disables lockout and a value above 10 permits many guesses."
                    remediation = "Set an account-lockout or equivalent smart-lockout policy based on the organization's authentication and availability requirements."
            elif folded in {"sedebugprivilege", "setcbprivilege", "seimpersonateprivilege", "sebackupprivilege", "serestoreprivilege", "setakeownershipprivilege", "seloaddriverprivilege"}:
                principals = _principal_values(value)
                broad = sorted(
                    principal for principal in principals
                    if any(token in principal.casefold() for token in (
                        "everyone", "authenticated users", "domain users", "\\users", "s-1-1-0",
                        "s-1-5-11", "s-1-5-32-545",
                    ))
                )
                if broad:
                    rule_id = "AD-GPO-005"
                    title = "GPO grants a sensitive user right to a broad principal"
                    severity = Severity.HIGH
                    rationale = f"The collected {name} assignment includes {', '.join(broad)}."
                    remediation = "Restrict the right to the smallest approved administrative or service group and validate operational dependencies."
            elif folded.endswith(("__members", "__memberof")):
                principals = _principal_values(value)
                broad = [
                    principal for principal in principals
                    if any(token in principal.casefold() for token in (
                        "everyone", "authenticated users", "domain users", "s-1-1-0", "s-1-5-11",
                    ))
                ]
                target_sid = name.rsplit("__", 1)[0]
                privileged_local_sid = any(target_sid.endswith(f"-{rid}") for rid in ("544", "551", "555"))
                if broad and privileged_local_sid:
                    rule_id = "AD-GPO-004"
                    title = "GPO assigns a broad principal to a privileged local group"
                    severity = Severity.HIGH
                    rationale = f"The collected Restricted Groups setting for {target_sid} includes {', '.join(broad)}."
                    remediation = "Remove broad principals from privileged local groups and grant access through a narrowly scoped, approved group."
            elif setting.get("credential_exposure"):
                rule_id = "AD-GPO-008"
                severity = Severity.HIGH
                if setting.get("credential_exposure_kind") == "registry":
                    title = "GPO contains a credential-like registry value"
                    rationale = "A registry policy value is associated with a password, credential, or secret-named setting; its value was deliberately withheld."
                else:
                    title = "GPO Preferences contains a legacy cpassword field"
                    rationale = "A Group Policy Preferences XML item contains a cpassword attribute; its value was deliberately withheld."
                remediation = "Remove the credential-bearing policy value and rotate any potentially exposed secret; use a managed account or another supported secret-management method."
            elif folded == "configured policy script":
                rule_id = "AD-GPO-009"
                title = "GPO configures a startup, shutdown, logon, or logoff script"
                severity = Severity.INFO
                rationale = "A policy script entry is configured. Script contents were not executed or collected."
                remediation = "Review script ownership, write permissions, signing, and contents through the organization's change-control process."
            elif folded.endswith(":command") or folded.endswith(":program"):
                if "scheduledtasks" in folded:
                    rule_id = "AD-GPO-009"
                    title = "GPO configures a scheduled task command"
                    severity = Severity.INFO
                    rationale = "A scheduled-task command is configured; command text and arguments were not retained."
                    remediation = "Review task ownership, execution context, command path permissions, and change controls."
            elif "scheduledtasks:properties" in folded and isinstance(value, dict):
                if str(value.get("runlevel", "")).casefold() in {"highest", "highestavailable"}:
                    rule_id = "AD-GPO-009"
                    title = "GPO configures a scheduled task for highest privilege"
                    severity = Severity.INFO
                    rationale = "The collected scheduled-task properties request the highest available run level."
                    remediation = "Confirm the task requires elevation and restrict its principal, command path, and modification rights."
            elif folded in {"registry:registry", "registry:properties", "registryproperties"}:
                risk = _registry_risk(value)
                if risk:
                    rule_id = "AD-GPO-010"
                    title = risk[0]
                    severity = risk[1]
                    rationale = risk[2]
                    remediation = risk[3]
            if not rule_id:
                continue

            setting_identity = _setting_identity(setting)
            identity = (guid.casefold(), rule_id, _normalized(setting_identity))
            if identity in seen:
                continue
            seen.add(identity)
            matching_settings = [
                item for item in gpo.get("settings", [])
                if _normalized(_setting_identity(item)) == _normalized(setting_identity)
            ]
            links = gpo.get("links", [])
            evidence = {
                "gpo_name": label,
                "gpo_guid": guid,
                "gpo_dn": gpo.get("distinguishedName", ""),
                "linked_objects": [link.get("linked_object_dn", "") for link in links],
                "setting": name,
                "observed_value": value,
                "expected_or_recommended_configuration": remediation,
                "observed_values": list(dict.fromkeys(
                    repr(item.get("observed_value")) for item in matching_settings
                )),
                "source_files": sorted({str(item.get("source_file", "")) for item in matching_settings}),
                "section": setting.get("section", ""),
                "link_observation_only": True,
            }
            raw = {
                "setting_records": matching_settings,
                "gpo_attributes": gpo.get("source_attributes", {}),
                "links": links,
            }
            findings.append(make_finding(
                rule_id,
                f"{guid}|{setting_identity}|{hashlib.sha256(_normalized(value).encode()).hexdigest()[:12]}",
                title=title,
                severity=severity,
                category="GPO Security",
                affected_object=label,
                affected_type="Group Policy Object",
                description=(
                    f"{rationale} This is a linked-policy observation; effective endpoint application "
                    "was not established."
                ),
                evidence=evidence,
                impact="If this linked policy is processed in scope, the observed configuration may weaken the applicable security control.",
                remediation=remediation,
                confidence="High" if severity != Severity.INFO else "Medium",
                source_attributes=["gPCFileSysPath", "gPLink", "gPOptions", "policy setting"],
                raw_evidence=raw,
                detection_limitations=(
                    "LDAP links and readable policy files do not establish endpoint-effective policy. "
                    "Security filtering, WMI filters, inheritance, client processing, and precedence were not fully evaluated."
                ),
            ))
    return findings


def _principal_values(value: Any) -> list[str]:
    if isinstance(value, (list, tuple)):
        values = value
    else:
        values = str(value).split(",")
    return [str(item).strip().lstrip("*") for item in values if str(item).strip()]


def _registry_risk(value: Any) -> tuple[str, Severity, str, str] | None:
    if not isinstance(value, dict):
        return None
    key = " ".join(str(value.get(name, "")) for name in ("key", "keyname", "name")).casefold()
    setting_value = str(value.get("value", "")).strip().casefold()
    if "enablelua" in key and setting_value in {"0", "false"}:
        return (
            "GPO disables User Account Control", Severity.HIGH,
            "The collected registry policy sets EnableLUA to 0.",
            "Keep UAC enabled and validate any legacy application exception separately.",
        )
    if "uselogoncredential" in key and setting_value in {"1", "true"}:
        return (
            "GPO enables WDigest credential caching", Severity.HIGH,
            "The collected registry policy sets UseLogonCredential to 1.",
            "Disable WDigest credential caching and review systems that require legacy authentication.",
        )
    if "lmcompatibilitylevel" in key and setting_value in {"0", "1", "2"}:
        return (
            "GPO permits legacy LAN Manager authentication", Severity.MEDIUM,
            f"The collected registry policy sets LmCompatibilityLevel to {setting_value}.",
            "Require NTLMv2 or a stronger supported authentication protocol after validating compatibility requirements.",
        )
    if "enablesmb1protocol" in key and setting_value in {"1", "true"}:
        return (
            "GPO enables SMBv1", Severity.HIGH,
            "The collected registry policy enables the legacy SMBv1 protocol.",
            "Disable SMBv1 after validating dependent systems and services.",
        )
    if "ldapserverintegrity" in key and setting_value == "0":
        return (
            "GPO disables LDAP server signing requirements", Severity.MEDIUM,
            "The collected registry policy sets LDAPServerIntegrity to 0.",
            "Require LDAP signing where supported and validate client compatibility.",
        )
    return None