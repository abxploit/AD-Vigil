"""Privileged group membership rules, including nested group paths."""

from collections import defaultdict
from typing import Any

from core.findings.rules.common import is_disabled, make_finding, sid_string, text, values
from core.models import Finding, Severity


PRIVILEGED_GROUPS = {
    "domain admins",
    "enterprise admins",
    "administrators",
    "account operators",
    "backup operators",
    "server operators",
    "dnsadmins",
    "schema admins",
}


def analyze_privileged_service_account(data: dict[str, Any]) -> list[Finding]:
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
    spns_by_account: dict[str, list[str]] = defaultdict(list)
    for record in data.get("spns", []):
        account = text(record, "sAMAccountName")
        if account:
            spns_by_account[account.casefold()].extend(str(item) for item in values(record, "servicePrincipalName"))

    findings: list[Finding] = []
    for username, record in users.items():
        spns = list(dict.fromkeys(spns_by_account.get(username, [])))
        if not spns or is_disabled(record) is not False:
            continue
        member_groups = []
        for member_dn in values(record, "memberOf"):
            group_name = groups_by_dn.get(str(member_dn).casefold())
            if group_name and group_name.casefold() in PRIVILEGED_GROUPS:
                member_groups.append({"name": group_name, "dn": str(member_dn), "relationship": "Direct"})
        if not member_groups:
            continue
        evidence = {
            "Account": text(record, "sAMAccountName"),
            "SPNs": spns,
            "Privileged groups": member_groups,
            "dn": text(record, "dn"),
            "memberOf": record.get("memberOf", []),
        }
        findings.append(make_finding(
            "AD-PRIV-002", text(record, "dn") or username,
            title="Privileged account has a Service Principal Name",
            severity=Severity.HIGH,
            category="Kerberos / Privilege",
            affected_object=text(record, "sAMAccountName"),
            affected_type="User",
            description="The account combines an SPN with elevated privileges and should be reviewed for service-account security and unnecessary privileges.",
            evidence=evidence,
            impact="The combination of a service principal and elevated domain privileges increases the importance of reviewing the account's purpose, exposure, and credential protection.",
            remediation="Review whether the SPN and privileged group membership are both necessary; prefer a managed service-account pattern and remove unnecessary privileges.",
            technique="Kerberoasting",
            mitre_attack="T1558.003",
            source_attributes=["sAMAccountName", "servicePrincipalName", "memberOf", "dn"],
            raw_evidence=evidence,
        ))
    return findings


def analyze_privileged_membership(data: dict[str, Any]) -> list[Finding]:
    groups = data.get("groups", [])
    groups_by_dn = {
        text(group, "dn").casefold(): group
        for group in groups
        if text(group, "dn")
    }
    groups_by_sid = {
        sid.casefold(): group
        for group in groups
        if (sid := sid_string(group)) is not None
    }
    parent_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for group in groups:
        group_dn = text(group, "dn")
        if not group_dn:
            continue
        for member_dn in values(group, "member"):
            key = str(member_dn).casefold()
            if all(text(parent, "dn").casefold() != group_dn.casefold() for parent in parent_groups[key]):
                parent_groups[key].append(group)

    for user in data.get("users", []):
        user_dn = text(user, "dn")
        if not user_dn:
            continue
        for group_dn in values(user, "memberOf"):
            group = groups_by_dn.get(str(group_dn).casefold())
            if group is not None:
                key = user_dn.casefold()
                if all(text(parent, "dn").casefold() != str(group_dn).casefold() for parent in parent_groups[key]):
                    parent_groups[key].append(group)
        user_sid = sid_string(user)
        try:
            primary_group_id = int(text(user, "primaryGroupID"))
        except ValueError:
            continue
        if user_sid is not None:
            domain_sid = user_sid.rsplit("-", 1)[0]
            primary_group = groups_by_sid.get(f"{domain_sid}-{primary_group_id}".casefold())
            if primary_group is not None:
                key = user_dn.casefold()
                if all(
                    text(parent, "dn").casefold() != text(primary_group, "dn").casefold()
                    for parent in parent_groups[key]
                ):
                    parent_groups[key].append(primary_group)

    findings: list[Finding] = []
    for user in data.get("users", []):
        if is_disabled(user) is not False:
            continue
        user_dn = text(user, "dn")
        username = text(user, "sAMAccountName")
        if not user_dn or not username:
            continue

        memberships: dict[str, dict[str, Any]] = {}

        def walk(member_dn: str, path: list[str], visited: set[str]) -> None:
            for parent in parent_groups.get(member_dn.casefold(), []):
                parent_dn = text(parent, "dn")
                parent_key = parent_dn.casefold()
                if not parent_dn or parent_key in visited:
                    continue
                next_path = [*path, parent_dn]
                group_name = text(parent, "name") or text(parent, "sAMAccountName")
                if group_name.casefold() in PRIVILEGED_GROUPS:
                    existing = memberships.get(parent_key)
                    if existing is None or len(next_path) < len(existing["path"]):
                        memberships[parent_key] = {
                            "name": group_name,
                            "dn": parent_dn,
                            "relationship": "Direct" if len(next_path) == 2 else "Nested",
                            "path": next_path,
                        }
                else:
                    walk(parent_dn, next_path, {*visited, parent_key})

        walk(user_dn, [user_dn], {user_dn.casefold()})
        if not memberships:
            continue
        groups_evidence = list(memberships.values())
        findings.append(make_finding(
            "AD-PRIV-001", user_dn,
            title="User is a member of a highly privileged Active Directory group",
            severity=Severity.HIGH,
            category="Privilege",
            affected_object=username,
            affected_type="User",
            description="Collected direct or nested group membership places this enabled user in one or more privileged groups.",
            evidence={
                "sAMAccountName": user.get("sAMAccountName", username),
                "user_dn": user_dn,
                "privileged_groups": groups_evidence,
                "memberOf": user.get("memberOf", []),
            },
            impact="These groups can grant broad control over domain identities, systems, or directory configuration.",
            remediation="Review each assignment and remove memberships that are not required; use time-bound or delegated administration where available.",
        ))
    return findings