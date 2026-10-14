from copy import deepcopy
from threading import Event
from unittest.mock import MagicMock, patch

from core.findings import FindingEngine
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
from core.findings.rules.privilege import analyze_privileged_membership
from core.models import Finding, Severity
from core.trust_assessment import decode_trust
from core.ldap_connection import ConnectionTestResult
from core.scanner import AssessmentCancelled
from gui.main_window import LDAPTestWorker


def _user(name: str, flags: int, rid: int | None = None, dn: str | None = None) -> dict:
    sid = f"S-1-5-21-111-222-333-{rid}" if rid is not None else "S-1-5-21-111-222-333-1100"
    return {
        "sAMAccountName": name,
        "dn": dn or f"CN={name},CN=Users,DC=example,DC=local",
        "userAccountControl": flags,
        "objectSid": sid,
        "memberOf": [],
    }


def test_account_rules_use_uac_bits_and_skip_disabled_accounts() -> None:
    data = {"users": [
        _user("svc", 0x10000 | 0x20),
        _user("disabled", 0x10000 | 0x2),
    ]}

    findings = analyze_account_security(data)

    assert {finding.title for finding in findings} == {
        "User account configured with password never expires",
        "User account does not require a password",
    }
    assert all("disabled" not in finding.affected_object for finding in findings)
    assert all(finding.evidence["userAccountControl"] == 0x10020 for finding in findings)


def test_asrep_rule_records_disabled_state_and_flag_evidence() -> None:
    findings = analyze_asrep_exposure({"users": [
        _user("asrep", 0x400000),
        _user("disabled", 0x400002),
        _user("normal", 512),
    ]})

    assert len(findings) == 2
    assert {finding.affected_object for finding in findings} == {"asrep", "disabled"}
    assert findings[0].evidence["userAccountControl"] in {0x400000, 0x400002}
    assert any("disabled" in finding.description.lower() for finding in findings)


def test_spn_rule_aggregates_spns_and_skips_machine_accounts() -> None:
    service_user = _user("svc_sql", 512)
    machine = {
        "sAMAccountName": "COMPUTER$",
        "dn": "CN=COMPUTER,OU=Servers,DC=example,DC=local",
        "userAccountControl": 0x8200,
        "objectClass": ["computer"],
    }
    data = {
        "users": [service_user, _user("disabled_svc", 514), machine],
        "spns": [
            {"sAMAccountName": "svc_sql", "dn": service_user["dn"], "servicePrincipalName": ["MSSQLSvc/sql01"]},
            {"sAMAccountName": "svc_sql", "dn": service_user["dn"], "servicePrincipalName": ["MSSQLSvc/sql01.example.local"]},
            {"sAMAccountName": "COMPUTER$", "servicePrincipalName": ["HOST/computer"]},
            {"sAMAccountName": "disabled_svc", "servicePrincipalName": ["HTTP/disabled"]},
        ],
    }

    findings = analyze_user_spns(data)

    assert len(findings) == 1
    assert findings[0].evidence["servicePrincipalName"] == [
        "MSSQLSvc/sql01", "MSSQLSvc/sql01.example.local"
    ]
    assert findings[0].evidence["serviceClasses"] == ["MSSQLSvc"]
    assert all("COMPUTER" not in finding.affected_object for finding in findings)


def test_unconstrained_delegation_checks_enabled_users_and_computers() -> None:
    data = {
        "users": [_user("delegated", 0x80000), _user("disabled", 0x80002)],
        "computers": [{
            "sAMAccountName": "server$",
            "dn": "CN=server,DC=example,DC=local",
            "userAccountControl": 0x1000 | 0x80000,
        }],
    }

    findings = analyze_unconstrained_delegation(data)

    assert {finding.affected_object for finding in findings} == {"delegated", "server$"}
    assert all(finding.evidence["userAccountControl"] & 0x80000 for finding in findings)


def test_privileged_membership_aggregates_direct_and_nested_groups() -> None:
    user = _user("alice", 512)
    nested_group = {
        "name": "Tier 1 Admins",
        "dn": "CN=Tier 1 Admins,OU=Groups,DC=example,DC=local",
        "member": [user["dn"]],
    }
    domain_admins = {
        "name": "Domain Admins",
        "dn": "CN=Domain Admins,CN=Users,DC=example,DC=local",
        "member": [nested_group["dn"]],
    }
    direct_group = {
        "name": "Backup Operators",
        "dn": "CN=Backup Operators,CN=Builtin,DC=example,DC=local",
        "member": [user["dn"]],
    }
    findings = analyze_privileged_membership({
        "users": [user],
        "groups": [nested_group, domain_admins, direct_group],
    })

    assert len(findings) == 1
    groups = findings[0].evidence["privileged_groups"]
    assert {group["name"] for group in groups} == {"Domain Admins", "Backup Operators"}
    assert next(group for group in groups if group["name"] == "Domain Admins")["relationship"] == "Nested"
    assert next(group for group in groups if group["name"] == "Backup Operators")["relationship"] == "Direct"


def test_privileged_membership_resolves_primary_group_from_sids() -> None:
    user = _user("primary_admin", 512)
    user["primaryGroupID"] = 512
    domain_sid = user["objectSid"].rsplit("-", 1)[0]
    primary_group = {
        "name": "Domain Admins",
        "dn": "CN=Domain Admins,CN=Users,DC=example,DC=local",
        "objectSid": f"{domain_sid}-512",
        "member": [],
    }

    findings = analyze_privileged_membership({"users": [user], "groups": [primary_group]})

    assert len(findings) == 1
    assert findings[0].evidence["privileged_groups"][0]["relationship"] == "Direct"


def test_builtin_accounts_use_sid_and_only_enabled_accounts_are_reported() -> None:
    findings = analyze_account_security({"users": [
        _user("renamed_admin", 512, rid=500),
        _user("disabled_admin", 514, rid=500),
        _user("renamed_guest", 512, rid=501),
        _user("disabled_guest", 514, rid=501),
        _user("Administrator", 512, rid=1200),
    ]})

    assert {finding.title for finding in findings} == {
        "Built-in Administrator account is enabled",
        "Guest account is enabled",
    }


def test_pre_windows_group_only_flags_collected_broad_membership() -> None:
    data = {"groups": [
        {"name": "Pre-Windows 2000 Compatible Access", "dn": "CN=PreWin,DC=example,DC=local", "member": []},
        {"name": "Pre-Windows 2000 Compatible Access", "dn": "CN=PreWin2,DC=example,DC=local", "member": ["CN=Everyone,CN=WellKnown Security Principals,DC=example,DC=local"]},
    ]}

    findings = analyze_pre_windows_2000_access(data)

    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].evidence["member"][0].startswith("CN=Everyone,")


def test_engine_deduplicates_and_does_not_mutate_inventory() -> None:
    data = {
        "users": [_user("svc_sql", 0x10000)],
        "groups": [],
        "computers": [],
        "spns": [],
    }
    before = deepcopy(data)
    engine = FindingEngine(rules=(analyze_account_security, analyze_account_security))

    first = engine.analyze(data)
    second = engine.analyze(data)

    assert len(first) == 1
    assert first[0].finding_id == second[0].finding_id
    assert data == before
    assert isinstance(first[0], Finding)
    assert first[0].source == "AD-AS-001"


def test_missing_attributes_do_not_create_findings() -> None:
    data = {
        "users": [{"sAMAccountName": "unknown", "dn": "CN=unknown,DC=example,DC=local"}],
        "groups": [{"name": "Pre-Windows 2000 Compatible Access"}],
        "computers": [{"sAMAccountName": "server$"}],
        "spns": [{"sAMAccountName": "unknown", "servicePrincipalName": ["HTTP/app"]}],
    }

    assert FindingEngine().analyze(data) == []


def test_engine_registers_ou_trust_and_protocol_rules() -> None:
    trust = decode_trust({"source_attributes": {
        "trustPartner": "external.example", "trustDirection": 1, "trustType": 1,
        "trustAttributes": 0,
    }}, "example.local")
    trust["distinguishedName"] = "CN=external,CN=System,DC=example,DC=local"
    findings = FindingEngine().analyze({
        "ous": [{
            "name": "Empty OU", "distinguishedName": "OU=Empty,DC=example,DC=local",
            "gPLink": None, "direct_gpo_links": [], "description": "documented",
        }],
        "trusts": [trust],
        "protocols": [{
            "check": "Configured LDAP client transport", "status": "Plain LDAP configured",
            "evidence_source": "Client settings", "port": 389,
        }],
    })

    assert {finding.category for finding in findings} == {
        "OU Security", "Trust Security", "Protocol Security",
    }


def test_advanced_kerberos_and_delegation_rules_generate_evidence_based_findings() -> None:
    data = {
        "users": [
            {
                "sAMAccountName": "svc_sql",
                "dn": "CN=svc_sql,CN=Users,DC=example,DC=local",
                "userAccountControl": 512,
                "memberOf": ["CN=Domain Admins,CN=Users,DC=example,DC=local"],
                "objectSid": "S-1-5-21-111-222-333-1100",
            },
            {
                "sAMAccountName": "asrepuser",
                "dn": "CN=asrepuser,CN=Users,DC=example,DC=local",
                "userAccountControl": 0x400000,
                "memberOf": [],
                "objectSid": "S-1-5-21-111-222-333-1200",
            },
            {
                "sAMAccountName": "krbtgt",
                "dn": "CN=krbtgt,CN=Users,DC=example,DC=local",
                "userAccountControl": 544,
                "memberOf": [],
                "objectSid": "S-1-5-21-111-222-333-502",
            },
        ],
        "groups": [
            {
                "name": "Domain Admins",
                "dn": "CN=Domain Admins,CN=Users,DC=example,DC=local",
                "member": ["CN=svc_sql,CN=Users,DC=example,DC=local"],
            }
        ],
        "computers": [
            {
                "sAMAccountName": "DC01$",
                "dn": "CN=DC01,OU=Domain Controllers,DC=example,DC=local",
                "dNSHostName": "dc01.example.local",
                "userAccountControl": 0x80000,
                "operatingSystem": "Windows Server",
                "msDS-AllowedToDelegateTo": ["LDAP/DC01.example.local"],
            },
            {
                "sAMAccountName": "sql01$",
                "dn": "CN=sql01,CN=Computers,DC=example,DC=local",
                "dNSHostName": "sql01.example.local",
                "userAccountControl": 0,
                "msDS-AllowedToActOnBehalfOfOtherIdentity": ["CN=svc_sql,CN=Users,DC=example,DC=local"],
            },
        ],
        "spns": [
            {
                "sAMAccountName": "svc_sql",
                "dn": "CN=svc_sql,CN=Users,DC=example,DC=local",
                "servicePrincipalName": ["MSSQLSvc/sql01.example.local:1433"],
            }
        ],
        "domain_controllers": [
            {"sAMAccountName": "DC01$", "dNSHostName": "dc01.example.local"}
        ],
    }

    findings = FindingEngine().analyze(data)
    titles = {finding.title for finding in findings}
    assert "Kerberoasting exposure: user/service account has an SPN" in titles
    assert "AS-REP roasting exposure: Kerberos pre-authentication disabled" in titles
    assert "Unconstrained delegation configured" in titles
    assert "Constrained delegation configured" in titles
    assert "Resource-Based Constrained Delegation configured" in titles
    assert "Privileged account has a Service Principal Name" in titles
    assert any(finding.technique == "Kerberoasting" for finding in findings)
    assert any(finding.mitre_attack == "T1558.003" for finding in findings)


def test_finding_metadata_supports_technique_and_mitre_fields() -> None:
    finding = Finding(
        finding_id="AD-EX-001",
        title="Test finding",
        severity=Severity.HIGH,
        category="Kerberos",
        affected_object="svc_sql",
        affected_type="User",
        description="Evidence-driven assessment only.",
        evidence={"sAMAccountName": "svc_sql"},
        security_impact="This is an assessment, not an attack.",
        recommended_remediation="Review the account configuration.",
        technique="Kerberoasting",
        mitre_attack="T1558.003",
        source_attributes=["servicePrincipalName"],
        raw_evidence={"servicePrincipalName": ["MSSQLSvc/sql01.example.local:1433"]},
    )

    assert finding.technique == "Kerberoasting"
    assert finding.mitre_attack == "T1558.003"
    assert finding.source_attributes == ["servicePrincipalName"]
    assert finding.raw_evidence["servicePrincipalName"] == ["MSSQLSvc/sql01.example.local:1433"]
    assert "does not" in finding.detection_limitations.lower()


def test_worker_analyzes_after_scan_and_preserves_inventory_records() -> None:
    user = _user("svc", 0x10000)
    inventory = {
        "server": "192.0.2.10",
        "server_name": "DC01",
        "domain": "EXAMPLE",
        "base_dn": "DC=example,DC=local",
        "users": [user],
        "groups": [],
        "computers": [],
        "domain_controllers": [],
        "spns": [],
    }
    manager = MagicMock()
    manager.connect.return_value = ConnectionTestResult(
        True, "192.0.2.10", "LDAP authentication succeeded",
        resolved_ip="192.0.2.10", ldap_reachable=True,
    )
    output: list[dict] = []
    with patch("gui.main_window.AssessmentScanner") as scanner_class:
        scanner_class.return_value.run_assessment.return_value = inventory
        worker = LDAPTestWorker(manager)
        worker.completed.connect(output.append)
        worker.run()

    assert output[0]["success"] is True
    result_data = output[0]["data"]
    assert result_data["users"] is inventory["users"]
    assert result_data["findings"][0].title == "User account configured with password never expires"
    assert "findings" not in inventory
    assert "connection_diagnostics" not in inventory
    manager.disconnect.assert_called_once()


def test_worker_stop_before_connect_is_cancelled_and_cleans_up() -> None:
    manager = MagicMock()
    cancellation = Event()
    cancellation.set()
    output: list[dict] = []
    worker = LDAPTestWorker(manager, cancellation)
    worker.completed.connect(output.append)

    worker.run()

    assert output[0]["status"] == "cancelled"
    manager.connect.assert_not_called()
    manager.disconnect.assert_called_once()


def test_worker_cancel_during_scan_skips_findings_and_disconnects() -> None:
    manager = MagicMock()
    manager.connect.return_value = ConnectionTestResult(
        True, "192.0.2.10", "LDAP authentication succeeded",
        resolved_ip="192.0.2.10", ldap_reachable=True,
    )
    partial = {
        "domain": "EXAMPLE",
        "users": [{"sAMAccountName": "alice"}],
        "completed_categories": [],
        "in_progress_category": "users",
    }
    output: list[dict] = []
    cancellation = Event()

    def cancel_scan(_progress, event):
        event.set()
        raise AssessmentCancelled(partial)

    with (
        patch("gui.main_window.AssessmentScanner") as scanner_class,
        patch("gui.main_window.FindingEngine.analyze") as analyze,
    ):
        scanner_class.return_value.run_assessment.side_effect = cancel_scan
        worker = LDAPTestWorker(manager, cancellation)
        worker.completed.connect(output.append)
        worker.run()

    assert output[0]["status"] == "cancelled"
    assert output[0]["partial_data"] is partial
    analyze.assert_not_called()
    manager.disconnect.assert_called_once()


def test_worker_keeps_connection_failures_as_failed_not_cancelled() -> None:
    manager = MagicMock()
    manager.connect.return_value = ConnectionTestResult(
        False, "dc01.example.local", "LDAP authentication failed", error_type="LDAPException"
    )
    output: list[dict] = []
    worker = LDAPTestWorker(manager, Event())
    worker.completed.connect(output.append)

    worker.run()

    assert output[0]["status"] == "failed"
    assert output[0]["success"] is False
    manager.disconnect.assert_called_once()


def test_stop_requested_during_connect_is_seen_before_directory_queries() -> None:
    manager = MagicMock()
    manager.settings.server = "192.0.2.10"
    cancellation = Event()
    manager.connect.side_effect = lambda _callback: (
        cancellation.set(),
        ConnectionTestResult(
            True, "192.0.2.10", "LDAP authentication succeeded",
            resolved_ip="192.0.2.10", ldap_reachable=True,
        ),
    )[1]
    output: list[dict] = []
    with patch("gui.main_window.FindingEngine.analyze") as analyze:
        worker = LDAPTestWorker(manager, cancellation)
        worker.completed.connect(output.append)
        worker.run()

    assert output[0]["status"] == "cancelled"
    assert output[0]["partial_data"]["completed_categories"] == []
    analyze.assert_not_called()
    manager.disconnect.assert_called_once()