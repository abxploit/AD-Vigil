from pathlib import Path
from threading import Event
from unittest.mock import MagicMock

import pytest

from core.findings.rules.gpo import analyze_gpo_security
from core.gpo_assessment import assess_gpo_contents, discover_gpos, parse_gpo_links
from core.scanner import AssessmentCancelled, AssessmentScanner
from core.models import Severity


GUID = "11111111-2222-3333-4444-555555555555"
GPO_DN = f"CN={{{GUID}}},CN=Policies,CN=System,DC=example,DC=local"


def test_link_parser_preserves_order_enabled_state_and_enforcement() -> None:
    links = parse_gpo_links(
        f"[LDAP://{GPO_DN};0][LDAP://CN={{{GUID}}},CN=Policies,CN=System,DC=example,DC=local;1]"
        f"[LDAP://{GPO_DN};2]"
    )

    assert [link["link_order"] for link in links] == [1, 2, 3]
    assert links[0]["enabled"] is True and links[0]["enforced"] is False
    assert links[1]["enabled"] is False and links[1]["enforced"] is False
    assert links[2]["enabled"] is True and links[2]["enforced"] is True
    assert links[0]["gpo_guid"] == GUID
    assert parse_gpo_links(None) == []


def test_discovery_collects_gpo_attributes_links_and_unknown_inheritance() -> None:
    connection = MagicMock()
    connection.connection.server.info.other = {
        "configurationNamingContext": ["CN=Configuration,DC=example,DC=local"]
    }
    domain = {
        "type": "searchResEntry",
        "dn": "DC=example,DC=local",
        "attributes": {
            "name": "example", "objectClass": ["top", "domainDNS"],
            "gPLink": f"[LDAP://{GPO_DN};2]",
        },
    }
    gpo = {
        "type": "searchResEntry",
        "dn": GPO_DN,
        "attributes": {
            "displayName": "Baseline", "name": f"{{{GUID}}}", "objectGUID": f"{{{GUID}}}",
            "gPCFileSysPath": r"\\example.local\SYSVOL\example.local\Policies\baseline",
            "gPCFunctionalityVersion": 2, "flags": 0, "versionNumber": 65536,
        },
    }

    def paged_search(**kwargs):
        if kwargs["search_filter"] == "(objectClass=groupPolicyContainer)":
            return [gpo]
        if kwargs["search_filter"] == "(|(objectClass=domainDNS)(objectClass=organizationalUnit))":
            return [domain]
        return []

    connection.connection.extend.standard.paged_search.side_effect = paged_search
    result = discover_gpos(connection, "DC=example,DC=local")

    assert result["gpos"][0]["displayName"] == "Baseline"
    assert result["gpos"][0]["versionNumber"] == 65536
    assert result["gpos"][0]["links"][0]["link_order"] == 1
    assert result["gpos"][0]["links"][0]["enforced"] is True
    assert result["gpos"][0]["links"][0]["block_inheritance"] is None
    assert result["gpo_links"][0]["linked_object_type"] == "Domain"


def _policy_root(tmp_path: Path) -> Path:
    root = tmp_path / "policy"
    (root / "Machine" / "Microsoft" / "Windows NT" / "SecEdit").mkdir(parents=True)
    return root


def test_content_parser_extracts_inf_settings_and_marks_missing_path_inaccessible(tmp_path: Path) -> None:
    root = _policy_root(tmp_path)
    (root / "Machine" / "Microsoft" / "Windows NT" / "SecEdit" / "GptTmpl.inf").write_text(
        "[System Access]\nMinimumPasswordLength = 6\nLockoutBadCount = 0\n",
        encoding="utf-8",
    )
    records = [
        {"objectGUID": GUID, "gPCFileSysPath": str(root)},
        {"objectGUID": "missing", "gPCFileSysPath": str(tmp_path / "absent")},
    ]

    assess_gpo_contents(records)

    assert records[0]["assessment_status"] == "Assessed successfully"
    assert {item["setting"] for item in records[0]["settings"]} == {
        "MinimumPasswordLength", "LockoutBadCount",
    }
    assert records[1]["assessment_status"] == "Inaccessible"
    assert "unavailable" in records[1]["content_assessment_reason"]


def test_malformed_xml_is_partial_and_cpassword_value_is_never_retained(tmp_path: Path) -> None:
    root = tmp_path / "policy"
    xml_dir = root / "Machine" / "Preferences" / "Groups"
    xml_dir.mkdir(parents=True)
    (xml_dir / "Groups.xml").write_text(
        '<Groups><User name="svc" cpassword="DO_NOT_RETAIN" /></Groups>', encoding="utf-8"
    )
    gpo = {"objectGUID": GUID, "gPCFileSysPath": str(root)}
    assess_gpo_contents([gpo])

    assert any(item.get("credential_exposure") for item in gpo["settings"])
    assert "DO_NOT_RETAIN" not in repr(gpo)
    assert gpo["assessment_status"] == "Assessed successfully"

    (xml_dir / "Groups.xml").write_text("<Groups><broken>", encoding="utf-8")
    malformed = {"objectGUID": GUID, "gPCFileSysPath": str(root)}
    assess_gpo_contents([malformed])
    assert malformed["assessment_status"] == "Partially assessed"
    assert "ParseError" in malformed["content_assessment_reason"]


def test_script_ini_is_inspected_as_metadata_without_execution_or_command_retention(tmp_path: Path) -> None:
    root = tmp_path / "policy"
    script_dir = root / "Machine" / "Scripts"
    script_dir.mkdir(parents=True)
    (script_dir / "scripts.ini").write_text(
        "[Startup]\n0=powershell -Command Set-Content marker.txt executed\n", encoding="utf-8"
    )
    gpo = {"objectGUID": GUID, "gPCFileSysPath": str(root)}

    assess_gpo_contents([gpo])

    assert any(item["setting"] == "Configured policy script" for item in gpo["settings"])
    assert "Set-Content" not in repr(gpo)
    assert not (script_dir / "marker.txt").exists()


def test_unsupported_registry_pol_and_configured_scripts_report_partial_coverage(tmp_path: Path) -> None:
    root = tmp_path / "policy"
    (root / "Machine").mkdir(parents=True)
    (root / "Machine" / "Registry.pol").write_bytes(b"PReg")
    script_dir = root / "Machine" / "Scripts"
    script_dir.mkdir()
    (script_dir / "scripts.ini").write_text("[Startup]\n0=setup.cmd\n", encoding="utf-8")
    gpo = {"objectGUID": GUID, "gPCFileSysPath": str(root)}

    assess_gpo_contents([gpo])

    assert gpo["assessment_status"] == "Partially assessed"
    assert "Registry.pol" in gpo["content_assessment_reason"]
    assert "script bodies" in gpo["content_assessment_reason"]


def test_credential_like_registry_value_is_withheld_from_raw_policy_evidence(tmp_path: Path) -> None:
    root = _policy_root(tmp_path)
    policy_file = root / "Machine" / "Microsoft" / "Windows NT" / "SecEdit" / "GptTmpl.inf"
    policy_file.write_text(
        "[Registry Values]\nMACHINE\\Software\\Vendor\\DefaultPassword=1,DO_NOT_RETAIN\n",
        encoding="utf-8",
    )
    gpo = {"objectGUID": GUID, "gPCFileSysPath": str(root)}

    assess_gpo_contents([gpo])

    assert "DO_NOT_RETAIN" not in repr(gpo)
    assert gpo["settings"][0]["credential_exposure"] is True
    assert gpo["settings"][0]["observed_value"]["value"] == "Present (value withheld)"


def test_gpo_rules_use_evidence_and_deduplicate_repeated_policy_settings() -> None:
    gpo = {
        "objectGUID": GUID,
        "displayName": "Baseline",
        "distinguishedName": GPO_DN,
        "source_attributes": {"displayName": "Baseline"},
        "links": [{"linked_object_dn": "OU=Servers,DC=example,DC=local"}],
        "settings": [
            {"setting": "MinimumPasswordLength", "observed_value": "6", "source_file": "GptTmpl.inf"},
            {"setting": "MinimumPasswordLength", "observed_value": "6", "source_file": "Other.inf"},
            {"setting": "LockoutBadCount", "observed_value": "0", "source_file": "GptTmpl.inf"},
            {"setting": "Group Policy Preferences cpassword", "observed_value": "Present (value withheld)", "credential_exposure": True, "source_file": "Groups.xml"},
        ],
    }

    findings = analyze_gpo_security({"gpos": [gpo]})

    assert len(findings) == 3
    assert {finding.category for finding in findings} == {"GPO Security"}
    password = next(item for item in findings if "short minimum" in item.title)
    assert password.severity == Severity.MEDIUM
    assert password.evidence["source_files"] == ["GptTmpl.inf", "Other.inf"]
    assert password.evidence["linked_objects"] == ["OU=Servers,DC=example,DC=local"]
    assert "effective endpoint" in password.description


def test_gpo_rules_cover_privilege_scripts_authentication_and_registry_settings() -> None:
    findings = analyze_gpo_security({"gpos": [{
        "objectGUID": GUID,
        "displayName": "Baseline",
        "distinguishedName": GPO_DN,
        "settings": [
            {"setting": "ClearTextPassword", "observed_value": "1"},
            {"setting": "SeDebugPrivilege", "observed_value": "*S-1-1-0"},
            {"setting": "Groups:Member", "observed_value": {
                "target_group": "Administrators", "member": "Authenticated Users", "action": "ADD",
            }},
            {"setting": "Registry:Properties", "observed_value": {
                "key": "Software\\Policies\\Microsoft\\Windows NT\\DNSClient\\EnableLUA", "value": "0",
            }},
            {"setting": "Registry:Properties", "observed_value": {
                "key": "SYSTEM\\CurrentControlSet\\Control\\Lsa\\UseLogonCredential", "value": "1",
            }},
            {"setting": "Registry:Properties", "observed_value": {
                "key": "SYSTEM\\CurrentControlSet\\Control\\Lsa\\LmCompatibilityLevel", "value": "2",
            }},
            {"setting": "Configured policy script", "observed_value": {"phase": "Startup", "entry": "0"}},
            {"setting": "ScheduledTasks:Properties", "observed_value": {"runlevel": "HighestAvailable"}},
        ],
    }]})

    titles = [finding.title for finding in findings]
    assert "GPO permits reversible password storage" in titles
    assert "GPO grants a sensitive user right to a broad principal" in titles
    assert "GPO adds a broad principal to a privileged local group" in titles
    assert "GPO disables User Account Control" in titles
    assert "GPO enables WDigest credential caching" in titles
    assert "GPO permits legacy LAN Manager authentication" in titles
    assert "GPO configures a startup, shutdown, logon, or logoff script" in titles
    assert "GPO configures a scheduled task for highest privilege" in titles
    assert len([finding for finding in findings if finding.title.startswith(("GPO disables", "GPO enables", "GPO permits legacy"))]) == 3


def test_cancellation_during_gpo_collection_preserves_partial_coverage() -> None:
    connection = MagicMock()
    connection.settings.server = "dc01.example.local"
    connection.settings.domain = "EXAMPLE"
    connection.get_base_dn.return_value = "DC=example,DC=local"
    connection.connection.server.info.server_name = "DC01"
    connection.connection.server.info.other = {}
    connection.connection.extend.standard.paged_search.return_value = []
    cancellation = Event()

    def cancel_content(gpos, event):
        gpos.append({"objectGUID": GUID, "assessment_status": "Partially assessed"})
        event.set()

    from unittest.mock import patch
    with patch("core.scanner.assess_gpo_contents", side_effect=cancel_content):
        with pytest.raises(AssessmentCancelled) as cancelled:
            AssessmentScanner(connection).run_assessment(cancellation_event=cancellation)

    partial = cancelled.value.partial_data
    assert partial["gpos"][0]["assessment_status"] == "Partially assessed"
    assert partial["in_progress_category"] == "gpos"