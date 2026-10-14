from threading import Event
from unittest.mock import MagicMock, patch

import pytest

from core.scanner import AssessmentCancelled, AssessmentScanner


def test_run_assessment_collects_directory_inventory() -> None:
    connection = MagicMock()
    connection.settings.server = "dc01.example.local"
    connection.settings.domain = "EXAMPLE"
    connection.get_base_dn.return_value = "DC=example,DC=local"
    connection.connection.server.info.server_name = "DC01"
    connection.connection.extend.standard.paged_search.return_value = [
        {
            "type": "searchResEntry",
            "dn": "CN=Alice,DC=example,DC=local",
            "attributes": {"sAMAccountName": "alice"},
        },
        {"type": "searchResDone"},
    ]
    progress: list[tuple[int, str]] = []

    from unittest.mock import patch
    with (
        patch("core.scanner.discover_ous", return_value={"ous": [], "ou_discovery_status": "Completed", "ou_acl_status": "Completed"}),
        patch("core.scanner.discover_trusts", return_value={"trusts": [], "trust_discovery_status": "Completed"}),
        patch("core.scanner.assess_protocols", return_value={"protocols": [], "protocol_assessment_status": "Completed"}),
    ):
        result = AssessmentScanner(connection).run_assessment(
            lambda value, message: progress.append((value, message))
        )

    assert result["base_dn"] == "DC=example,DC=local"
    assert result["server_name"] == "DC01"
    assert result["users"] == [
        {"dn": "CN=Alice,DC=example,DC=local", "sAMAccountName": "alice"}
    ]
    assert result["domain_controllers"] == result["users"]
    assert connection.connection.extend.standard.paged_search.call_count == 7
    searches = connection.connection.extend.standard.paged_search.call_args_list
    assert "objectSid" in searches[0].kwargs["attributes"]
    assert "memberOf" in searches[0].kwargs["attributes"]
    assert "primaryGroupID" in searches[0].kwargs["attributes"]
    assert "member" in searches[1].kwargs["attributes"]
    assert "objectSid" in searches[1].kwargs["attributes"]
    assert searches[5].kwargs["search_filter"] == "(objectClass=groupPolicyContainer)"
    assert "gPCFileSysPath" in searches[5].kwargs["attributes"]
    assert progress[-1] == (100, "Assessment complete")


def test_scanner_integrates_ou_trust_and_protocol_coverage() -> None:
    connection = MagicMock()
    connection.settings.server = "dc.example.test"
    connection.settings.domain = "EXAMPLE"
    connection.settings.use_ssl = False
    connection.settings.effective_port = 389
    connection.get_base_dn.return_value = "DC=example,DC=test"
    connection.connection.server.info.server_name = "DC"
    connection.connection.server.info.other = {}
    connection.connection.server.host = "192.0.2.10"
    connection.connection.extend.standard.paged_search.return_value = []
    progress: list[tuple[int, str]] = []
    with (
        patch("core.scanner.assess_gpo_contents"),
        patch("core.scanner.discover_ous", return_value={
            "ous": [{"distinguishedName": "OU=Servers,DC=example,DC=test"}],
            "ou_discovery_status": "Completed", "ou_acl_status": "Partially assessed",
        }) as discover_ous,
        patch("core.scanner.discover_trusts", return_value={
            "trusts": [], "trust_discovery_status": "Completed",
        }) as discover_trusts,
        patch("core.scanner.assess_protocols", return_value={
            "protocols": [{"check": "LDAP signing requirement", "status": "Unknown"}],
            "protocol_assessment_status": "Completed",
        }) as assess_protocols,
    ):
        result = AssessmentScanner(connection).run_assessment(
            lambda value, message: progress.append((value, message))
        )

    assert result["ou_acl_status"] == "Partially assessed"
    assert result["trust_discovery_status"] == "Completed"
    assert result["protocol_assessment_status"] == "Completed"
    assert {"ous", "trusts", "protocols"}.issubset(result["completed_categories"])
    assert discover_ous.call_args.kwargs["inventories"]["users"] == []
    assert discover_trusts.call_args.args[2] == "EXAMPLE"
    assert assess_protocols.call_args.kwargs["resolved_ip"] == "192.0.2.10"
    assert any("Organizational Units" in message for _value, message in progress)
    assert all(value < 100 for value, _message in progress[:-1])


def test_cancel_during_protocol_assessment_preserves_partial_protocol_records() -> None:
    connection = MagicMock()
    connection.settings.server = "dc.example.test"
    connection.settings.domain = "EXAMPLE"
    connection.settings.use_ssl = False
    connection.settings.effective_port = 389
    connection.get_base_dn.return_value = "DC=example,DC=test"
    connection.connection.server.info.server_name = "DC"
    connection.connection.server.info.other = {}
    connection.connection.server.host = "192.0.2.10"
    connection.connection.extend.standard.paged_search.return_value = []
    cancellation = Event()

    def cancel_after_check(**_kwargs):
        cancellation.set()
        return {
            "protocols": [{"check": "LDAP signing requirement", "status": "Unknown"}],
            "protocol_assessment_status": "Partial",
        }

    with (
        patch("core.scanner.assess_gpo_contents"),
        patch("core.scanner.discover_ous", return_value={"ous": [], "ou_discovery_status": "Completed", "ou_acl_status": "Completed"}),
        patch("core.scanner.discover_trusts", return_value={"trusts": [], "trust_discovery_status": "Completed"}),
        patch("core.scanner.assess_protocols", side_effect=cancel_after_check),
    ):
        with pytest.raises(AssessmentCancelled) as cancelled:
            AssessmentScanner(connection).run_assessment(cancellation_event=cancellation)

    assert cancelled.value.partial_data["protocols"][0]["status"] == "Unknown"
    assert cancelled.value.partial_data["in_progress_category"] == "protocols"


def test_cancellation_during_paged_search_preserves_only_partial_records() -> None:
    connection = MagicMock()
    connection.settings.server = "dc01.example.local"
    connection.settings.domain = "EXAMPLE"
    connection.get_base_dn.return_value = "DC=example,DC=local"
    connection.connection.server.info.server_name = "DC01"
    cancellation = Event()
    progress: list[tuple[int, str]] = []

    def streamed_entries():
        yield {
            "type": "searchResEntry",
            "dn": "CN=Alice,DC=example,DC=local",
            "attributes": {"sAMAccountName": "alice"},
        }
        cancellation.set()
        yield {
            "type": "searchResEntry",
            "dn": "CN=Bob,DC=example,DC=local",
            "attributes": {"sAMAccountName": "bob"},
        }

    connection.connection.extend.standard.paged_search.return_value = streamed_entries()
    scanner = AssessmentScanner(connection)

    with pytest.raises(AssessmentCancelled) as cancelled:
        scanner.run_assessment(
            lambda value, message: progress.append((value, message)),
            cancellation,
        )

    partial = cancelled.value.partial_data
    assert partial["users"] == [{"dn": "CN=Alice,DC=example,DC=local", "sAMAccountName": "alice"}]
    assert partial["completed_categories"] == []
    assert partial["in_progress_category"] == "users"
    assert all(value < 100 for value, _ in progress)
    assert connection.connection.extend.standard.paged_search.call_count == 1


@pytest.mark.parametrize(
    ("label", "expected_searches"),
    (("Groups", 1), ("Computers", 2), ("Domain controllers", 3), ("SPNs", 4)),
)
def test_cancellation_checkpoints_prevent_later_category_searches(
    label: str, expected_searches: int
) -> None:
    connection = MagicMock()
    connection.settings.server = "dc01.example.local"
    connection.settings.domain = "EXAMPLE"
    connection.get_base_dn.return_value = "DC=example,DC=local"
    connection.connection.server.info.server_name = "DC01"
    connection.connection.extend.standard.paged_search.return_value = [{
        "type": "searchResEntry",
        "dn": "CN=Entry,DC=example,DC=local",
        "attributes": {"sAMAccountName": "entry"},
    }]
    cancellation = Event()
    progress_events: list[tuple[int, str]] = []

    def progress(value: int, message: str) -> None:
        progress_events.append((value, message))
        if message == f"Enumerating {label}":
            cancellation.set()

    with pytest.raises(AssessmentCancelled) as cancelled:
        AssessmentScanner(connection).run_assessment(progress, cancellation)

    assert connection.connection.extend.standard.paged_search.call_count == expected_searches
    assert cancelled.value.partial_data["in_progress_category"]
    assert all(value < 100 for value, _message in progress_events)