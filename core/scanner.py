"""Assessment orchestration contracts."""

import logging
from collections.abc import Callable, Iterator
from threading import Event
from typing import Any

from ldap3 import SUBTREE

from core.connection import ADConnection
from core.gpo_assessment import assess_gpo_contents, discover_gpos
from core.ou_assessment import discover_ous
from core.trust_assessment import discover_trusts
from core.protocol_assessment import assess_protocols

logger = logging.getLogger(__name__)
ProgressCallback = Callable[[int, str], None]


class AssessmentCancelled(Exception):
    """Signal cooperative cancellation and retain safely collected inventory."""

    def __init__(self, partial_data: dict[str, Any]) -> None:
        super().__init__("Assessment cancelled")
        self.partial_data = partial_data


class AssessmentScanner:
    """Run safe, read-only assessment operations in a controlled sequence."""

    def __init__(self, connection: ADConnection) -> None:
        self.connection = connection
        self.partial_data: dict[str, Any] = {}

    def discover_domain(self, progress: ProgressCallback | None = None) -> dict[str, str]:
        """Read basic directory metadata without modifying the directory."""
        if progress:
            progress(10, "Reading directory metadata")
        info = self.connection.connection.server.info
        result = {
            "server": self.connection.settings.server,
            "domain": self.connection.settings.domain,
            "server_name": str(getattr(info, "server_name", "Unknown")),
        }
        if progress:
            progress(100, "Domain discovery complete")
        logger.info("Domain discovery completed", extra={"domain": result["domain"]})
        return result

    def run_assessment(
        self,
        progress: ProgressCallback | None = None,
        cancellation_event: Event | None = None,
    ) -> dict[str, Any]:
        """Collect a read-only inventory of common Active Directory objects."""
        server_info = self.connection.connection.server.info
        result: dict[str, Any] = {
            "server": self.connection.settings.server,
            "server_name": str(getattr(server_info, "server_name", "Unknown")),
            "domain": self.connection.settings.domain,
            "base_dn": "",
            "completed_categories": [],
            "in_progress_category": "",
            "gpos": [],
            "gpo_links": [],
            "gpo_discovery_status": "Not assessed",
            "gpo_content_status": "Not assessed",
            "ous": [],
            "ou_discovery_status": "Not assessed",
            "ou_acl_status": "Not assessed",
            "trusts": [],
            "trust_discovery_status": "Not assessed",
            "protocols": [],
            "protocol_assessment_status": "Not assessed",
        }
        self.partial_data = result
        self._check_cancelled(cancellation_event)
        result["base_dn"] = self.connection.get_base_dn()
        queries = (
            ("users", "Users", "(&(objectCategory=person)(objectClass=user))", [
                "sAMAccountName", "displayName", "userPrincipalName", "mail",
                "description", "userAccountControl", "lastLogonTimestamp",
                "objectSid", "memberOf", "primaryGroupID", "objectClass",
                "objectCategory", "msDS-AllowedToDelegateTo",
                "msDS-AllowedToActOnBehalfOfOtherIdentity", "pwdLastSet",
            ]),
            ("groups", "Groups", "(objectCategory=group)", [
                "sAMAccountName", "name", "description", "groupType", "member",
                "objectSid", "objectClass", "objectCategory",
            ]),
            ("computers", "Computers", "(objectCategory=computer)", [
                "sAMAccountName", "dNSHostName", "operatingSystem",
                "operatingSystemVersion", "lastLogonTimestamp", "userAccountControl",
                "objectClass", "objectCategory", "servicePrincipalName",
                "msDS-AllowedToDelegateTo", "msDS-AllowedToActOnBehalfOfOtherIdentity",
            ]),
            (
                "domain_controllers",
                "Domain controllers",
                "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
                ["sAMAccountName", "dNSHostName", "operatingSystem", "operatingSystemVersion"],
            ),
            ("spns", "SPNs", "(servicePrincipalName=*)", [
                "sAMAccountName", "dNSHostName", "servicePrincipalName",
                "userAccountControl", "objectClass", "objectCategory",
                "memberOf",
            ]),
        )

        for index, (key, label, search_filter, attributes) in enumerate(queries):
            self._check_cancelled(cancellation_event)
            result["in_progress_category"] = key
            result[key] = []
            if progress:
                progress(10 + index * 17, f"Enumerating {label}")
            self._check_cancelled(cancellation_event)
            for record in self._search(result["base_dn"], search_filter, attributes):
                self._check_cancelled(cancellation_event)
                result[key].append(record)
            result["completed_categories"].append(key)
            result["in_progress_category"] = ""
            self._check_cancelled(cancellation_event)

        result["in_progress_category"] = "gpos"
        if progress:
            progress(84, "Discovering Group Policy Objects and links")
        try:
            gpo_data = discover_gpos(self.connection, result["base_dn"], cancellation_event)
            result.update(gpo_data)
            self._check_cancelled(cancellation_event)
            if progress:
                progress(91, "Assessing readable SYSVOL policy content")
            assess_gpo_contents(result["gpos"], cancellation_event)
            self._check_cancelled(cancellation_event)
            statuses = {gpo.get("assessment_status") for gpo in result["gpos"]}
            if not result["gpos"]:
                result["gpo_content_status"] = "No GPOs discovered"
            elif statuses == {"Assessed successfully"}:
                result["gpo_content_status"] = "Assessed successfully"
            elif statuses == {"Inaccessible"}:
                result["gpo_content_status"] = "Inaccessible"
            else:
                result["gpo_content_status"] = "Partially assessed"
            result["completed_categories"].append("gpos")
        except Exception as exc:
            if cancellation_event is not None and cancellation_event.is_set():
                raise AssessmentCancelled(dict(self.partial_data)) from exc
            logger.warning("GPO assessment collection failed", extra={"error_type": type(exc).__name__})
            result["gpo_discovery_status"] = "Failed"
            result["gpo_content_status"] = "Failed"
            result["gpo_assessment_error"] = type(exc).__name__
        finally:
            result["in_progress_category"] = ""
        self._check_cancelled(cancellation_event)

        result["in_progress_category"] = "ous"
        if progress:
            progress(92, "Discovering Organizational Units and DACL evidence")
        try:
            ou_data = discover_ous(
                self.connection,
                result["base_dn"],
                inventories=result,
                cancellation_event=cancellation_event,
            )
            result.update(ou_data)
        except Exception as exc:
            logger.warning("OU assessment failed", extra={"error_type": type(exc).__name__})
            result["ou_discovery_status"] = "Failed"
            result["ou_acl_status"] = "Failed"
            result["ou_assessment_error"] = type(exc).__name__
        self._check_cancelled(cancellation_event)
        result["completed_categories"].append("ous")

        result["in_progress_category"] = "trusts"
        if progress:
            progress(95, "Discovering local domain trust relationships")
        try:
            trust_data = discover_trusts(
                self.connection,
                result["base_dn"],
                result["domain"],
                cancellation_event=cancellation_event,
            )
            result.update(trust_data)
        except Exception as exc:
            logger.warning("Trust assessment failed", extra={"error_type": type(exc).__name__})
            result["trust_discovery_status"] = "Failed"
            result["trust_assessment_error"] = type(exc).__name__
        self._check_cancelled(cancellation_event)
        result["completed_categories"].append("trusts")

        result["in_progress_category"] = "protocols"
        if progress:
            progress(98, "Checking LDAP, TLS, and SMB protocol behavior")
        try:
            server_host = str(getattr(self.connection.connection.server, "host", "") or "")
            result.update(assess_protocols(
                hostname=self.connection.settings.server,
                resolved_ip=server_host or None,
                settings=self.connection.settings,
                gpos=result.get("gpos", []),
                cancellation_event=cancellation_event,
            ))
        except Exception as exc:
            logger.warning("Protocol assessment failed", extra={"error_type": type(exc).__name__})
            result["protocol_assessment_status"] = "Failed"
            result["protocols"] = []
            result["protocol_assessment_error"] = type(exc).__name__
        self._check_cancelled(cancellation_event)
        result["completed_categories"].append("protocols")
        result["in_progress_category"] = ""

        if progress:
            progress(100, "Assessment complete")
        logger.info(
            "Directory inventory completed",
            extra={"domain": result["domain"], "object_counts": {
                key: len(result[key]) for key, *_ in queries
            }},
        )
        return result

    def _check_cancelled(self, cancellation_event: Event | None) -> None:
        if cancellation_event is not None and cancellation_event.is_set():
            raise AssessmentCancelled(dict(self.partial_data))

    def _search(
        self, base_dn: str, search_filter: str, attributes: list[str]
    ) -> Iterator[dict[str, Any]]:
        entries = self.connection.connection.extend.standard.paged_search(
            search_base=base_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=attributes,
            paged_size=500,
            generator=True,
        )
        for entry in entries:
            if entry.get("type") == "searchResEntry":
                yield {"dn": entry.get("dn", ""), **(entry.get("attributes") or {})}