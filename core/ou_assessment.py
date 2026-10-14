"""Bounded OU discovery and safe DACL evidence extraction."""

import logging
import struct
from typing import Any

from ldap3 import SUBTREE
from ldap3.protocol.microsoft import security_descriptor_control

from core.gpo_assessment import parse_gpo_links

logger = logging.getLogger(__name__)

OU_ATTRIBUTES = [
    "name", "objectGUID", "description", "whenCreated", "whenChanged", "gPLink",
    "gPOptions", "managedBy",
]
SD_FLAGS_DACL = 0x00000004
SD_CONTROL_DACL_PRESENT = 0x0004
SD_CONTROL_SELF_RELATIVE = 0x8000
ACE_INHERIT_FLAGS = {
    0x01: "object_inherit", 0x02: "container_inherit", 0x04: "no_propagate",
    0x08: "inherit_only", 0x10: "inherited",
}
RESET_PASSWORD_GUID = "00299570-246d-11d0-a768-00aa006e0529"


def _parent_dn(dn: str) -> str:
    escaped = False
    for index, character in enumerate(dn):
        if escaped:
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == ",":
            return dn[index + 1:]
    return ""


def _as_bytes(value: Any) -> bytes:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, (list, tuple)) and value:
        return _as_bytes(value[0])
    raise ValueError("Security descriptor is not binary data")


def _sid_from(data: bytes, offset: int) -> tuple[str, int]:
    if offset + 8 > len(data):
        raise ValueError("Truncated SID header")
    revision, count = data[offset], data[offset + 1]
    if count > 15:
        raise ValueError("SID has too many subauthorities")
    end = offset + 8 + count * 4
    if end > len(data):
        raise ValueError("Truncated SID subauthorities")
    authority = int.from_bytes(data[offset + 2:offset + 8], "big")
    subauthorities = [
        struct.unpack_from("<I", data, offset + 8 + index * 4)[0]
        for index in range(count)
    ]
    sid = "-".join((f"S-{revision}-{authority}", *(str(value) for value in subauthorities)))
    return sid, end


def _rights(mask: int, object_guid: str | None) -> list[str]:
    rights: list[str] = []
    for bit, label in (
        (0x10000000, "generic_all"), (0x40000000, "generic_write"),
        (0x00040000, "write_dacl"), (0x00080000, "write_owner"),
        (0x00000001, "create_child"), (0x00000002, "delete_child"),
        (0x00000020, "write_property"), (0x00000040, "delete_tree"),
        (0x00000100, "control_access"),
    ):
        if mask & bit:
            rights.append(label)
    if object_guid and object_guid.casefold() == RESET_PASSWORD_GUID:
        rights.append("reset_password")
    return rights


def parse_security_descriptor(value: Any) -> dict[str, Any]:
    """Parse owner-independent DACL evidence from a self-relative descriptor."""
    data = _as_bytes(value)
    if len(data) < 20:
        raise ValueError("Security descriptor header is truncated")
    revision = data[0]
    control = struct.unpack_from("<H", data, 2)[0]
    if not control & SD_CONTROL_SELF_RELATIVE:
        raise ValueError("Security descriptor is not self-relative")
    dacl_offset = struct.unpack_from("<I", data, 16)[0]
    if not control & SD_CONTROL_DACL_PRESENT:
        return {"revision": revision, "dacl_state": "Null DACL", "aces": []}
    if dacl_offset == 0:
        return {"revision": revision, "dacl_state": "Null DACL", "aces": []}
    if dacl_offset + 8 > len(data):
        raise ValueError("DACL header is truncated")
    acl_size = struct.unpack_from("<H", data, dacl_offset + 2)[0]
    ace_count = struct.unpack_from("<H", data, dacl_offset + 4)[0]
    acl_end = dacl_offset + acl_size
    if acl_size < 8 or acl_end > len(data):
        raise ValueError("DACL size is invalid")
    aces: list[dict[str, Any]] = []
    offset = dacl_offset + 8
    for _ in range(ace_count):
        if offset + 4 > acl_end:
            raise ValueError("ACE header is truncated")
        ace_type, ace_flags, ace_size = struct.unpack_from("<BBH", data, offset)
        if ace_size < 4 or offset + ace_size > acl_end:
            raise ValueError("ACE size is invalid")
        ace_data = data[offset:offset + ace_size]
        ace_name = {0x00: "allow", 0x01: "deny", 0x05: "allow_object", 0x06: "deny_object"}.get(
            ace_type, f"unsupported_{ace_type}"
        )
        ace: dict[str, Any] = {
            "type": ace_name,
            "flags": ace_flags,
            "inheritance": [label for bit, label in ACE_INHERIT_FLAGS.items() if ace_flags & bit],
            "inherited": bool(ace_flags & 0x10),
        }
        if ace_type in {0x00, 0x01} and ace_size >= 8:
            mask = struct.unpack_from("<I", ace_data, 4)[0]
            sid, _end = _sid_from(ace_data, 8)
            ace.update({"mask": mask, "sid": sid, "rights": _rights(mask, None)})
        elif ace_type in {0x05, 0x06} and ace_size >= 12:
            mask = struct.unpack_from("<I", ace_data, 4)[0]
            object_flags = struct.unpack_from("<I", ace_data, 8)[0]
            sid_offset = 12
            object_guid = None
            if object_flags & 0x1:
                if sid_offset + 16 > ace_size:
                    raise ValueError("Object ACE GUID is truncated")
                object_guid = _guid_le(ace_data[sid_offset:sid_offset + 16])
                sid_offset += 16
            if object_flags & 0x2:
                if sid_offset + 16 > ace_size:
                    raise ValueError("Inherited object ACE GUID is truncated")
                ace["inherited_object_guid"] = _guid_le(ace_data[sid_offset:sid_offset + 16])
                sid_offset += 16
            sid, _end = _sid_from(ace_data, sid_offset)
            ace.update({
                "mask": mask, "sid": sid, "object_guid": object_guid,
                "rights": _rights(mask, object_guid),
            })
        aces.append(ace)
        offset += ace_size
    return {
        "revision": revision,
        "dacl_state": "Empty DACL" if ace_count == 0 else "Present",
        "aces": aces,
    }


def _guid_le(value: bytes) -> str:
    import uuid
    return str(uuid.UUID(bytes_le=value))


def _broad_sid(sid: str) -> bool:
    normalized = sid.casefold()
    return normalized in {"s-1-1-0", "s-1-5-11", "s-1-5-32-545"} or normalized.endswith("-513")


def discover_ous(
    connection: Any,
    base_dn: str,
    inventories: dict[str, Any] | None = None,
    cancellation_event: Any = None,
    max_ous: int = 3000,
) -> dict[str, Any]:
    """Discover OUs, derived hierarchy, inventory associations, and DACL coverage."""
    if max_ous < 1:
        raise ValueError("max_ous must be positive")
    inventories = inventories or {}
    gpos = inventories.get("gpos", [])
    gpo_by_dn = {
        str(gpo.get("distinguishedName", "")).casefold(): gpo
        for gpo in gpos if gpo.get("distinguishedName")
    }
    gpo_by_guid = {
        str(gpo.get("objectGUID", "")).strip("{}").casefold(): gpo
        for gpo in gpos if gpo.get("objectGUID")
    }
    def collect(request_descriptor: bool) -> tuple[list[dict[str, Any]], bool]:
        records: list[dict[str, Any]] = []
        limited_records = False
        attributes = OU_ATTRIBUTES + (["nTSecurityDescriptor"] if request_descriptor else [])
        kwargs: dict[str, Any] = {
            "search_base": base_dn,
            "search_filter": "(objectClass=organizationalUnit)",
            "search_scope": SUBTREE,
            "attributes": attributes,
            "paged_size": 500,
            "generator": True,
        }
        if request_descriptor:
            kwargs["controls"] = security_descriptor_control(criticality=False, sdflags=SD_FLAGS_DACL)
        entries = connection.connection.extend.standard.paged_search(**kwargs)
        for entry in entries:
            if cancellation_event is not None and cancellation_event.is_set():
                break
            if entry.get("type") != "searchResEntry":
                continue
            if len(records) >= max_ous:
                limited_records = True
                break
            attrs = dict(entry.get("attributes") or {})
            dn = str(entry.get("dn") or attrs.get("distinguishedName") or "")
            direct_links = parse_gpo_links(_first(attrs, "gPLink", ""))
            for link in direct_links:
                linked_gpo = gpo_by_dn.get(str(link.get("gpo_dn", "")).casefold()) or gpo_by_guid.get(
                    str(link.get("gpo_guid", "")).casefold()
                )
                link["gpo_name"] = (
                    _first(linked_gpo, "displayName", _first(linked_gpo, "name", "Not resolved"))
                    if linked_gpo else "Not resolved"
                )
            record = {
                "distinguishedName": dn,
                "name": _first(attrs, "name", dn),
                "objectGUID": _first(attrs, "objectGUID", None),
                "description": _first(attrs, "description", None),
                "whenCreated": _first(attrs, "whenCreated", None),
                "whenChanged": _first(attrs, "whenChanged", None),
                "gPLink": _first(attrs, "gPLink", None),
                "gPOptions": _first(attrs, "gPOptions", None),
                "managedBy": _first(attrs, "managedBy", None),
                "direct_gpo_links": direct_links,
                "source_attributes": attrs,
                "security_descriptor_status": "Not returned" if request_descriptor else "Inaccessible",
                "security_descriptor": None,
                "contained_counts": {},
                "privileged_objects": [],
                "child_ous": [],
            }
            if request_descriptor:
                raw_descriptor = attrs.get("nTSecurityDescriptor")
                if raw_descriptor not in (None, [], ()):
                    try:
                        record["security_descriptor"] = parse_security_descriptor(raw_descriptor)
                        record["security_descriptor_status"] = "Parsed"
                    except (ValueError, struct.error) as exc:
                        record["security_descriptor_status"] = "Parse failed"
                        record["security_descriptor_error"] = type(exc).__name__
            records.append(record)
        return records, limited_records

    acl_request_failed = False
    try:
        ous, limited = collect(request_descriptor=True)
    except Exception as exc:
        logger.info("OU DACL control unavailable; retrying metadata discovery", extra={"error_type": type(exc).__name__})
        acl_request_failed = True
        try:
            ous, limited = collect(request_descriptor=False)
        except Exception as fallback_exc:
            logger.warning("OU LDAP discovery failed", extra={"error_type": type(fallback_exc).__name__})
            return {"ous": [], "ou_discovery_status": "Failed", "ou_acl_status": "Failed"}

    by_dn = {str(ou["distinguishedName"]).casefold(): ou for ou in ous if ou["distinguishedName"]}
    for ou in ous:
        parent = _parent_dn(str(ou["distinguishedName"]))
        ou["parent_ou_dn"] = parent if parent.casefold() in by_dn else ""
        ou["domain_dn"] = base_dn
        if ou["parent_ou_dn"]:
            by_dn[ou["parent_ou_dn"].casefold()]["child_ous"].append(ou["distinguishedName"])

    users = inventories.get("users", [])
    groups = inventories.get("groups", [])
    computers = inventories.get("computers", [])
    controllers = {str(item.get("dn", "")).casefold() for item in inventories.get("domain_controllers", [])}
    privileged_dns = {
        str(group.get("dn", "")).casefold()
        for group in groups
        if any(token in str(group.get("name", "")).casefold() for token in (
            "domain admins", "enterprise admins", "schema admins", "administrators",
        ))
    }
    records = [("users", item) for item in users] + [("groups", item) for item in groups] + [("computers", item) for item in computers]
    for ou in ous:
        ou_dn = str(ou["distinguishedName"]).casefold()
        for category, record in records:
            dn = str(record.get("dn", ""))
            if _parent_dn(dn).casefold() == ou_dn:
                ou["contained_counts"][category] = ou["contained_counts"].get(category, 0) + 1
            if dn.casefold() in controllers and _within(dn, str(ou["distinguishedName"])):
                ou["privileged_objects"].append({"dn": dn, "type": "Domain Controller"})
            if category == "users" and _within(dn, str(ou["distinguishedName"])):
                member_of = record.get("memberOf", [])
                member_of = member_of if isinstance(member_of, (list, tuple)) else [member_of]
                if any(str(group).casefold() in privileged_dns for group in member_of):
                    ou["privileged_objects"].append({"dn": dn, "type": "Privileged user"})
        if any(_within(str(group.get("dn", "")), str(ou["distinguishedName"])) for group in groups if str(group.get("dn", "")).casefold() in privileged_dns):
            ou["privileged_objects"].append({"dn": "Contained privileged group", "type": "Privileged group"})

    acl_statuses = {str(ou.get("security_descriptor_status", "Not returned")) for ou in ous}

    if cancellation_event is not None and cancellation_event.is_set():
        discovery_status = "Partial"
    else:
        discovery_status = "Limit reached" if limited else "Completed"
    if acl_request_failed and ous:
        acl_status = "Inaccessible"
    elif not acl_statuses:
        acl_status = "Not assessed"
    elif limited or (cancellation_event is not None and cancellation_event.is_set()):
        acl_status = "Partially assessed"
    else:
        acl_status = "Completed" if acl_statuses == {"Parsed"} else "Partially assessed"
    return {"ous": ous, "ou_discovery_status": discovery_status, "ou_acl_status": acl_status}


def _first(record: dict[str, Any], key: str, default: Any = "") -> Any:
    value = record.get(key, default)
    if isinstance(value, (list, tuple)):
        return value[0] if value else default
    return default if value is None else value


def _within(object_dn: str, container_dn: str) -> bool:
    return bool(object_dn and container_dn and object_dn.casefold().endswith("," + container_dn.casefold()))
