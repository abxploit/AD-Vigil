"""Read-only discovery and conservative interpretation of AD trust objects."""

import logging
from typing import Any

from ldap3 import SUBTREE

logger = logging.getLogger(__name__)

TRUST_ATTRIBUTES = [
    "trustPartner", "flatName", "trustDirection", "trustType", "trustAttributes",
    "securityIdentifier", "whenCreated", "whenChanged",
]
TRUST_DIRECTION = {0: "disabled", 1: "inbound", 2: "outbound", 3: "bidirectional"}
TRUST_TYPE = {1: "downlevel/external", 2: "uplevel/Active Directory", 3: "MIT", 4: "DCE"}
TRUST_FLAGS = {
    0x00000001: "non_transitive",
    0x00000002: "uplevel_only",
    0x00000004: "quarantined_domain_sid_filtering",
    0x00000008: "forest_transitive",
    0x00000010: "cross_organization_selective_authentication",
    0x00000020: "within_forest",
    0x00000040: "treat_as_external",
    0x00000080: "uses_rc4_encryption",
    0x00000200: "cross_organization_no_tgt_delegation",
    0x00000400: "pim_trust",
}
KNOWN_TRUST_FLAGS = sum(TRUST_FLAGS)


def _first(attrs: dict[str, Any], key: str, default: Any = None) -> Any:
    value = attrs.get(key, default)
    if isinstance(value, (list, tuple)):
        return value[0] if value else default
    return default if value is None else value


def _integer(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return None


def decode_trust(record: dict[str, Any], source_domain: str) -> dict[str, Any]:
    attrs = record.get("source_attributes", record)
    direction_value = _integer(_first(attrs, "trustDirection"))
    type_value = _integer(_first(attrs, "trustType"))
    attribute_value = _integer(_first(attrs, "trustAttributes"))
    flags = (attribute_value & 0xFFFFFFFF) if attribute_value is not None else 0
    trust_type = TRUST_TYPE.get(type_value, "unknown" if type_value is not None else "not returned")
    is_external = type_value == 1 or bool(flags & 0x40)
    transitivity: bool | None
    if attribute_value is None:
        transitivity = None
    elif flags & 0x1:
        transitivity = False
    elif flags & (0x8 | 0x20):
        transitivity = True
    else:
        transitivity = None
    if is_external and attribute_value is not None:
        sid_filtering: bool | None = bool(flags & 0x4)
    else:
        sid_filtering = None
    selective_auth = (
        True if attribute_value is not None and flags & 0x10 else None
    )
    return {
        "trustPartner": _first(attrs, "trustPartner", ""),
        "flatName": _first(attrs, "flatName", ""),
        "source_domain": source_domain,
        "target_domain": _first(attrs, "trustPartner", ""),
        "trustDirection": direction_value,
        "direction": TRUST_DIRECTION.get(direction_value, "unknown" if direction_value is not None else "not returned"),
        "trustType": type_value,
        "type": trust_type,
        "trustAttributes": attribute_value,
        "attribute_flags": [label for bit, label in TRUST_FLAGS.items() if flags & bit],
        "unknown_attribute_bits": flags & ~KNOWN_TRUST_FLAGS if attribute_value is not None else None,
        "transitive": transitivity,
        "sid_filtering_enabled": sid_filtering,
        "selective_authentication_indicated": selective_auth,
        "is_external": is_external if type_value is not None or attribute_value is not None else None,
        "partner_status": "Not inspected",
        "collection_status": "Discovered",
        "source_attributes": attrs,
        "limitations": (
            "Trust discovery does not establish partner reachability, authentication, "
            "effective access, or trust-secret state. Partner domains were not queried."
        ),
    }


def discover_trusts(
    connection: Any,
    base_dn: str,
    source_domain: str,
    cancellation_event: Any = None,
    max_trusts: int = 1000,
) -> dict[str, Any]:
    if max_trusts < 1:
        raise ValueError("max_trusts must be positive")
    search_base = f"CN=System,{base_dn}"
    trusts: list[dict[str, Any]] = []
    limited = False
    try:
        entries = connection.connection.extend.standard.paged_search(
            search_base=search_base,
            search_filter="(objectClass=trustedDomain)",
            search_scope=SUBTREE,
            attributes=TRUST_ATTRIBUTES,
            paged_size=250,
            generator=True,
        )
        for entry in entries:
            if cancellation_event is not None and cancellation_event.is_set():
                break
            if entry.get("type") != "searchResEntry":
                continue
            if len(trusts) >= max_trusts:
                limited = True
                break
            attrs = dict(entry.get("attributes") or {})
            record = decode_trust({"source_attributes": attrs}, source_domain)
            record["distinguishedName"] = entry.get("dn", "")
            record["source_attributes"] = attrs
            trusts.append(record)
    except Exception as exc:
        logger.warning("Trust discovery failed", extra={"error_type": type(exc).__name__})
        return {"trusts": trusts, "trust_discovery_status": "Failed", "trust_collection_error": type(exc).__name__}
    if cancellation_event is not None and cancellation_event.is_set():
        status = "Partial"
    else:
        status = "Limit reached" if limited else "Completed"
    return {"trusts": trusts, "trust_discovery_status": status}
