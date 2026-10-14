"""Read-only Group Policy discovery, link parsing, and bounded content review."""

import configparser
import logging
import multiprocessing
import os
import re
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

GPO_ATTRIBUTES = [
    "displayName", "name", "distinguishedName", "objectGUID", "gPCFileSysPath",
    "gPCFunctionalityVersion", "flags", "versionNumber",
]
LINK_ATTRIBUTES = ["distinguishedName", "name", "gPLink", "gPOptions", "objectClass"]
MAX_POLICY_FILES = 80
MAX_FILE_BYTES = 1_048_576
MAX_GPO_SECONDS = 5.0
_LINK_PATTERN = re.compile(r"\[LDAP://([^;\]]+);(\d+)\]", re.IGNORECASE)
_GUID_PATTERN = re.compile(r"\{([0-9a-f-]{36})\}", re.IGNORECASE)


def parse_gpo_links(value: Any) -> list[dict[str, Any]]:
    """Parse gPLink segments in their stored order without inferring effective scope."""
    links: list[dict[str, Any]] = []
    for order, match in enumerate(_LINK_PATTERN.finditer(str(value or "")), 1):
        target_dn, raw_flags = match.groups()
        flags = int(raw_flags)
        guid_match = _GUID_PATTERN.search(target_dn)
        links.append({
            "gpo_dn": target_dn,
            "gpo_guid": guid_match.group(1).lower() if guid_match else "",
            "link_order": order,
            "enabled": not bool(flags & 0x1),
            "enforced": bool(flags & 0x2),
            "raw_options": flags,
        })
    return links


def _first(record: dict[str, Any], key: str, default: Any = "") -> Any:
    value = record.get(key, default)
    if isinstance(value, (list, tuple)):
        return value[0] if value else default
    return default if value is None else value


def _guid(record: dict[str, Any]) -> str:
    value = _first(record, "objectGUID")
    if isinstance(value, bytes):
        try:
            import uuid
            return str(uuid.UUID(bytes_le=value)).lower()
        except (ValueError, AttributeError):
            return ""
    text = str(value).strip().strip("{}").lower()
    return text if _GUID_PATTERN.fullmatch("{" + text + "}") else ""


def discover_gpos(connection: Any, base_dn: str, cancellation_event: Any = None) -> dict[str, Any]:
    """Discover GPOs and domain/OU/site links through LDAP."""
    gpos: list[dict[str, Any]] = []
    for entry in connection.connection.extend.standard.paged_search(
        search_base=base_dn,
        search_filter="(objectClass=groupPolicyContainer)",
        search_scope=2,
        attributes=GPO_ATTRIBUTES,
        paged_size=250,
        generator=True,
    ):
        if cancellation_event is not None and cancellation_event.is_set():
            break
        if entry.get("type") != "searchResEntry":
            continue
        attrs = dict(entry.get("attributes") or {})
        gpos.append({
            "displayName": _first(attrs, "displayName"),
            "name": _first(attrs, "name"),
            "distinguishedName": entry.get("dn", _first(attrs, "distinguishedName")),
            "objectGUID": _guid(attrs),
            "gPCFileSysPath": _first(attrs, "gPCFileSysPath"),
            "gPCFunctionalityVersion": _first(attrs, "gPCFunctionalityVersion", None),
            "flags": _first(attrs, "flags", None),
            "versionNumber": _first(attrs, "versionNumber", None),
            "links": [],
            "linked_objects": [],
            "assessment_status": "Discovered",
            "content_status": "Not assessed",
            "settings": [],
            "source_attributes": attrs,
        })

    containers: list[dict[str, Any]] = []
    for entry in connection.connection.extend.standard.paged_search(
        search_base=base_dn,
        search_filter="(|(objectClass=domainDNS)(objectClass=organizationalUnit))",
        search_scope=2,
        attributes=LINK_ATTRIBUTES,
        paged_size=250,
        generator=True,
    ):
        if cancellation_event is not None and cancellation_event.is_set():
            break
        if entry.get("type") == "searchResEntry":
            containers.append({"dn": entry.get("dn", ""), **(entry.get("attributes") or {})})

    rootdse = getattr(connection.connection.server, "info", None)
    root_other = getattr(rootdse, "other", {}) or {}
    config_dn = _first(root_other, "configurationNamingContext", "") if isinstance(root_other, dict) else ""
    site_status = "Not available"
    if config_dn and not (cancellation_event is not None and cancellation_event.is_set()):
        site_base = f"CN=Sites,{config_dn}"
        try:
            for entry in connection.connection.extend.standard.paged_search(
                search_base=site_base,
                search_filter="(objectClass=site)",
                search_scope=2,
                attributes=LINK_ATTRIBUTES,
                paged_size=250,
                generator=True,
            ):
                if cancellation_event is not None and cancellation_event.is_set():
                    break
                if entry.get("type") == "searchResEntry":
                    containers.append({"dn": entry.get("dn", ""), **(entry.get("attributes") or {})})
            site_status = "Completed"
        except Exception as exc:
            site_status = "Failed"
            logger.info("GPO site-link discovery unavailable", extra={"error_type": type(exc).__name__})
    elif not config_dn:
        site_status = "Unavailable: configuration naming context not provided"

    by_dn = {str(gpo["distinguishedName"]).casefold(): gpo for gpo in gpos if gpo["distinguishedName"]}
    by_guid = {gpo["objectGUID"].casefold(): gpo for gpo in gpos if gpo["objectGUID"]}
    all_links: list[dict[str, Any]] = []
    for container in containers:
        dn = str(container.get("dn") or _first(container, "distinguishedName"))
        options = _first(container, "gPOptions", None)
        try:
            block_inheritance = bool(int(options) & 0x1)
        except (TypeError, ValueError):
            block_inheritance = None
        for link in parse_gpo_links(_first(container, "gPLink")):
            target = by_dn.get(link["gpo_dn"].casefold()) or by_guid.get(link["gpo_guid"].casefold())
            resolved = {
                **link,
                "linked_object_dn": dn,
                "linked_object_name": _first(container, "name", dn),
                "linked_object_type": _container_type(container),
                "block_inheritance": block_inheritance,
            }
            all_links.append(resolved)
            if target is not None:
                target["links"].append(resolved)
                target["linked_objects"].append(dn)

    discovery_status = "Completed" if site_status == "Completed" else "Partially assessed"
    return {
        "gpos": gpos,
        "gpo_links": all_links,
        "gpo_discovery_status": discovery_status,
        "gpo_site_link_status": site_status,
    }


def _container_type(record: dict[str, Any]) -> str:
    classes = record.get("objectClass", [])
    classes = classes if isinstance(classes, (list, tuple)) else [classes]
    normalized = {str(item).casefold() for item in classes}
    if "site" in normalized:
        return "Site"
    if "organizationalunit" in normalized:
        return "Organizational Unit"
    if "domaindns" in normalized:
        return "Domain"
    return "Directory object"


def _parse_inf(path: Path, gpo_guid: str) -> list[dict[str, Any]]:
    settings: list[dict[str, Any]] = []
    section = ""
    for line in path.read_text(encoding="utf-8-sig", errors="replace").splitlines():
        clean = line.strip()
        if not clean or clean.startswith((";", "#")):
            continue
        if clean.startswith("[") and clean.endswith("]"):
            section = clean[1:-1].strip()
        elif "=" in clean:
            key, value = clean.split("=", 1)
            if section.casefold() == "registry values":
                raw_value = value.strip().split(",")
                is_credential_key = any(
                    token in key.casefold() for token in ("password", "credential", "secret")
                )
                settings.append({
                    "gpo_guid": gpo_guid,
                    "setting": "Registry:Properties",
                    "observed_value": {
                        "key": key.strip(),
                        "value": (
                            "Present (value withheld)" if is_credential_key
                            else raw_value[-1].strip().strip('"') if raw_value else ""
                        ),
                    },
                    "section": section,
                    "source_file": path.name,
                    "format": "INF",
                    "credential_exposure": is_credential_key,
                    "credential_exposure_kind": "registry" if is_credential_key else "",
                })
                continue
            settings.append({
                "gpo_guid": gpo_guid, "setting": key.strip(), "observed_value": value.strip().strip('"'),
                "section": section, "source_file": str(path.name), "format": "INF",
            })
    return settings


def _parse_xml(path: Path, gpo_guid: str) -> list[dict[str, Any]]:
    root = ET.parse(path).getroot()
    settings: list[dict[str, Any]] = []
    for node in root.iter():
        attrs = {key.rsplit("}", 1)[-1].casefold(): value for key, value in node.attrib.items()}
        tag = node.tag.rsplit("}", 1)[-1]
        lower_text = (node.text or "").strip()
        if "cpassword" in attrs:
            settings.append({
                "gpo_guid": gpo_guid, "setting": "Group Policy Preferences cpassword",
                "observed_value": "Present (value withheld)", "section": "Credentials",
                "source_file": path.name, "format": "XML", "credential_exposure": True,
            })
        if tag.casefold() in {
            "user", "group", "member", "registry", "properties", "task", "scheduledtask",
            "taskitem", "script",
        }:
            safe_attrs: dict[str, str] = {}
            identity_text = " ".join(attrs.get(key, "") for key in ("key", "keyname", "name", "valuename"))
            credential_key = any(
                token in identity_text.casefold() for token in ("password", "credential", "secret")
            )
            for key, item in attrs.items():
                if key in {"cpassword", "password"}:
                    continue
                if key not in {
                    "name", "uid", "key", "keyname", "valuename", "value", "type", "action",
                    "runlevel", "enabled", "changed", "removeallgroups", "deleteallusers",
                }:
                    continue
                if key == "value" and any(token in identity_text.casefold() for token in ("password", "credential", "secret")):
                    continue
                safe_attrs[key] = item
            if safe_attrs:
                parent_group = ""
                if tag.casefold() == "member":
                    parent_map = {child: parent for parent in root.iter() for child in parent}
                    parent = parent_map.get(node)
                    while parent is not None:
                        if parent.tag.rsplit("}", 1)[-1].casefold() == "group":
                            parent_group = next((
                                item for key, item in parent.attrib.items()
                                if key.rsplit("}", 1)[-1].casefold() == "name"
                            ), "")
                            break
                        parent = parent_map.get(parent)
                observed: Any = safe_attrs
                if tag.casefold() == "member":
                    observed = {
                        "target_group": parent_group,
                        "member": safe_attrs.get("name", "Not available"),
                        "action": safe_attrs.get("action", "Not available"),
                    }
                settings.append({
                    "gpo_guid": gpo_guid, "setting": f"{path.stem}:{tag}",
                    "observed_value": observed, "section": path.stem,
                    "source_file": path.name, "format": "XML",
                    "credential_exposure": credential_key and "value" in attrs,
                    "credential_exposure_kind": "registry" if credential_key and "value" in attrs else "",
                })
        if lower_text and tag.casefold() in {"command", "arguments", "program", "runas"}:
            marker = "PowerShell" if "powershell" in lower_text.casefold() else (
                "command configured" if tag.casefold() in {"command", "program"} else "arguments configured"
            )
            settings.append({
                "gpo_guid": gpo_guid, "setting": f"{path.stem}:{tag}",
                "observed_value": marker, "section": path.stem,
                "source_file": path.name, "format": "XML",
            })
    return settings


def _inspect_policy(gpo: dict[str, Any], max_seconds: float = MAX_GPO_SECONDS) -> dict[str, Any]:
    path_text = str(gpo.get("gPCFileSysPath") or "")
    if not path_text:
        return {"status": "Inaccessible", "reason": "SYSVOL path attribute is missing", "settings": []}
    root = Path(path_text.replace("/", os.sep))
    if not root.is_dir():
        return {"status": "Inaccessible", "reason": "SYSVOL policy directory is unavailable", "settings": []}
    guid = str(gpo.get("objectGUID", ""))
    deadline = time.monotonic() + max_seconds
    candidates = [
        "Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf",
        "User/Microsoft/Windows NT/SecEdit/GptTmpl.inf",
        "Machine/Preferences/Groups/Groups.xml", "User/Preferences/Groups/Groups.xml",
        "Machine/Preferences/Registry/Registry.xml", "User/Preferences/Registry/Registry.xml",
        "Machine/Preferences/ScheduledTasks/ScheduledTasks.xml",
        "User/Preferences/ScheduledTasks/ScheduledTasks.xml",
        "Machine/Preferences/Services/Services.xml", "User/Preferences/Services/Services.xml",
        "Machine/Scripts/scripts.ini", "User/Scripts/scripts.ini", "GPT.INI",
    ]
    settings: list[dict[str, Any]] = []
    inspected = 0
    parsed_policy_content = 0
    parse_errors: list[str] = []
    if (root / "Machine/Registry.pol").exists() or (root / "User/Registry.pol").exists():
        parse_errors.append("Registry.pol is present but its binary policy format is not parsed")
    for relative in candidates:
        if inspected >= MAX_POLICY_FILES or time.monotonic() >= deadline:
            break
        file_path = root / relative
        try:
            if not file_path.is_file():
                continue
            if file_path.stat().st_size > MAX_FILE_BYTES:
                parse_errors.append(f"{relative}: exceeds size limit")
                continue
            inspected += 1
            if file_path.suffix.casefold() == ".inf":
                settings.extend(_parse_inf(file_path, guid))
                parsed_policy_content += 1
            elif file_path.suffix.casefold() == ".xml":
                settings.extend(_parse_xml(file_path, guid))
                parsed_policy_content += 1
            elif file_path.name.casefold() == "scripts.ini":
                parser = configparser.ConfigParser(interpolation=None)
                parser.read_string(file_path.read_text(encoding="utf-8-sig", errors="replace"))
                for section in parser.sections():
                    for key in parser[section]:
                        settings.append({
                            "gpo_guid": guid, "setting": "Configured policy script",
                            "observed_value": {"phase": section, "entry": key},
                            "section": section, "source_file": file_path.name, "format": "INI",
                        })
                if parser.sections():
                    parse_errors.append("Configured script bodies were not collected or executed")
                parsed_policy_content += 1
        except (OSError, UnicodeError, ET.ParseError, configparser.Error) as exc:
            parse_errors.append(f"{relative}: {type(exc).__name__}")
    if time.monotonic() >= deadline:
        status = "Partially assessed"
        parse_errors.append("Policy content time budget reached")
    elif parse_errors:
        status = "Partially assessed"
    elif parsed_policy_content:
        status = "Assessed successfully"
    else:
        status = "Partially assessed"
        parse_errors.append("No supported policy files were available for analysis")
    return {"status": status, "reason": "; ".join(parse_errors), "settings": settings}


def _remote_content_worker(gpos: list[dict[str, Any]], sender: Any) -> None:
    try:
        for index, gpo in enumerate(gpos):
            sender.send((index, _inspect_policy(gpo)))
        sender.send((-1, None))
    finally:
        sender.close()


def _assess_remote_gpos(gpos: list[dict[str, Any]], cancellation_event: Any) -> None:
    targets = [
        {"objectGUID": str(gpo.get("objectGUID", "")), "gPCFileSysPath": str(gpo.get("gPCFileSysPath", ""))}
        for gpo in gpos
    ]
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(target=_remote_content_worker, args=(targets, sender), daemon=True)
    try:
        process.start()
    except Exception as exc:
        receiver.close()
        sender.close()
        for gpo in gpos:
            gpo["content_status"] = "Failed"
            gpo["assessment_status"] = "Failed"
            gpo["content_assessment_reason"] = f"SYSVOL reader could not start: {type(exc).__name__}"
        return
    sender.close()
    pending = set(range(len(gpos)))
    deadline = time.monotonic() + max(10.0, MAX_GPO_SECONDS)
    completed = False
    try:
        while True:
            if cancellation_event is not None and cancellation_event.is_set():
                if process.is_alive():
                    process.terminate()
                for index in pending:
                    gpos[index]["content_status"] = "Partially assessed"
                    gpos[index]["assessment_status"] = "Partially assessed"
                    gpos[index]["content_assessment_reason"] = "Assessment cancelled during SYSVOL content collection"
                break
            if receiver.poll(0.1):
                try:
                    index, outcome = receiver.recv()
                except EOFError:
                    break
                if index == -1:
                    completed = True
                    break
                if index in pending:
                    gpos[index]["content_status"] = outcome["status"]
                    gpos[index]["assessment_status"] = outcome["status"]
                    gpos[index]["content_assessment_reason"] = outcome["reason"]
                    gpos[index]["settings"] = outcome["settings"]
                    pending.remove(index)
                    deadline = time.monotonic() + MAX_GPO_SECONDS
            if time.monotonic() >= deadline:
                if process.is_alive():
                    process.terminate()
                for index in pending:
                    gpos[index]["content_status"] = "Failed"
                    gpos[index]["assessment_status"] = "Failed"
                    gpos[index]["content_assessment_reason"] = "SYSVOL content read exceeded the timeout"
                break
            if not process.is_alive() and not receiver.poll():
                break
    finally:
        process.join(timeout=0.5)
        if process.is_alive():
            process.terminate()
            process.join(timeout=0.5)
        receiver.close()
    if not completed and pending and not (cancellation_event and cancellation_event.is_set()):
        for index in pending:
            gpos[index]["content_status"] = "Failed"
            gpos[index]["assessment_status"] = "Failed"
            gpos[index]["content_assessment_reason"] = "SYSVOL reader stopped before returning a result"


def assess_gpo_contents(gpos: list[dict[str, Any]], cancellation_event: Any = None) -> None:
    """Read allowlisted policy files without executing content or retaining secrets."""
    remote: list[dict[str, Any]] = []
    local: list[dict[str, Any]] = []
    for gpo in gpos:
        path = str(gpo.get("gPCFileSysPath") or "")
        (remote if path.startswith(("\\\\", "//")) else local).append(gpo)
    for gpo in local:
        if cancellation_event is not None and cancellation_event.is_set():
            return
        outcome = _inspect_policy(gpo)
        gpo["content_status"] = outcome["status"]
        gpo["content_assessment_reason"] = outcome["reason"]
        gpo["settings"] = outcome["settings"]
        gpo["assessment_status"] = outcome["status"]
    if remote and not (cancellation_event is not None and cancellation_event.is_set()):
        _assess_remote_gpos(remote, cancellation_event)
