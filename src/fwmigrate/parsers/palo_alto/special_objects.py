"""Source-only extraction for PAN objects without portable IR semantics."""

from __future__ import annotations

from typing import Iterable
import xml.etree.ElementTree as ET

from fwmigrate.extraction.models import ExtractionStatus

from .extraction import add_source_section, record_extract_only, record_parse_error, record_unsupported
from .source_model import PANScope
from .xml_utils import collect_unknown_children, member_texts, structured_xml_capture, text_or_none


def _entry_path(container: str, entry: ET.Element) -> str:
    name = entry.get("name")
    return f"{container}/entry[@name='{name}']" if name else f"{container}/entry"


def _references(entry: ET.Element) -> dict:
    references = {}
    for field in ("member", "group", "tag", "source", "destination", "application", "service"):
        values = member_texts(entry, f"./{field}/member")
        if values:
            references[field] = values
    return references


def extract_region_objects(scope: PANScope, search_root: ET.Element, extraction) -> None:
    """Inventory configured Region objects without treating them as addresses."""
    containers = [("region", search_root.findall("./region/entry")),
                  ("regions", search_root.findall("./regions/entry"))]
    found = [(container, entry) for container, entries in containers for entry in entries]
    present = [container for container in (search_root.find("./region"), search_root.find("./regions")) if container is not None]
    if not found and not present:
        return
    if not found:
        for container in present:
            record_unsupported(
                extraction, "region_objects", container.tag, scope, container.tag,
                {"pan_source_entry": structured_xml_capture(container)},
                notes=["PAN-OS Region container has no recognized entries."],
            )
        add_source_section(
            extraction, "region", ExtractionStatus.UNSUPPORTED, len(present), len(present), 0,
            "extract_region_objects", source_context=f"{scope.kind}:{scope.name}",
        )
        return
    parsed = 0
    for container, entry in found:
        name = entry.get("name")
        path = _entry_path(container, entry)
        attributes = {
            "pan_object_kind": "region",
            "pan_description": text_or_none(entry, "./description"),
            "pan_region_settings": structured_xml_capture(entry),
            "pan_references": _references(entry),
            "pan_unknown_fields": collect_unknown_children(entry, [
                "description", "country", "region", "latitude", "longitude", "exclude-list",
                "ip-address", "member", "group", "tag", "source", "destination", "application", "service",
            ]),
            "pan_source_entry": structured_xml_capture(entry),
        }
        attributes = {key: value for key, value in attributes.items() if value not in (None, {}, [])}
        if not name:
            record_parse_error(extraction, "region_objects", path, scope, None, attributes,
                               notes=["PAN-OS Region object is missing its required name."])
            continue
        record_extract_only(
            extraction, "region_objects", path, scope, name, attributes,
            notes=["PAN-OS Region object retained as source-only evidence; no generic address semantics were inferred."],
            requires_manual_review=True,
        )
        parsed += 1
    add_source_section(
        extraction, "region", ExtractionStatus.EXTRACT_ONLY, len(found), parsed, 0,
        "extract_region_objects", source_context=f"{scope.kind}:{scope.name}",
    )


DEVICE_ID_CONTAINERS = (
    "device-id", "device-id-objects", "device-identification", "device-objects",
)


def extract_device_id_objects(scope: PANScope, search_root: ET.Element, extraction) -> None:
    """Inventory PAN Device-ID/device-object configuration as vendor data."""
    found: list[tuple[str, ET.Element]] = []
    for container in DEVICE_ID_CONTAINERS:
        found.extend((container, entry) for entry in search_root.findall(f"./{container}/entry"))
    present = [search_root.find(f"./{container}") for container in DEVICE_ID_CONTAINERS]
    present = [container for container in present if container is not None]
    if not found and not present:
        return
    if not found:
        for container in present:
            record_unsupported(
                extraction, "device_id_objects", container.tag, scope, container.tag,
                {"pan_source_entry": structured_xml_capture(container)},
                notes=["PAN-OS Device-ID container has no recognized entries."],
            )
        add_source_section(
            extraction, "device-id", ExtractionStatus.UNSUPPORTED, len(present), len(present), 0,
            "extract_device_id_objects", source_context=f"{scope.kind}:{scope.name}",
        )
        return
    parsed = 0
    for container, entry in found:
        name = entry.get("name")
        path = _entry_path(container, entry)
        attributes = {
            "pan_object_kind": "device-id",
            "pan_description": text_or_none(entry, "./description"),
            "pan_device_id_settings": structured_xml_capture(entry),
            "pan_references": _references(entry),
            "pan_unknown_fields": collect_unknown_children(entry, [
                "description", "device", "device-type", "device-category", "host", "ip-address",
                "serial-number", "mac-address", "tag", "group", "member", "source", "destination",
                "application", "service", "user", "vendor", "model", "os",
            ]),
            "pan_source_entry": structured_xml_capture(entry),
        }
        attributes = {key: value for key, value in attributes.items() if value not in (None, {}, [])}
        if not name:
            record_parse_error(extraction, "device_id_objects", path, scope, None, attributes,
                               notes=["PAN-OS Device-ID object is missing its required name."])
            continue
        record_extract_only(
            extraction, "device_id_objects", path, scope, name, attributes,
            notes=["PAN-OS Device-ID configuration retained as source-only evidence; PAN-specific taxonomy was not projected into addresses."],
            requires_manual_review=True,
        )
        parsed += 1
    add_source_section(
        extraction, "device-id", ExtractionStatus.EXTRACT_ONLY, len(found), parsed, 0,
        "extract_device_id_objects", source_context=f"{scope.kind}:{scope.name}",
    )
