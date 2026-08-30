"""Panorama device-group topology discovery and validation."""

from __future__ import annotations

from typing import Dict, List, Set
import xml.etree.ElementTree as ET

from fwmigrate.extraction.models import ExtractionStatus

from .extraction import add_source_section, record_parse_error, record_vendor_extension
from .source_model import PANScope
from .xml_utils import structured_xml_capture, text_or_none


class PANPanoramaExtractor:
    @staticmethod
    def discover(root: ET.Element, resolver, extraction) -> None:
        entries = root.findall(".//device-group/entry")
        names = {entry.get("name") for entry in entries if entry.get("name")}
        requested: Dict[str, str] = {}
        by_name = {entry.get("name"): entry for entry in entries if entry.get("name")}
        for child, entry in by_name.items():
            parent = text_or_none(entry, "./parent-dg")
            if parent:
                requested[child] = parent

        invalid: Set[str] = set()
        for child, parent in requested.items():
            if parent not in names:
                invalid.add(child)
                record_parse_error(
                    extraction, "panorama_hierarchy",
                    f"device-group/entry[@name='{child}']/parent-dg",
                    PANScope(kind="device-group", name=child), child,
                    {"pan_parent_device_group": parent},
                    notes=[f"Parent device group {parent!r} does not exist."],
                )

        # Detect cycles without installing any edge participating in a cycle.
        for start in requested:
            seen: List[str] = []
            current = start
            while current in requested:
                if current in seen:
                    cycle = seen[seen.index(current):]
                    invalid.update(cycle)
                    for child in cycle:
                        record_parse_error(
                            extraction, "panorama_hierarchy",
                            f"device-group/entry[@name='{child}']/parent-dg",
                            PANScope(kind="device-group", name=child), child,
                            {"pan_parent_device_group": requested[child], "pan_cycle": cycle},
                            notes=[f"Device-group parent cycle detected: {' -> '.join(cycle + [cycle[0]])}."],
                        )
                    break
                seen.append(current)
                current = requested[current]

        for child, parent in requested.items():
            if child not in invalid:
                resolver.set_dg_parent(child, parent)

        # Panorama device-group membership links managed firewall VSYS scopes.
        for dg_name, entry in by_name.items():
            for device in entry.findall("./devices/entry"):
                serial = device.get("name")
                for vsys in device.findall("./vsys/entry"):
                    vsys_name = vsys.get("name")
                    if not vsys_name:
                        continue
                    resolver.set_vsys_device_group(vsys_name, dg_name)
                    record_vendor_extension(
                        extraction, "panorama_hierarchy",
                        f"device-group/entry[@name='{dg_name}']/devices/entry[@name='{serial}']/vsys/entry[@name='{vsys_name}']",
                        PANScope(kind="device-group", name=dg_name), vsys_name,
                        {"pan_device_group": dg_name, "pan_device_serial": serial,
                         "pan_vsys": vsys_name, "pan_source_entry": structured_xml_capture(vsys)},
                        notes=["Panorama managed-firewall VSYS to device-group relationship."],
                    )
        if entries:
            add_source_section(
                extraction, "panorama/device-group-hierarchy",
                ExtractionStatus.PARTIALLY_NORMALIZED if invalid else ExtractionStatus.VENDOR_EXTENSION,
                len(entries), len(entries), 0,
                "PANPanoramaExtractor.discover", source_context="panorama",
            )
