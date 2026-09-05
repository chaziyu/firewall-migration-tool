"""Panorama device-group topology discovery and validation."""

from __future__ import annotations

from typing import Dict, List, Set
from copy import deepcopy
import xml.etree.ElementTree as ET

from fwmigrate.extraction.models import ExtractionStatus

from .extraction import add_source_section, record_extract_only, record_parse_error, record_vendor_extension
from .source_model import PANScope
from .xml_utils import structured_xml_capture, text_or_none


class PANPanoramaExtractor:
    @staticmethod
    def _leaf_values(node: ET.Element, prefix: str = "") -> Dict[str, List[str]]:
        values: Dict[str, List[str]] = {}
        for child in node:
            path = f"{prefix}/{child.tag}" if prefix else child.tag
            if list(child):
                for key, entries in PANPanoramaExtractor._leaf_values(child, path).items():
                    values.setdefault(key, []).extend(entries)
            elif child.text and child.text.strip():
                values.setdefault(path, []).append(child.text.strip())
        return values

    @staticmethod
    def _effective_template_values(templates, ordered_names, stack):
        effective: Dict[str, List[str]] = {}
        provenance: Dict[str, List[dict]] = {}

        def merge(source, node):
            for path, values in PANPanoramaExtractor._leaf_values(node).items():
                for value in values:
                    effective[path] = [value]
                    provenance.setdefault(path, []).append({
                        "source": source, "value": value,
                        "inherited": source != "template-stack",
                    })

        for name in ordered_names:
            if name in templates:
                merge(name, templates[name])
        local = ET.Element("template-stack")
        for child in stack:
            if child.tag not in {"templates", "devices"}:
                local.append(deepcopy(child))
        merge("template-stack", local)
        for entries in provenance.values():
            if len(entries) > 1:
                entries[-1]["overrides"] = [entry["source"] for entry in entries[:-1]]
        return effective, provenance

    @staticmethod
    def top_level_device_entries(root: ET.Element) -> List[ET.Element]:
        """Return device entries in normal or read-only PAN exports."""
        return root.findall("./devices/entry") + root.findall("./readonly/devices/entry")

    @staticmethod
    def device_group_entries(root: ET.Element) -> List[ET.Element]:
        """Return device-group entries from configuration contexts only.

        Template XML can contain nested ``devices`` and ``device-group``
        nodes.  Those are template content, not live Panorama hierarchy, so
        broad descendant searches would incorrectly flatten them into the
        active resolver.
        """
        candidates = list(root.findall("./device-group/entry"))
        for device in PANPanoramaExtractor.top_level_device_entries(root):
            candidates.extend(device.findall("./device-group/entry"))
        for container in root.findall("./device-groups"):
            candidates.extend(container.findall("./entry"))
        result: List[ET.Element] = []
        seen = set()
        for entry in candidates:
            if id(entry) not in seen:
                result.append(entry)
                seen.add(id(entry))
        return result

    @staticmethod
    def device_entries(root: ET.Element) -> List[ET.Element]:
        """Return direct devices plus managed devices in real device groups."""
        candidates = list(PANPanoramaExtractor.top_level_device_entries(root))
        for dg in PANPanoramaExtractor.device_group_entries(root):
            candidates.extend(dg.findall("./devices/entry"))
        result: List[ET.Element] = []
        seen = set()
        for entry in candidates:
            if id(entry) not in seen:
                result.append(entry)
                seen.add(id(entry))
        return result

    @staticmethod
    def template_entries(root: ET.Element, stack: bool = False) -> List[ET.Element]:
        names = ("template-stack", "template-stacks") if stack else ("template", "templates")
        candidates: List[ET.Element] = []
        for name in names:
            candidates.extend(root.findall(f"./{name}/entry"))
            candidates.extend(root.findall(f"./panorama/{name}/entry"))
        result: List[ET.Element] = []
        seen = set()
        for entry in candidates:
            if id(entry) not in seen:
                result.append(entry)
                seen.add(id(entry))
        return result

    @staticmethod
    def discover(root: ET.Element, resolver, extraction) -> None:
        entries = PANPanoramaExtractor.device_group_entries(root)
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
                    new_cycle = [child for child in cycle if child not in invalid]
                    invalid.update(cycle)
                    for child in new_cycle:
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
                record_vendor_extension(
                    extraction, "panorama_hierarchy",
                    f"device-group/entry[@name='{child}']/parent-dg",
                    PANScope(kind="device-group", name=child), child,
                    {"pan_parent_device_group": parent},
                    notes=[f"Device-group parent relationship to {parent!r}."],
                )

        # Panorama device-group membership links managed firewall VSYS scopes.
        for dg_name, entry in by_name.items():
            for device in entry.findall("./devices/entry"):
                serial = device.get("name")
                for vsys in device.findall("./vsys/entry"):
                    vsys_name = vsys.get("name")
                    if not vsys_name:
                        continue
                    resolver.set_vsys_device_group(vsys_name, dg_name, device_serial=serial)
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

    @staticmethod
    def extract_templates(root: ET.Element, extraction) -> None:
        """Inventory template and template-stack topology without flattening it."""
        templates = PANPanoramaExtractor.template_entries(root)
        stacks = PANPanoramaExtractor.template_entries(root, stack=True)
        templates_by_name = {entry.get("name"): entry for entry in templates if entry.get("name")}
        for entry in templates:
            name = entry.get("name")
            path = f"template/entry[@name='{name}']" if name else "template/entry"
            attributes = {
                "pan_template_name": name,
                "pan_network": structured_xml_capture(entry.find("./config/devices/entry/network"))
                    or structured_xml_capture(entry.find("./network")),
                "pan_device_configuration": structured_xml_capture(entry.find("./config/devices")),
                "pan_vsys_sections": structured_xml_capture(entry.find("./config/devices/entry/vsys")),
                "pan_source_entry": structured_xml_capture(entry),
                "pan_source_scope": "template",
            }
            attributes = {key: value for key, value in attributes.items() if value is not None}
            if not name:
                record_parse_error(extraction, "panorama_templates", path, None, None, attributes,
                                   notes=["PAN-OS template is missing its required name."])
                continue
            record_extract_only(
                extraction, "panorama_templates", path,
                PANScope(kind="template", name=name), name, attributes,
                notes=["Panorama template retained with raw source configuration for effective inheritance."],
                requires_manual_review=True,
            )
        for entry in stacks:
            name = entry.get("name")
            path = f"template-stack/entry[@name='{name}']" if name else "template-stack/entry"
            ordered_templates = [child.get("name") for child in entry.findall("./templates/entry") if child.get("name")]
            ordered_templates += [child.text.strip() for child in entry.findall("./templates/member") if child.text and child.text.strip()]
            effective, provenance = PANPanoramaExtractor._effective_template_values(
                templates_by_name, ordered_templates, entry
            )
            attributes = {
                "pan_templates": ordered_templates,
                "pan_template_stack_order": ordered_templates,
                "pan_effective_template_configuration": effective,
                "pan_template_provenance": provenance,
                "pan_devices": [child.get("name") for child in entry.findall("./devices/entry") if child.get("name")],
                "pan_source_entry": structured_xml_capture(entry),
                "pan_source_scope": "template-stack",
            }
            if not name:
                record_parse_error(extraction, "panorama_template_stacks", path, None, None, attributes,
                                   notes=["PAN-OS template stack is missing its required name."])
                continue
            record_extract_only(
                extraction, "panorama_template_stacks", path,
                PANScope(kind="template-stack", name=name), name, attributes,
                notes=["Panorama template stack effective values use declared order; raw source evidence is retained."],
                requires_manual_review=True,
            )
        if templates:
            add_source_section(extraction, "panorama/templates", ExtractionStatus.EXTRACT_ONLY,
                               len(templates), len(templates), 0,
                               "PANPanoramaExtractor.extract_templates", source_context="panorama")
        if stacks:
            add_source_section(extraction, "panorama/template-stacks", ExtractionStatus.EXTRACT_ONLY,
                               len(stacks), len(stacks), 0,
                               "PANPanoramaExtractor.extract_templates", source_context="panorama")
