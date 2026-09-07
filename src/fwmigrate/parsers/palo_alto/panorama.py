"""Panorama device-group topology discovery and validation."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set
from copy import deepcopy
import xml.etree.ElementTree as ET

from fwmigrate.extraction.models import ExtractionStatus

from .extraction import add_source_section, record_extract_only, record_parse_error, record_vendor_extension
from .source_model import PANScope
from .xml_utils import structured_xml_capture, text_or_none


class PANPanoramaExtractor:
    _REPLACE_FIELDS = {
        "comment", "interface-management-profile", "ip", "ipv6", "tag",
        "netflow-profile", "lldp", "lacp", "aggregate-group", "mtu",
        "link-state", "speed", "duplex", "link-speed", "link-duplex",
    }

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
        if PANPanoramaExtractor._template_order_errors(templates, ordered_names):
            return effective, provenance
        merged, provenance = PANPanoramaExtractor.materialize_effective_template_device(
            templates,
            ordered_names,
            stack,
            PANPanoramaExtractor.template_stack_contexts(stack)[0]["device"],
        )
        effective = PANPanoramaExtractor._leaf_values(merged)
        for entries in provenance.values():
            if len(entries) > 1:
                entries[-1]["overrides"] = [entry["source"] for entry in entries[:-1]]
        return effective, provenance

    @staticmethod
    def _template_order_errors(templates, ordered_names: List[str]) -> List[str]:
        errors = []
        if len(ordered_names) != len(set(ordered_names)):
            errors.append("Template stack contains duplicate template references.")
        missing = [name for name in ordered_names if name not in templates]
        if missing:
            errors.append("Template stack references missing templates: " + ", ".join(missing) + ".")
        if not ordered_names:
            errors.append("Template stack has no declared template order.")
        return errors

    @staticmethod
    def _template_device(entry: ET.Element, device_name: Optional[str] = None) -> Optional[ET.Element]:
        candidates = entry.findall("./config/devices/entry") + entry.findall("./devices/entry")
        if candidates:
            if device_name:
                for candidate in candidates:
                    if candidate.get("name") == device_name:
                        return candidate
            return candidates[0]
        return None

    @staticmethod
    def _path(node: ET.Element, prefix: str) -> str:
        name = node.get("name")
        suffix = f"[@name='{name}']" if name else ""
        return f"{prefix}/{node.tag}{suffix}" if prefix else f"{node.tag}{suffix}"

    @classmethod
    def _record_fields(cls, node: ET.Element, source: str, prefix: str, provenance: Dict[str, List[dict]]) -> None:
        if node.tag in cls._REPLACE_FIELDS and list(node):
            values = [
                value for entries in cls._leaf_values(node).values() for value in entries
            ]
            provenance.setdefault(cls._path(node, prefix), []).append({
                "source": source,
                "value": values,
                "inherited": source != "template-stack",
            })
        if not list(node):
            value = (node.text or "").strip() or node.get("name")
            if value:
                provenance.setdefault(cls._path(node, prefix), []).append({
                    "source": source,
                    "value": value,
                    "inherited": source != "template-stack",
                })
            return
        for child in node:
            path = cls._path(child, prefix)
            if list(child):
                cls._record_fields(child, source, path, provenance)
            else:
                cls._record_fields(child, source, prefix, provenance)

    @classmethod
    def _merge_nodes(
        cls,
        target: ET.Element,
        source: ET.Element,
        source_name: str,
        provenance: Dict[str, List[dict]],
        prefix: str = "",
    ) -> None:
        members = [child for child in source if child.tag == "member"]
        members_done = False
        for child in source:
            path = cls._path(child, prefix)
            if child.tag in {"templates", "devices"} and prefix == "":
                continue
            if child.tag == "member":
                if members_done:
                    continue
                members_done = True
                for old in list(target):
                    if old.tag == "member":
                        target.remove(old)
                for member in members:
                    target.append(deepcopy(member))
                    cls._record_fields(member, source_name, path.rsplit("/", 1)[0], provenance)
                continue
            if child.tag in cls._REPLACE_FIELDS or (not list(child) and child.tag != "entry"):
                for old in list(target):
                    if old.tag == child.tag:
                        target.remove(old)
                target.append(deepcopy(child))
                cls._record_fields(child, source_name, path if list(child) else path.rsplit("/", 1)[0], provenance)
                continue
            name = child.get("name") if child.tag == "entry" else None
            matches = [old for old in target if old.tag == child.tag and (not name or old.get("name") == name)]
            if matches:
                cls._merge_nodes(matches[0], child, source_name, provenance, path)
            else:
                target.append(deepcopy(child))
                cls._record_fields(child, source_name, path, provenance)

    @classmethod
    def materialize_effective_template_device(
        cls,
        templates: Dict[str, ET.Element],
        ordered_names: List[str],
        stack: ET.Element,
        device_name: Optional[str] = None,
    ) -> tuple[ET.Element, Dict[str, List[dict]]]:
        """Merge one stack/device view while retaining field-level provenance."""
        effective = ET.Element("entry", {"name": device_name} if device_name else {})
        provenance: Dict[str, List[dict]] = {}
        for name in ordered_names:
            device = cls._template_device(templates[name], device_name)
            if device is not None:
                cls._merge_nodes(effective, device, name, provenance)
            else:
                network = templates[name].find("./network")
                if network is not None:
                    cls._merge_nodes(effective, network, name, provenance)
        stack_device = cls._template_device(stack, device_name)
        if stack_device is not None:
            cls._merge_nodes(effective, stack_device, "template-stack", provenance)
        for child in stack:
            if child.tag not in {"templates", "devices", "config"}:
                cls._merge_nodes(effective, child, "template-stack", provenance)
        for entries in provenance.values():
            if len(entries) > 1:
                entries[-1]["overrides"] = [entry["source"] for entry in entries[:-1]]
                entries[-1]["inherited_values"] = [entry["value"] for entry in entries[:-1]]
        return effective, provenance

    @staticmethod
    def template_stack_contexts(stack: ET.Element) -> List[Dict[str, Any]]:
        devices = stack.findall("./devices/entry") or stack.findall("./config/devices/entry")
        if not devices:
            return [{"device": None, "vsys": []}]
        return [{
            "device": device.get("name"),
            "vsys": [entry.get("name") for entry in device.findall("./vsys/entry") if entry.get("name")],
        } for device in devices]

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
            resolution_errors = PANPanoramaExtractor._template_order_errors(
                templates_by_name, ordered_templates
            )
            effective, provenance = (
                PANPanoramaExtractor._effective_template_values(
                    templates_by_name, ordered_templates, entry
                )
                if not resolution_errors else ({}, {})
            )
            attributes = {
                "pan_templates": ordered_templates,
                "pan_template_stack_order": ordered_templates,
                "pan_effective_template_configuration": effective,
                "pan_template_provenance": provenance,
                "pan_template_resolution_valid": not resolution_errors,
                "pan_devices": [child.get("name") for child in entry.findall("./devices/entry") if child.get("name")],
                "pan_source_entry": structured_xml_capture(entry),
                "pan_source_scope": "template-stack",
            }
            if resolution_errors:
                attributes["pan_template_resolution_errors"] = resolution_errors
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
