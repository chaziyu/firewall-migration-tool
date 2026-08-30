"""PAN-OS network-scope relationship helpers."""

from __future__ import annotations

from typing import Dict, List, Optional
import xml.etree.ElementTree as ET

from fwmigrate.extraction.models import ExtractionStatus

from .extraction import add_source_section, record_vendor_extension
from .source_model import PANScope
from .xml_utils import member_texts, structured_xml_capture


class PANVsysImportExtractor:
    IMPORT_TYPES = {
        "interface": "interfaces",
        "virtual-router": "virtual_routers",
        "logical-router": "logical_routers",
        "vlan": "vlans",
        "virtual-wire": "virtual_wires",
    }

    @staticmethod
    def extract(root: ET.Element, extraction) -> Dict[object, Dict[str, List[str]]]:
        mappings: Dict[object, Dict[str, List[str]]] = {}
        seen = set()

        def candidates():
            # Direct device VSYS entries, including Panorama's managed-device
            # entries nested under a device-group, are discovered explicitly.
            for device in root.findall("./devices/entry") + root.findall("./readonly/devices/entry"):
                for vsys in device.findall("./vsys/entry"):
                    yield device.get("name"), vsys
                for dg in device.findall("./device-group/entry"):
                    for managed_device in dg.findall("./devices/entry"):
                        for vsys in managed_device.findall("./vsys/entry"):
                            yield managed_device.get("name"), vsys
            for dg in root.findall("./device-group/entry") + root.findall("./device-groups/entry"):
                for device in dg.findall("./devices/entry"):
                    for vsys in device.findall("./vsys/entry"):
                        yield device.get("name"), vsys
            for vsys in root.findall("./vsys/entry"):
                yield None, vsys

        for device_serial, vsys_entry in candidates():
            identity = (device_serial, id(vsys_entry))
            if identity in seen:
                continue
            seen.add(identity)
            vsys = vsys_entry.get("name") or "vsys1"
            scope = PANScope(kind="vsys", name=vsys, vsys=vsys,
                             device_serial=device_serial, device_name=device_serial)
            network = vsys_entry.find("./import/network")
            if network is None:
                continue
            values_by_type: Dict[str, List[str]] = {}
            for child in network:
                values = member_texts(network, f"./{child.tag}/member")
                values_by_type[child.tag] = values
                domain = PANVsysImportExtractor.IMPORT_TYPES.get(child.tag, "unknown")
                for value in values or [child.tag]:
                    record_vendor_extension(
                        extraction, "vsys_network_import",
                        f"import/network/{child.tag}/member", scope, value,
                        {"pan_import_type": child.tag, "pan_import_value": value,
                         "pan_source_entry": structured_xml_capture(child)},
                        notes=[f"VSYS network {domain} import relationship."],
                    )
            mapping_key: object = (device_serial, vsys) if device_serial else vsys
            mappings[mapping_key] = values_by_type
            add_source_section(
                extraction, "import/network", ExtractionStatus.VENDOR_EXTENSION,
                sum(len(values) or 1 for values in values_by_type.values()),
                sum(len(values) or 1 for values in values_by_type.values()), 0,
                "PANVsysImportExtractor.extract", source_context=f"vsys:{vsys}",
            )
        return mappings

    @staticmethod
    def associate(mappings: Dict[str, Dict[str, List[str]]], extraction) -> None:
        def mapping_parts(key: object) -> tuple[Optional[str], str]:
            if isinstance(key, tuple):
                return key[0], key[1]
            return None, str(key)

        def matches(item_attrs: dict, key: object, values: Dict[str, List[str]], value: str) -> bool:
            serial, _ = mapping_parts(key)
            item_serial = item_attrs.get("pan_device_serial") or item_attrs.get("scope_device_serial")
            return value in values.get("interface", []) and (serial is None or item_serial in {None, serial})

        for interface in extraction.canonical_ir.interfaces:
            imported = [mapping_parts(key)[1] for key, values in mappings.items()
                        if matches(interface.source_attributes, key, values, interface.name)]
            if imported:
                interface.source_attributes["pan_imported_by_vsys"] = imported
                if len(imported) == 1:
                    interface.source_attributes["pan_vsys"] = imported[0]
                else:
                    interface.requires_manual_review = True
        for route in extraction.canonical_ir.routes:
            vr = route.source_attributes.get("pan_virtual_router")
            imported = [mapping_parts(key)[1] for key, values in mappings.items()
                        if (mapping_parts(key)[0] is None or
                            route.source_attributes.get("pan_device_serial") in {None, mapping_parts(key)[0]})
                        and (vr in values.get("virtual-router", []) or
                             vr in values.get("logical-router", []))]
            if imported:
                route.source_attributes["pan_imported_by_vsys"] = imported
                if len(imported) > 1:
                    route.requires_manual_review = True
                    route.migration_status = "PARTIALLY_NORMALIZED"
                    if "multiple-vsys-imports" not in route.review_reasons:
                        route.review_reasons.append("multiple-vsys-imports")
        for item in extraction.inventory_items:
            attrs = item.source_attributes
            if item.domain == "interfaces" and item.name:
                imported = [mapping_parts(key)[1] for key, values in mappings.items()
                            if matches(attrs, key, values, item.name)]
                if imported:
                    attrs["pan_imported_by_vsys"] = imported
                    if len(imported) == 1:
                        attrs["pan_vsys"] = imported[0]
            vr = attrs.get("virtual_router_name") or attrs.get("logical_router_name")
            if not vr or not item.domain.startswith("dynamic_routing:"):
                continue
            imported = [
                mapping_parts(key)[1] for key, values in mappings.items()
                if (mapping_parts(key)[0] is None or
                    attrs.get("pan_device_serial") in {None, mapping_parts(key)[0]})
                and (vr in values.get("virtual-router", []) or
                     vr in values.get("logical-router", []))
            ]
            if imported:
                attrs["pan_imported_by_vsys"] = imported
                if len(imported) == 1:
                    attrs["pan_vsys"] = imported[0]
