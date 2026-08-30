"""PAN-OS network-scope relationship helpers."""

from __future__ import annotations

from typing import Dict, List
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
    def extract(root: ET.Element, extraction) -> Dict[str, Dict[str, List[str]]]:
        mappings: Dict[str, Dict[str, List[str]]] = {}
        for vsys_entry in root.findall(".//vsys/entry"):
            vsys = vsys_entry.get("name") or "vsys1"
            scope = PANScope(kind="vsys", name=vsys, vsys=vsys)
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
            mappings[vsys] = values_by_type
            add_source_section(
                extraction, "import/network", ExtractionStatus.VENDOR_EXTENSION,
                sum(len(values) or 1 for values in values_by_type.values()),
                sum(len(values) or 1 for values in values_by_type.values()), 0,
                "PANVsysImportExtractor.extract", source_context=f"vsys:{vsys}",
            )
        return mappings

    @staticmethod
    def associate(mappings: Dict[str, Dict[str, List[str]]], extraction) -> None:
        for interface in extraction.canonical_ir.interfaces:
            imported = [vsys for vsys, values in mappings.items()
                        if interface.name in values.get("interface", [])]
            if imported:
                interface.source_attributes["pan_imported_by_vsys"] = imported
                if len(imported) == 1:
                    interface.source_attributes["pan_vsys"] = imported[0]
                else:
                    interface.requires_manual_review = True
        for route in extraction.canonical_ir.routes:
            vr = route.source_attributes.get("pan_virtual_router")
            imported = [vsys for vsys, values in mappings.items()
                        if vr in values.get("virtual-router", []) or
                        vr in values.get("logical-router", [])]
            if imported:
                route.source_attributes["pan_imported_by_vsys"] = imported
                if len(imported) > 1:
                    route.requires_manual_review = True
                    route.migration_status = "PARTIALLY_NORMALIZED"
                    if "multiple-vsys-imports" not in route.review_reasons:
                        route.review_reasons.append("multiple-vsys-imports")
