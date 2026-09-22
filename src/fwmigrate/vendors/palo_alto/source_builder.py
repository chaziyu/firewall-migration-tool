"""PAN-OS source loading, inventory capture, and typed extraction orchestration."""

from __future__ import annotations

import xml.etree.ElementTree as ET

from fwmigrate.extraction.sanitize import sanitize_raw_text, sanitize_source_attributes

from .extraction.address import extract_address
from .extraction.interface import extract_interface
from .extraction.nat import extract_nat
from .extraction.policy import extract_policy
from .extraction.routing import extract_routing
from .extraction.schedule import extract_schedule
from .extraction.service import extract_service
from .model import PANOSConfig
from .source_context import walk_pan_source
from .source_model import PANSourceRecord, PANScope, pan_scope_identity
from .xml_loader import load_pan_source


def _record_value(element: ET.Element) -> dict[str, object]:
    values: dict[str, object] = {}
    for child in element:
        if len(child) == 0 and (child.text or "").strip():
            values[child.tag] = (child.text or "").strip()
        elif len(child):
            values[child.tag] = [item.get("name") or (item.text or "").strip() for item in child]
    return values


def _inventory_record(element: ET.Element, path: tuple[str, ...], context, source_order: int) -> PANSourceRecord:
    return PANSourceRecord(kind=path[-2] if len(path) > 1 else "entry", source_path="/".join(path), name=element.get("name"), scope=context.scope, rulebase_position=context.rulebase_position, values=sanitize_source_attributes(_record_value(element)), source_order=source_order, raw_xml=sanitize_raw_text(ET.tostring(element, encoding="unicode")))


def build_panos_config(content: str) -> PANOSConfig:
    source = load_pan_source(content)
    scopes: list[PANScope] = []
    records: list[PANSourceRecord] = []
    typed: dict[str, list[object]] = {"addresses": [], "address_groups": [], "services": [], "service_groups": [], "schedules": [], "security_rules": [], "default_security_rules": [], "interfaces": [], "interface_imports": [], "interface_units": [], "nat_rules": [], "static_routes": [], "virtual_routers": [], "logical_routers": []}
    extractors = (extract_address, extract_service, extract_schedule, extract_policy, extract_interface, extract_nat, extract_routing)
    keys = {"PANAddress": "addresses", "PANAddressGroup": "address_groups", "PANService": "services", "PANServiceGroup": "service_groups", "PANSchedule": "schedules", "PANSecurityRule": "security_rules", "PANDefaultSecurityRule": "default_security_rules", "PANInterface": "interfaces", "PANInterfaceImport": "interface_imports", "PANInterfaceUnit": "interface_units", "PANNATRule": "nat_rules", "PANStaticRoute": "static_routes", "PANVirtualRouter": "virtual_routers", "PANLogicalRouter": "logical_routers"}
    for element, path, context in walk_pan_source(source.root):
        if context.scope and pan_scope_identity(context.scope) not in {pan_scope_identity(item) for item in scopes}:
            scopes.append(context.scope)
        if element.tag == "entry":
            records.append(_inventory_record(element, path, context, len(records) + 1))
            source_order = len(records)
        elif path[-3:] != ("import", "network", "interface"):
            continue
        else:
            source_order = len(records) + 1
        for extractor in extractors:
            model = extractor(element, path, context, source_order)
            if model is not None:
                typed[keys[type(model).__name__]].append(model)
                break
    return PANOSConfig(hostname=source.hostname, source_version=source.source_version, scopes=scopes, **typed, source_inventory=records)
