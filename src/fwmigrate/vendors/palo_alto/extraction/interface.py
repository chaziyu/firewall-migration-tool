from __future__ import annotations

import xml.etree.ElementTree as ET

from ..model import PANInterface, PANInterfaceImport, PANInterfaceIPv6Address, PANInterfaceUnit
from ..schema_registry import PANPathSpec
from ..source_context import PANWalkContext
from .common import raw_extra, source_fields, value


def _ipv6(element: ET.Element | None):
    node = element.find("ipv6/address") if element is not None else None
    if node is None:
        return None
    return [PANInterfaceIPv6Address(address=item.get("name"), enable=value(item, "enable"), raw_extra=raw_extra(item, {"enable"}), explicit_fields={child.tag for child in item if child.tag == "enable"}) for item in node]


def _ipv4(element: ET.Element | None):
    node = element.find("ip") if element is not None else None
    return [item.get("name") for item in node if item.tag == "entry"] if node is not None else None


def _scalar_or_member(element: ET.Element | None, tag: str) -> str | None:
    node = element.find(tag) if element is not None else None
    if node is None:
        return None
    return (node.text or next((child.text for child in node if child.text), "")).strip() or None


def _sdwan_link_settings(element: ET.Element | None) -> tuple[str | None, str | None, str | None, str | None, set[str]]:
    settings = element.find("sdwan-link-settings") if element is not None else None
    if settings is None and element is not None:
        settings = element.find("layer3/sdwan-link-settings")
    if settings is None:
        return None, None, None, None, set()
    upstream_nat = _scalar_or_member(settings, "upstream-nat")
    if upstream_nat is None and settings.find("upstream-nat") is not None:
        upstream_nat = _scalar_or_member(settings.find("upstream-nat"), "enable")
    present = {field for field, tag in (("sdwan_enabled", "enable"), ("ipv6_sdwan_enabled", "ipv6-enable"), ("sdwan_interface_profile", "sdwan-interface-profile"), ("upstream_nat", "upstream-nat")) if settings.find(tag) is not None}
    return value(settings, "enable"), value(settings, "ipv6-enable"), value(settings, "sdwan-interface-profile"), upstream_nat, present


def _mode_extra(element: ET.Element, modes: set[str]) -> dict[str, object]:
    known = {"layer3": {"interface-management-profile", "mtu", "ip", "ipv6", "units", "aggregate-group"}, "layer2": {"units", "lacp", "vlan", "aggregate-group"}, "virtual-wire": {"virtual-wire"}, "tap": set(), "ha": set(), "decrypt-mirror": set()}
    return {mode: raw_extra(element.find(mode), known[mode]) for mode in modes if element.find(mode) is not None and raw_extra(element.find(mode), known[mode])}


def extract_interface(element: ET.Element, path: tuple[str, ...], context: PANWalkContext, source_order: int, spec: PANPathSpec) -> object | None:
    common = {"source_path": "/".join(path), "scope": context.scope, "source_order": source_order}
    if spec.name in {"interface_import", "virtual_router_import"}:
        interfaces = [child.text.strip() for child in element if child.tag == "member" and child.text]
        extra, explicit = source_fields(element, spec)
        return PANInterfaceImport(scope=context.scope, interfaces=interfaces if spec.name == "interface_import" else None, virtual_routers=interfaces if spec.name == "virtual_router_import" else None, source_path="/".join(path), raw_extra=extra, explicit_fields=explicit)
    if spec.name == "interface_unit":
        extra, explicit = source_fields(element, spec)
        sdwan_enabled, ipv6_sdwan_enabled, sdwan_profile, upstream_nat, sdwan_fields = _sdwan_link_settings(element)
        explicit.update(sdwan_fields)
        return PANInterfaceUnit(name=element.get("name"), parent=context.interface_name, interface_family=context.interface_family, **common, tag=value(element, "tag"), ipv4_addresses=_ipv4(element), ipv6_addresses=_ipv6(element), management_profile=value(element, "interface-management-profile"), sdwan_enabled=sdwan_enabled, ipv6_sdwan_enabled=ipv6_sdwan_enabled, sdwan_interface_profile=sdwan_profile, upstream_nat=upstream_nat, raw_extra=extra, explicit_fields=explicit)
    if not spec.name.startswith("interface_") or not context.interface_family:
        return None
    modes = {child.tag for child in element if child.tag in {"layer3", "layer2", "virtual-wire", "tap", "ha", "decrypt-mirror"}}
    extra, explicit = source_fields(element, spec)
    explicit.difference_update(modes | {"layer3", "layer2", "virtual-wire", "tap", "ha", "decrypt-mirror"})
    if modes:
        explicit.add("mode")
    layer3 = element.find("layer3")
    if layer3 is not None:
        explicit.update(field for field in ("management_profile", "mtu", "ipv4_addresses", "ipv6_addresses") if layer3.find({"management_profile": "interface-management-profile", "mtu": "mtu", "ipv4_addresses": "ip", "ipv6_addresses": "ipv6"}[field]) is not None)
    extra.update(_mode_extra(element, modes))
    sdwan_enabled, ipv6_sdwan_enabled, sdwan_profile, upstream_nat, sdwan_fields = _sdwan_link_settings(element)
    explicit.update(sdwan_fields)
    aggregate = _scalar_or_member(element, "aggregate-group") or _scalar_or_member(layer3, "aggregate-group") or _scalar_or_member(element.find("layer2"), "aggregate-group")
    if aggregate:
        explicit.add("aggregate-group")
    return PANInterface(name=element.get("name"), **common, interface_family=context.interface_family, aggregate_group=aggregate, mode=next(iter(modes)) if len(modes) == 1 else sorted(modes) if modes else None, comment=value(element, "comment"), link_state=value(element, "link-state"), speed=value(element, "speed"), duplex=value(element, "duplex"), management_profile=value(layer3, "interface-management-profile"), mtu=value(layer3, "mtu"), ipv4_addresses=_ipv4(layer3), ipv6_addresses=_ipv6(layer3), vlan=value(element, "vlan"), lldp_enable=value(element.find("lldp"), "enable"), sdwan_enabled=sdwan_enabled, ipv6_sdwan_enabled=ipv6_sdwan_enabled, sdwan_interface_profile=sdwan_profile, upstream_nat=upstream_nat, raw_extra=extra, explicit_fields=explicit)
