from __future__ import annotations

import xml.etree.ElementTree as ET

from ..model import PANInterface, PANInterfaceImport, PANInterfaceIPv6Address, PANInterfaceUnit
from ..source_context import PANWalkContext
from .common import raw_extra, typed_fields, value


def _ipv6(element: ET.Element | None):
    node = element.find("ipv6/address") if element is not None else None
    if node is None:
        return None
    return [PANInterfaceIPv6Address(address=item.get("name"), enable=value(item, "enable"), raw_extra=raw_extra(item, {"enable"}), explicit_fields={child.tag for child in item if child.tag == "enable"}) for item in node]


def _ipv4(element: ET.Element | None):
    node = element.find("ip") if element is not None else None
    return [item.get("name") for item in node if item.tag == "entry"] if node is not None else None


def _mode_extra(element: ET.Element, modes: set[str]) -> dict[str, object]:
    known = {"layer3": {"interface-management-profile", "mtu", "ip", "ipv6", "units"}, "layer2": {"units", "lacp", "vlan"}, "virtual-wire": {"virtual-wire"}, "tap": set(), "ha": set(), "decrypt-mirror": set()}
    return {mode: raw_extra(element.find(mode), known[mode]) for mode in modes if element.find(mode) is not None and raw_extra(element.find(mode), known[mode])}


def extract_interface(element: ET.Element, path: tuple[str, ...], context: PANWalkContext, source_order: int) -> object | None:
    common = {"source_path": "/".join(path), "scope": context.scope, "source_order": source_order}
    if path[-3:] == ("import", "network", "interface"):
        interfaces = [child.text.strip() for child in element if child.tag == "member" and child.text]
        extra, explicit = typed_fields(element, {"member"})
        return PANInterfaceImport(scope=context.scope, interfaces=interfaces, source_path="/".join(path), raw_extra=extra, explicit_fields={"interfaces"} if explicit else set())
    if path[-2:] == ("units", "entry") and context.interface_name:
        extra, explicit = typed_fields(element, {"tag", "ip", "ipv6", "interface-management-profile"})
        return PANInterfaceUnit(name=element.get("name"), parent=context.interface_name, tag=value(element, "tag"), ipv4_addresses=_ipv4(element), ipv6_addresses=_ipv6(element), management_profile=value(element, "interface-management-profile"), raw_extra=extra, explicit_fields=explicit)
    if path[-2] not in {"ethernet", "aggregate-ethernet", "loopback", "tunnel", "vlan"} or not context.interface_family:
        return None
    modes = {child.tag for child in element if child.tag in {"layer3", "layer2", "virtual-wire", "tap", "ha", "decrypt-mirror"}}
    known = {"comment", "link-state", "speed", "duplex", *modes, "vlan", "lldp"}
    extra, explicit = typed_fields(element, known)
    extra.update(_mode_extra(element, modes))
    layer3 = element.find("layer3")
    return PANInterface(name=element.get("name"), **common, interface_family=context.interface_family, mode=next(iter(modes)) if len(modes) == 1 else sorted(modes) if modes else None, comment=value(element, "comment"), link_state=value(element, "link-state"), speed=value(element, "speed"), duplex=value(element, "duplex"), management_profile=value(layer3, "interface-management-profile"), mtu=value(layer3, "mtu"), ipv4_addresses=_ipv4(layer3), ipv6_addresses=_ipv6(layer3), vlan=value(element, "vlan"), lldp_enable=value(element.find("lldp"), "enable"), raw_extra=extra, explicit_fields=explicit)
