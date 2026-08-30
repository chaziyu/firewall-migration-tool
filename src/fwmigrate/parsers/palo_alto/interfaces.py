"""PAN-OS physical, logical, and mode-specific interface extraction."""

from __future__ import annotations

from typing import Any, Dict, Iterable, Optional, Tuple
import xml.etree.ElementTree as ET

from fwmigrate.ir.core import IRInterface

from .extraction import record_extract_only, record_normalized, record_partial, record_parse_error
from .source_model import PANScope, PANSourceObject
from .xml_utils import collect_unknown_children, structured_xml_capture, text_or_none


MODES = {"layer3", "layer2", "virtual-wire", "tap", "ha", "decrypt-mirror"}


def _source_fields(node: ET.Element, physical_node: Optional[ET.Element] = None) -> Dict[str, Any]:
    physical = physical_node if physical_node is not None else node
    attrs: Dict[str, Any] = {
        "pan_source_entry": structured_xml_capture(node),
        "pan_comment": text_or_none(node, "./comment") or text_or_none(physical, "./comment"),
        "pan_link_state": text_or_none(physical, "./link-state"),
        "pan_management_profile": text_or_none(node, "./interface-management-profile"),
        "pan_mtu": text_or_none(node, "./mtu") or text_or_none(physical, "./mtu"),
        "pan_speed": text_or_none(physical, "./speed"),
        "pan_duplex": text_or_none(physical, "./duplex"),
    }
    # These settings are valid PAN-OS interface configuration, but are not
    # represented by the portable IRInterface contract.  Keep the complete
    # subtree as source evidence instead of treating it as a handled/no-op
    # child.
    for child_name, attribute_name in (
        ("aggregate-group", "pan_aggregate_group"),
        ("lacp", "pan_lacp"),
        ("fec", "pan_fec"),
        ("poe", "pan_poe"),
    ):
        child = physical.find(f"./{child_name}")
        if child is not None:
            attrs[attribute_name] = structured_xml_capture(child)
    lldp = physical.find("./lldp")
    if lldp is not None:
        attrs["pan_lldp"] = structured_xml_capture(lldp)
    return {key: value for key, value in attrs.items() if value is not None}


def parse_layer3_interface(
    config_node: ET.Element,
    interface_name: str,
    interface_type: str,
    parent: Optional[str] = None,
    physical_node: Optional[ET.Element] = None,
) -> Tuple[IRInterface, Dict[str, Any]]:
    attrs = _source_fields(config_node, physical_node)
    attrs.update({"pan_interface_mode": "layer3", "pan_parent_interface": parent})
    ipv4 = [entry.get("name") for entry in config_node.findall("./ip/entry") if entry.get("name")]
    if ipv4:
        attrs["pan_ipv4_addresses"] = ipv4
    ipv6 = []
    for entry in config_node.findall("./ipv6/address/entry"):
        if entry.get("name"):
            ipv6.append({"address": entry.get("name"), "source_entry": structured_xml_capture(entry),
                         "enable": text_or_none(entry, "./enable")})
    if ipv6:
        attrs["pan_ipv6_addresses"] = ipv6
    dhcp = config_node.find("./dhcp-client")
    pppoe = config_node.find("./pppoe")
    if dhcp is not None:
        attrs["pan_dhcp_client"] = structured_xml_capture(dhcp)
    if pppoe is not None:
        attrs["pan_pppoe"] = structured_xml_capture(pppoe)
    adjust_mss = config_node.find("./adjust-tcp-mss")
    if adjust_mss is not None:
        attrs["pan_adjust_tcp_mss"] = structured_xml_capture(adjust_mss)
        attrs["pan_adjust_tcp_mss_enabled"] = text_or_none(adjust_mss, "./enable")
        attrs["pan_adjust_tcp_mss_ipv4"] = (
            text_or_none(adjust_mss, "./ipv4/mss-adjustment")
            or text_or_none(adjust_mss, "./ipv4")
        )
        attrs["pan_adjust_tcp_mss_ipv6"] = (
            text_or_none(adjust_mss, "./ipv6/mss-adjustment")
            or text_or_none(adjust_mss, "./ipv6")
        )
    ndp_proxy = config_node.find("./ndp-proxy")
    if ndp_proxy is not None:
        attrs["pan_ndp_proxy"] = structured_xml_capture(ndp_proxy)
        attrs["pan_ndp_proxy_enabled"] = text_or_none(ndp_proxy, "./enable")
        attrs["pan_ndp_proxy_negate"] = text_or_none(ndp_proxy, "./negate")
        ndp_addresses = [
            entry.get("name") or text_or_none(entry)
            for entry in ndp_proxy.findall("./address/entry")
            if entry.get("name") or text_or_none(entry)
        ]
        if not ndp_addresses:
            ndp_addresses = [
                value
                for member in ndp_proxy.findall("./address/member")
                for value in [(member.text or "").strip()]
                if value
            ]
        if ndp_addresses:
            attrs["pan_ndp_proxy_addresses"] = ndp_addresses
    tag_text = text_or_none(config_node, "./tag")
    tag = int(tag_text) if tag_text and tag_text.isdigit() else None
    if tag_text is not None:
        attrs["pan_subinterface_tag"] = tag_text
    unknown = collect_unknown_children(
        config_node, ["ip", "ipv6", "comment", "interface-management-profile", "dhcp-client",
                      "pppoe", "tag", "units", "link-state", "mtu", "adjust-tcp-mss", "ndp-proxy"])
    if unknown:
        attrs["pan_unknown_layer3_fields"] = unknown
    if physical_node is not None:
        physical_unknown = collect_unknown_children(
            physical_node, [*MODES, "comment", "link-state", "speed", "duplex", "mtu", "lldp",
                            "aggregate-group", "fec", "poe", "lacp"])
        if physical_unknown:
            attrs["pan_unknown_physical_fields"] = physical_unknown
    link_state = attrs.get("pan_link_state")
    status_kwargs = {"status": link_state != "down"} if link_state in {"auto", "up", "down"} else {}
    if link_state is not None and link_state not in {"auto", "up", "down"}:
        attrs["pan_link_state_invalid"] = True
    attrs["status_explicit"] = link_state is not None
    addressing_mode = "dhcp-client" if dhcp is not None else "pppoe" if pppoe is not None else "static" if ipv4 else None
    interface = IRInterface(
        name=interface_name, source_context=None, ip=ipv4[0] if ipv4 else None,
        description=attrs.get("pan_comment"), management_profile=attrs.get("pan_management_profile"),
        parent=parent, vlanid=tag, interface_type=interface_type,
        addressing_mode=addressing_mode, source_attributes=attrs, **status_kwargs,
    )
    return interface, attrs


def parse_layer2_interface(node: ET.Element, name: str, parent: Optional[str] = None,
                           physical_node: Optional[ET.Element] = None) -> Dict[str, Any]:
    attrs = _source_fields(node, physical_node)
    attrs.update({"pan_interface_mode": "layer2", "pan_parent_interface": parent,
                  "pan_vlan_tag": text_or_none(node, "./tag")})
    attrs["pan_unknown_fields"] = collect_unknown_children(
        node, ["comment", "interface-management-profile", "tag", "units", "lldp", "mtu"])
    return attrs


def parse_virtual_wire_interface(node: ET.Element, name: str, **_: Any) -> Dict[str, Any]:
    attrs = _source_fields(node)
    attrs.update({"pan_interface_mode": "virtual-wire",
                  "pan_virtual_wire_references": structured_xml_capture(node)})
    return attrs


def parse_tap_interface(node: ET.Element, name: str, **_: Any) -> Dict[str, Any]:
    attrs = _source_fields(node)
    attrs.update({"pan_interface_mode": "tap", "pan_tap_settings": structured_xml_capture(node)})
    return attrs


def parse_ha_interface(node: ET.Element, name: str, **_: Any) -> Dict[str, Any]:
    attrs = _source_fields(node)
    attrs.update({"pan_interface_mode": "ha", "pan_ha_settings": structured_xml_capture(node)})
    return attrs


def parse_decrypt_mirror_interface(node: ET.Element, name: str, **_: Any) -> Dict[str, Any]:
    attrs = _source_fields(node)
    attrs.update({"pan_interface_mode": "decrypt-mirror",
                  "pan_decrypt_mirror_settings": structured_xml_capture(node)})
    return attrs


def parse_ethernet_interface(entry: ET.Element, name: str) -> Dict[str, Any]:
    attrs = _source_fields(entry)
    attrs["pan_interface_type"] = "ethernet"
    unknown = collect_unknown_children(
        entry, [*MODES, "comment", "link-state", "speed", "duplex", "mtu", "lldp",
                "aggregate-group", "fec", "poe", "lacp"])
    if unknown:
        attrs["pan_unknown_physical_fields"] = unknown
    return attrs


def parse_aggregate_ethernet_interface(entry: ET.Element, name: str) -> Dict[str, Any]:
    attrs = _source_fields(entry)
    attrs["pan_interface_type"] = "aggregate-ethernet"
    unknown = collect_unknown_children(
        entry, [*MODES, "comment", "link-state", "speed", "duplex", "mtu", "lldp",
                "aggregate-group", "fec", "poe", "lacp"])
    if unknown:
        attrs["pan_unknown_physical_fields"] = unknown
    return attrs


def parse_loopback_interface(entry: ET.Element, name: str) -> Tuple[IRInterface, Dict[str, Any]]:
    return parse_layer3_interface(entry, name, "loopback")


def parse_tunnel_interface(entry: ET.Element, name: str) -> Tuple[IRInterface, Dict[str, Any]]:
    return parse_layer3_interface(entry, name, "tunnel")


def parse_vlan_interface(entry: ET.Element, name: str) -> Tuple[IRInterface, Dict[str, Any]]:
    return parse_layer3_interface(entry, name, "vlan")


def parse_subinterfaces(mode_node: ET.Element) -> Iterable[ET.Element]:
    return mode_node.findall("./units/entry")


def _issues(attrs: Dict[str, Any]) -> list[str]:
    issues = []
    if len(attrs.get("pan_ipv4_addresses", [])) > 1:
        issues.append("Multiple IPv4 addresses exceed the canonical scalar interface field.")
    if attrs.get("pan_ipv6_addresses"):
        issues.append("IPv6 entry attributes remain source-only.")
    if attrs.get("pan_dhcp_client"):
        issues.append("DHCP client settings remain source-only.")
    if attrs.get("pan_pppoe"):
        issues.append("PPPoE settings remain source-only.")
    if attrs.get("pan_adjust_tcp_mss"):
        issues.append("TCP MSS adjustment settings remain source-only.")
    if attrs.get("pan_ndp_proxy"):
        issues.append("NDP proxy settings remain source-only.")
    source_only_physical = {
        "pan_aggregate_group": "Aggregate-group semantics remain source-only.",
        "pan_lacp": "LACP settings remain source-only.",
        "pan_fec": "FEC settings remain source-only.",
        "pan_poe": "PoE settings remain source-only.",
    }
    issues.extend(message for key, message in source_only_physical.items() if attrs.get(key))
    if attrs.get("pan_unknown_layer3_fields") or attrs.get("pan_unknown_physical_fields"):
        issues.append("Unknown interface fields were retained.")
    if attrs.get("pan_link_state") == "auto":
        issues.append("Original link-state auto is retained in source evidence.")
    if attrs.get("pan_link_state_invalid"):
        issues.append("Invalid interface link-state was retained without applying a source default.")
    if any(attrs.get(key) is not None for key in ("pan_mtu", "pan_speed", "pan_duplex", "pan_lldp")):
        issues.append("Physical interface settings remain source evidence.")
    return issues


def _register_l3(ir, resolver, scope: PANScope, interface: IRInterface, attrs: Dict[str, Any],
                 path: str, extraction) -> None:
    if scope.device_serial:
        attrs["pan_device_serial"] = scope.device_serial
    interface.source_attributes.update(attrs)
    interface.source_context = (
        f"{scope.kind}:{scope.name}:device:{scope.device_serial}"
        if scope.device_serial else f"{scope.kind}:{scope.name}"
    )
    ir.interfaces.append(interface)
    resolver.register_object(PANSourceObject(
        name=interface.name, kind="interface", domain="interface", source_path=path,
        scope=scope, attributes=attrs, ir_object=interface), "interface")
    issues = _issues(attrs)
    interface.requires_manual_review = bool(issues)
    if issues:
        record_partial(extraction, "interfaces", path, scope, interface.name, attrs, notes=issues)
    else:
        record_normalized(extraction, "interfaces", path, scope, interface.name, attrs)


def _record_source_only(extraction, scope: PANScope, path: str, name: Optional[str], attrs: Dict[str, Any]) -> None:
    if not name:
        record_parse_error(extraction, "interfaces", path, scope, None, attrs,
                           notes=["PAN-OS interface is missing its required name."])
        return
    record_extract_only(
        extraction, "interfaces", path, scope, name, attrs,
        notes=[f"PAN-OS {attrs.get('pan_interface_mode')} interface semantics retained as source-only evidence."],
        requires_manual_review=True,
    )


def extract_interfaces(network_root: ET.Element, scope: PANScope, ir, resolver, extraction) -> None:
    root = network_root.find("./interface")
    if root is None:
        return
    physical_parsers = {"ethernet": parse_ethernet_interface,
                        "aggregate-ethernet": parse_aggregate_ethernet_interface}
    mode_parsers = {"layer2": parse_layer2_interface, "virtual-wire": parse_virtual_wire_interface,
                    "tap": parse_tap_interface, "ha": parse_ha_interface,
                    "decrypt-mirror": parse_decrypt_mirror_interface}
    for family, physical_parser in physical_parsers.items():
        for entry in root.findall(f"./{family}/entry"):
            name = entry.get("name")
            base = f"network/interface/{family}/entry[@name='{name}']"
            if not name:
                _record_source_only(extraction, scope, base, None, physical_parser(entry, ""))
                continue
            configured = [child.tag for child in entry if child.tag in MODES]
            if not configured:
                attrs = physical_parser(entry, name)
                attrs["pan_interface_mode"] = "unconfigured"
                _record_source_only(extraction, scope, base, name, attrs)
            layer3 = entry.find("./layer3")
            if layer3 is not None:
                interface, attrs = parse_layer3_interface(layer3, name, family, physical_node=entry)
                _register_l3(ir, resolver, scope, interface, attrs, f"{base}/layer3", extraction)
                for unit in parse_subinterfaces(layer3):
                    unit_name = unit.get("name")
                    path = f"{base}/layer3/units/entry[@name='{unit_name}']"
                    if not unit_name:
                        _record_source_only(extraction, scope, path, None,
                                            {"pan_source_entry": structured_xml_capture(unit),
                                             "pan_interface_mode": "layer3-subinterface"})
                        continue
                    sub, sub_attrs = parse_layer3_interface(
                        unit, unit_name, f"{family}-subinterface", parent=name)
                    _register_l3(ir, resolver, scope, sub, sub_attrs, path, extraction)
            for mode, parser in mode_parsers.items():
                mode_node = entry.find(f"./{mode}")
                if mode_node is None:
                    continue
                attrs = parser(mode_node, name, parent=None, physical_node=entry)
                attrs.update(physical_parser(entry, name))
                attrs["pan_interface_mode"] = mode
                _record_source_only(extraction, scope, f"{base}/{mode}", name, attrs)
                if mode == "layer2":
                    for unit in parse_subinterfaces(mode_node):
                        unit_name = unit.get("name")
                        unit_attrs = parse_layer2_interface(unit, unit_name or "", parent=name)
                        unit_attrs["pan_interface_mode"] = "layer2-subinterface"
                        _record_source_only(
                            extraction, scope,
                            f"{base}/layer2/units/entry[@name='{unit_name}']", unit_name, unit_attrs)

    logical = {"loopback": parse_loopback_interface, "tunnel": parse_tunnel_interface,
               "vlan": parse_vlan_interface}
    for family, parser in logical.items():
        entries = list(root.findall(f"./{family}/units/entry"))
        entries.extend(entry for entry in root.findall(f"./{family}/entry") if entry not in entries)
        for entry in entries:
            name = entry.get("name")
            path = (f"network/interface/{family}/units/entry[@name='{name}']"
                    if entry in root.findall(f"./{family}/units/entry")
                    else f"network/interface/{family}/entry[@name='{name}']")
            if not name:
                _record_source_only(extraction, scope, path, None,
                                    {"pan_source_entry": structured_xml_capture(entry),
                                     "pan_interface_mode": family})
                continue
            interface, attrs = parser(entry, name)
            _register_l3(ir, resolver, scope, interface, attrs, path, extraction)
