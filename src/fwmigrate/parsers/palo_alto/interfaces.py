"""PAN-OS physical, logical, and mode-specific interface extraction."""

from __future__ import annotations

from typing import Any, Dict, Iterable, Optional, Tuple
import ipaddress
import xml.etree.ElementTree as ET

from fwmigrate.ir.core import IRInterface, IRInterfaceIPv4Address, IRInterfaceIPv6Address, IRPANVirtualWire
from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.extraction.sanitize import sanitize_source_attributes

from .extraction import record_extract_only, record_normalized, record_partial, record_parse_error
from .routing_instances import PANRoutingInstance, discover_routing_instances, interface_members
from .source_model import PANScope, PANSourceObject, pan_scope_identity
from .xml_utils import collect_unknown_children, member_texts, structured_xml_capture, text_or_none


MODES = {"layer3", "layer2", "virtual-wire", "tap", "ha", "decrypt-mirror"}


def _sanitize_attrs(attrs: Dict[str, Any]) -> Dict[str, Any]:
    safe = sanitize_source_attributes(attrs)
    attrs.clear()
    attrs.update(safe)
    return attrs


def _mode_semantics(node: ET.Element) -> Dict[str, Any]:
    values: Dict[str, Any] = {}
    for child in node:
        if child.tag == "member":
            values.setdefault("members", []).append((child.text or "").strip())
        elif len(child) == 0:
            values[child.tag.replace("-", "_")] = (child.text or "").strip() or None
        else:
            values[child.tag.replace("-", "_")] = structured_xml_capture(child)
    return values


def _source_fields(node: ET.Element, physical_node: Optional[ET.Element] = None) -> Dict[str, Any]:
    physical = physical_node if physical_node is not None else node
    attrs: Dict[str, Any] = {
        "pan_source_entry": structured_xml_capture(node),
        "pan_comment": text_or_none(node, "./comment") or text_or_none(physical, "./comment"),
        "pan_link_state": text_or_none(physical, "./link-state"),
        "pan_management_profile": text_or_none(node, "./interface-management-profile"),
        "pan_mtu": text_or_none(node, "./mtu") or text_or_none(physical, "./mtu"),
        "pan_speed": text_or_none(physical, "./speed") or text_or_none(physical, "./link-speed"),
        "pan_duplex": text_or_none(physical, "./duplex") or text_or_none(physical, "./link-duplex"),
    }
    aggregate_group = text_or_none(physical, "./aggregate-group")
    if aggregate_group is not None:
        attrs["pan_aggregate_group_name"] = aggregate_group
    for child_name, attribute_name in (
        ("aggregate-group", "pan_aggregate_group"),
        ("lacp", "pan_lacp"),
        ("fec", "pan_fec"),
        ("poe", "pan_poe"),
    ):
        child = physical.find(f"./{child_name}")
        if child is not None:
            attrs[attribute_name] = structured_xml_capture(child)
            if child_name == "lacp":
                attrs["pan_lacp_fields"] = _mode_semantics(child)
    lldp = physical.find("./lldp")
    if lldp is not None:
        captured_lldp = structured_xml_capture(lldp)
        attrs["pan_lldp"] = captured_lldp
        lldp_enabled = text_or_none(lldp, "./enable")
        if lldp_enabled is not None and lldp_enabled.lower() in {"yes", "no"}:
            attrs["pan_lldp_enabled"] = lldp_enabled.lower()
        if physical_node is not None:
            attrs["pan_physical_lldp"] = captured_lldp
    return {key: value for key, value in attrs.items() if value is not None}


def _normalized_mtu(attrs: Dict[str, Any]) -> Optional[int]:
    value = attrs.get("pan_mtu")
    if value is None:
        return None
    if isinstance(value, str) and value.isdigit():
        return int(value)
    attrs["pan_mtu_invalid"] = True
    return None


def _explicit_lldp_state(node: Optional[ET.Element]) -> Optional[str]:
    if node is None:
        return None
    value = text_or_none(node, "./enable")
    normalized = value.lower() if value is not None else None
    return normalized if normalized in {"yes", "no"} else None


def _lldp_semantics(node: ET.Element) -> Dict[str, Any]:
    result: Dict[str, Any] = {"source_entry": structured_xml_capture(node)}
    enabled = text_or_none(node, "./enable")
    profile = text_or_none(node, "./profile")
    if enabled is not None:
        result["enable"] = enabled
    if profile is not None:
        result["profile"] = profile
    passive = text_or_none(node, "./high-availability/passive-pre-negotiation")
    if passive is not None:
        result["high_availability_passive_pre_negotiation"] = passive
    return result


def _ipv6_address_semantics(entry: ET.Element) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "address": entry.get("name"),
        "source_entry": structured_xml_capture(entry),
    }
    enable = text_or_none(entry, "./enable-on-interface") or text_or_none(entry, "./enable")
    if enable is not None:
        result["enable"] = enable
        result["enable_on_interface"] = enable
    if entry.find("./prefix") is not None:
        result["prefix"] = True
    if entry.find("./anycast") is not None:
        result["anycast"] = True
    advertise = entry.find("./advertise")
    if advertise is not None:
        result["advertise"] = {
            "source_entry": structured_xml_capture(advertise),
            **{
                field.replace("-", "_"): value
                for field in (
                    "enable", "valid-lifetime", "preferred-lifetime", "onlink-flag", "auto-config-flag"
                )
                if (value := text_or_none(advertise, f"./{field}")) is not None
            },
        }
    return result


def _ipv6_neighbor_discovery(node: ET.Element) -> Dict[str, Any]:
    result: Dict[str, Any] = {"source_entry": structured_xml_capture(node)}
    for field in ("enable-ndp-monitor", "enable-dad", "dad-attempts", "ns-interval", "reachable-time"):
        value = text_or_none(node, f"./{field}")
        if value is not None:
            result[field.replace("-", "_")] = value
    ra = node.find("./router-advertisement")
    if ra is not None:
        ra_result: Dict[str, Any] = {"source_entry": structured_xml_capture(ra)}
        for field in (
            "enable", "max-interval", "min-interval", "managed-flag", "other-flag", "link-mtu",
            "reachable-time", "retransmission-timer", "hop-limit", "lifetime", "router-preference",
            "enable-consistency-check",
        ):
            value = text_or_none(ra, f"./{field}")
            if value is not None:
                ra_result[field.replace("-", "_")] = value
        dns_support = ra.find("./dns-support")
        if dns_support is not None:
            ra_result["dns_support"] = structured_xml_capture(dns_support)
        result["router_advertisement"] = ra_result
    result["neighbors"] = [
        {
            "address": entry.get("name"),
            "hw_address": text_or_none(entry, "./hw-address"),
            "source_entry": structured_xml_capture(entry),
        }
        for entry in node.findall("./neighbor/entry")
    ]
    return result


def _ipv6_dhcp_client(node: ET.Element) -> Dict[str, Any]:
    result: Dict[str, Any] = {"source_entry": structured_xml_capture(node)}
    for field in ("enable", "accept-ra-route", "default-route-metric", "preference"):
        value = text_or_none(node, f"./{field}")
        if value is not None:
            result[field.replace("-", "_")] = value
    options = node.find("./v6-options")
    if options is not None:
        option_result: Dict[str, Any] = {"source_entry": structured_xml_capture(options)}
        for path, key in (
            ("./enable", "enable"), ("./rapid-commit", "rapid_commit"), ("./duid-type", "duid_type"),
            ("./enable/yes/non-temp-addr", "non_temp_addr"), ("./enable/yes/temp-addr", "temp_addr"),
        ):
            value = text_or_none(options, path)
            if value is not None:
                option_result[key] = value
        result["v6_options"] = option_result
    delegation = node.find("./prefix-delegation")
    if delegation is not None:
        delegation_result: Dict[str, Any] = {"source_entry": structured_xml_capture(delegation)}
        for path, key in (
            ("./enable", "enable"), ("./enable/yes/prefix-len-hint", "prefix_len_hint"),
            ("./enable/yes/prefix-len", "prefix_len"), ("./enable/yes/pfx-pool-name", "prefix_pool_name"),
        ):
            value = text_or_none(delegation, path)
            if value is not None:
                delegation_result[key] = value
        result["prefix_delegation"] = delegation_result
    nd = node.find("./neighbor-discovery")
    if nd is not None:
        result["neighbor_discovery"] = _ipv6_neighbor_discovery(nd)
    return result


def parse_layer3_interface(
    config_node: ET.Element,
    interface_name: str,
    interface_type: str,
    parent: Optional[str] = None,
    physical_node: Optional[ET.Element] = None,
) -> Tuple[IRInterface, Dict[str, Any]]:
    attrs = _source_fields(config_node, physical_node)
    attrs.update({"pan_interface_mode": "layer3", "pan_parent_interface": parent})
    for field in ("decrypt-forward", "cluster-interconnect", "traffic-interconnect", "untagged-sub-interface"):
        value = text_or_none(config_node, f"./{field}")
        if value is not None:
            attrs[f"pan_{field.replace('-', '_')}"] = value
    for child_name, attribute_name in (
        ("bonjour", "pan_bonjour"), ("sdwan-link-settings", "pan_sdwan_link_settings"),
        ("ddns-config", "pan_ddns_config"), ("arp", "pan_arp"),
    ):
        child = config_node.find(f"./{child_name}")
        if child is not None:
            attrs[attribute_name] = structured_xml_capture(child)
    lldp = config_node.find("./lldp")
    if lldp is not None:
        captured_lldp = structured_xml_capture(lldp)
        attrs["pan_layer3_lldp"] = captured_lldp
        attrs["pan_layer3_lldp_fields"] = _lldp_semantics(lldp)
        if physical_node is None or "pan_physical_lldp" not in attrs:
            attrs["pan_lldp"] = captured_lldp
    netflow_profile = text_or_none(config_node, "./netflow-profile")
    if netflow_profile is not None:
        attrs["pan_netflow_profile"] = netflow_profile
    ipv4_entries = [
        {"address": entry.get("name"), "source_entry": structured_xml_capture(entry)}
        for entry in config_node.findall("./ip/entry") if entry.get("name")
    ]
    ipv4 = [entry["address"] for entry in ipv4_entries]
    if ipv4:
        attrs["pan_ipv4_addresses"] = ipv4
        attrs["pan_ipv4_address_entries"] = ipv4_entries
    ipv6_root = config_node.find("./ipv6")
    if ipv6_root is not None:
        ipv6_enabled = text_or_none(ipv6_root, "./enabled")
        interface_id = text_or_none(ipv6_root, "./interface-id")
        if ipv6_enabled is not None:
            attrs["pan_ipv6_enabled"] = ipv6_enabled
        if interface_id is not None:
            attrs["pan_ipv6_interface_id"] = interface_id
    ipv6 = [
        _ipv6_address_semantics(entry)
        for entry in config_node.findall("./ipv6/address/entry") if entry.get("name")
    ]
    if ipv6:
        attrs["pan_ipv6_addresses"] = ipv6
    ipv6_typed: list[IRInterfaceIPv6Address] = []
    for value in ipv6:
        raw = value["address"]
        try:
            parsed = ipaddress.ip_interface(raw)
            if parsed.version != 6:
                raise ValueError("not-ipv6")
            ipv6_typed.append(IRInterfaceIPv6Address(address=str(parsed), source_address=raw))
        except ValueError:
            value["ipv6_parse_error"] = True
    if ipv6_typed:
        attrs["pan_ipv6_typed_addresses"] = [item.model_dump() for item in ipv6_typed]
    for label, path in (
        ("local", "./ipv6/neighbor-discovery"), ("inherited", "./ipv6/inherited/neighbor-discovery"),
        ("inherited", "./ipv6/neighbor-discovery/inherited"),
    ):
        node = config_node.find(path)
        if node is not None:
            key = f"pan_ipv6_neighbor_discovery_{label}"
            value = _ipv6_neighbor_discovery(node)
            if key in attrs:
                attrs[key] = [attrs[key], value] if not isinstance(attrs[key], list) else [*attrs[key], value]
            else:
                attrs[key] = value
    dhcpv6 = config_node.find("./ipv6/dhcp-client")
    if dhcpv6 is not None:
        attrs["pan_ipv6_dhcp_client"] = _ipv6_dhcp_client(dhcpv6)
    dhcp = config_node.find("./dhcp-client")
    pppoe = config_node.find("./pppoe")
    dhcp_enabled = text_or_none(dhcp, "./enable") if dhcp is not None else None
    pppoe_enabled = text_or_none(pppoe, "./enable") if pppoe is not None else None
    if dhcp is not None:
        attrs["pan_dhcp_client"] = structured_xml_capture(dhcp)
        attrs["pan_dhcp_client_fields"] = {
            key: value for key, value in {
                "enable": dhcp_enabled, "create_default_route": text_or_none(dhcp, "./create-default-route"),
                "send_hostname_enable": text_or_none(dhcp, "./send-hostname/enable"),
                "send_hostname": text_or_none(dhcp, "./send-hostname/hostname"),
                "default_route_metric": text_or_none(dhcp, "./default-route-metric"),
            }.items() if value is not None
        }
    if pppoe is not None:
        attrs["pan_pppoe"] = structured_xml_capture(pppoe)
        attrs["pan_pppoe_fields"] = {
            key: value for key, value in {
                "enable": pppoe_enabled, "authentication": text_or_none(pppoe, "./authentication"),
                "static_address_ip": text_or_none(pppoe, "./static-address/ip"),
                "username": text_or_none(pppoe, "./username"),
                "create_default_route": text_or_none(pppoe, "./create-default-route"),
                "default_route_metric": text_or_none(pppoe, "./default-route-metric"),
                "access_concentrator": text_or_none(pppoe, "./access-concentrator"),
                "service": text_or_none(pppoe, "./service"), "passive_enable": text_or_none(pppoe, "./passive/enable"),
            }.items() if value is not None
        }
    adjust_mss = config_node.find("./adjust-tcp-mss")
    if adjust_mss is not None:
        attrs["pan_adjust_tcp_mss"] = structured_xml_capture(adjust_mss)
        attrs["pan_adjust_tcp_mss_enabled"] = text_or_none(adjust_mss, "./enable")
        attrs["pan_adjust_tcp_mss_ipv4"] = (
            text_or_none(adjust_mss, "./ipv4-mss-adjustment") or text_or_none(adjust_mss, "./ipv4/mss-adjustment")
            or text_or_none(adjust_mss, "./ipv4")
        )
        attrs["pan_adjust_tcp_mss_ipv6"] = (
            text_or_none(adjust_mss, "./ipv6-mss-adjustment") or text_or_none(adjust_mss, "./ipv6/mss-adjustment")
            or text_or_none(adjust_mss, "./ipv6")
        )
    ndp_proxy = config_node.find("./ndp-proxy")
    if ndp_proxy is not None:
        attrs["pan_ndp_proxy"] = structured_xml_capture(ndp_proxy)
        ndp_proxy_enabled = text_or_none(ndp_proxy, "./enabled")
        ndp_proxy_legacy_enabled = text_or_none(ndp_proxy, "./enable")
        attrs["pan_ndp_proxy_enabled"] = ndp_proxy_enabled if ndp_proxy_enabled is not None else ndp_proxy_legacy_enabled
        if ndp_proxy_enabled is not None and ndp_proxy_legacy_enabled is not None and ndp_proxy_enabled != ndp_proxy_legacy_enabled:
            attrs["pan_ndp_proxy_enable_conflict"] = {"enabled": ndp_proxy_enabled, "enable": ndp_proxy_legacy_enabled}
        attrs["pan_ndp_proxy_negate"] = text_or_none(ndp_proxy, "./negate")
        ndp_addresses = [
            entry.get("name") or ((entry.text or "").strip() or None)
            for entry in ndp_proxy.findall("./address/entry")
            if entry.get("name") or (entry.text and entry.text.strip())
        ]
        if not ndp_addresses:
            ndp_addresses = member_texts(ndp_proxy, "./address/member")
        if ndp_addresses:
            attrs["pan_ndp_proxy_addresses"] = ndp_addresses
    tag_text = text_or_none(config_node, "./tag")
    tag = int(tag_text) if tag_text and tag_text.isdigit() else None
    if tag_text is not None:
        attrs["pan_subinterface_tag"] = tag_text
    known_layer3 = [
        "ip", "ipv6", "comment", "interface-management-profile", "dhcp-client", "pppoe", "tag", "units",
        "link-state", "mtu", "adjust-tcp-mss", "ndp-proxy", "lldp", "netflow-profile", "decrypt-forward",
        "cluster-interconnect", "traffic-interconnect", "untagged-sub-interface", "bonjour", "sdwan-link-settings",
        "ddns-config", "arp",
    ]
    unknown = collect_unknown_children(config_node, known_layer3)
    if unknown:
        attrs["pan_unknown_layer3_fields"] = unknown
    if physical_node is not None:
        physical_unknown = collect_unknown_children(
            physical_node,
            [*MODES, "comment", "link-state", "link-speed", "link-duplex", "speed", "duplex", "mtu", "lldp",
             "aggregate-group", "fec", "poe", "lacp"],
        )
        if physical_unknown:
            attrs["pan_unknown_physical_fields"] = physical_unknown
    link_state = attrs.get("pan_link_state")
    status_kwargs = {"status": link_state != "down"} if link_state in {"auto", "up", "down"} else {}
    if link_state is not None and link_state not in {"auto", "up", "down"}:
        attrs["pan_link_state_invalid"] = True
    attrs["status_explicit"] = link_state is not None
    source_mtu = _normalized_mtu(attrs)
    physical_lldp = physical_node.find("./lldp") if physical_node is not None else None
    source_lldp_enabled = _explicit_lldp_state(lldp) if lldp is not None else _explicit_lldp_state(physical_lldp)
    addressing_mode = None
    if dhcp_enabled is not None and dhcp_enabled.lower() == "yes":
        addressing_mode = "dhcp-client"
    elif pppoe_enabled is not None and pppoe_enabled.lower() == "yes":
        addressing_mode = "pppoe"
    elif ipv4:
        addressing_mode = "static"
    primary_ipv6 = ipv6_typed[0] if ipv6_typed else None
    nd_local = attrs.get("pan_ipv6_neighbor_discovery_local")
    ra_local = nd_local.get("router_advertisement", {}) if isinstance(nd_local, dict) else {}
    interface = IRInterface(
        name=interface_name, source_context=None, ip=ipv4[0] if ipv4 else None,
        ipv6_address=primary_ipv6.address if primary_ipv6 else None,
        source_ipv6_address=primary_ipv6.source_address if primary_ipv6 else None,
        source_ipv6_interface_identifier=attrs.get("pan_ipv6_interface_id"),
        source_ipv6_send_adv=ra_local.get("enable"), source_ipv6_manage_flag=ra_local.get("managed_flag"),
        source_ipv6_other_flag=ra_local.get("other_flag"), description=attrs.get("pan_comment"),
        management_profile=attrs.get("pan_management_profile"), parent=parent, vlanid=tag, interface_type=interface_type,
        addressing_mode=addressing_mode, dhcp_client=(dhcp_enabled.lower() == "yes") if dhcp_enabled is not None else None,
        source_mtu=source_mtu, source_link_state=attrs.get("pan_link_state"), source_speed=attrs.get("pan_speed"),
        source_duplex=attrs.get("pan_duplex"), source_netflow_profile=attrs.get("pan_netflow_profile"),
        source_lldp_enabled=source_lldp_enabled, source_attributes=attrs, **status_kwargs,
    )
    interface.additional_ipv6_addresses = ipv6_typed[1:]
    for value in ipv4[1:]:
        try:
            parsed = ipaddress.ip_interface(value)
        except ValueError:
            continue
        if parsed.version == 4:
            interface.additional_ipv4_addresses.append(
                IRInterfaceIPv4Address(address=str(parsed), source_address=value)
            )
    return interface, attrs


def parse_layer2_interface(node: ET.Element, name: str, parent: Optional[str] = None,
                           physical_node: Optional[ET.Element] = None) -> Dict[str, Any]:
    attrs = _source_fields(node, physical_node)
    netflow = text_or_none(node, "./netflow-profile")
    lldp = node.find("./lldp")
    attrs.update({"pan_interface_mode": "layer2", "pan_parent_interface": parent,
                  "pan_vlan_tag": text_or_none(node, "./tag"), "pan_layer2_netflow_profile": netflow,
                  "pan_layer2_settings": _mode_semantics(node)})
    if lldp is not None:
        attrs["pan_layer2_lldp"] = _lldp_semantics(lldp)
        attrs["pan_layer2_lldp_enabled"] = _explicit_lldp_state(lldp)
    unknown = collect_unknown_children(node, ["comment", "interface-management-profile", "tag", "units", "lldp", "mtu", "netflow-profile"])
    if unknown:
        attrs["pan_unknown_fields"] = unknown
    return {key: value for key, value in attrs.items() if value is not None}


def parse_virtual_wire_interface(node: ET.Element, name: str, parent: Optional[str] = None,
                                 physical_node: Optional[ET.Element] = None) -> Dict[str, Any]:
    attrs = _source_fields(node, physical_node)
    lldp = node.find("./lldp")
    lacp = node.find("./lacp")
    attrs.update({"pan_interface_mode": "virtual-wire", "pan_parent_interface": parent,
                  "pan_virtual_wire_netflow_profile": text_or_none(node, "./netflow-profile"),
                  "pan_virtual_wire_settings": _mode_semantics(node)})
    if lldp is not None:
        attrs["pan_virtual_wire_lldp"] = _lldp_semantics(lldp)
        attrs["pan_virtual_wire_lldp_enabled"] = _explicit_lldp_state(lldp)
    if lacp is not None:
        attrs["pan_virtual_wire_lacp"] = structured_xml_capture(lacp)
        attrs["pan_virtual_wire_lacp_fields"] = _mode_semantics(lacp)
    unknown = collect_unknown_children(node, ["units", "netflow-profile", "lldp", "lacp", "comment"])
    if unknown:
        attrs["pan_unknown_fields"] = unknown
    return {key: value for key, value in attrs.items() if value is not None}


def parse_virtual_wire_subinterface(node: ET.Element, name: str, parent: str) -> Dict[str, Any]:
    attrs = _source_fields(node)
    classifiers = member_texts(node, "./ip-classifier/member")
    if not classifiers:
        scalar = text_or_none(node, "./ip-classifier")
        if scalar:
            classifiers = [scalar]
    attrs.update({"pan_interface_mode": "virtual-wire-subinterface", "pan_parent_interface": parent,
                  "pan_vlan_tag": text_or_none(node, "./tag"),
                  "pan_virtual_wire_netflow_profile": text_or_none(node, "./netflow-profile"),
                  "pan_virtual_wire_ip_classifiers": classifiers,
                  "pan_virtual_wire_unit_settings": _mode_semantics(node)})
    unknown = collect_unknown_children(node, ["tag", "netflow-profile", "comment", "ip-classifier"])
    if unknown:
        attrs["pan_unknown_fields"] = unknown
    return {key: value for key, value in attrs.items() if value is not None}


def parse_tap_interface(node: ET.Element, name: str, parent: Optional[str] = None,
                        physical_node: Optional[ET.Element] = None) -> Dict[str, Any]:
    attrs = _source_fields(node, physical_node)
    attrs.update({"pan_interface_mode": "tap", "pan_parent_interface": parent,
                  "pan_tap_netflow_profile": text_or_none(node, "./netflow-profile"),
                  "pan_tap_settings": _mode_semantics(node)})
    unknown = collect_unknown_children(node, ["netflow-profile", "comment"])
    if unknown:
        attrs["pan_unknown_fields"] = unknown
    return {key: value for key, value in attrs.items() if value is not None}


def parse_ha_interface(node: ET.Element, name: str, parent: Optional[str] = None,
                       physical_node: Optional[ET.Element] = None) -> Dict[str, Any]:
    attrs = _source_fields(node, physical_node)
    lacp = node.find("./lacp")
    attrs.update({"pan_interface_mode": "ha", "pan_parent_interface": parent, "pan_ha_settings": _mode_semantics(node)})
    if lacp is not None:
        attrs["pan_ha_lacp"] = structured_xml_capture(lacp)
        attrs["pan_ha_lacp_fields"] = _mode_semantics(lacp)
    unknown = collect_unknown_children(node, ["lacp", "comment"])
    if unknown:
        attrs["pan_unknown_fields"] = unknown
    return {key: value for key, value in attrs.items() if value is not None}


def parse_decrypt_mirror_interface(node: ET.Element, name: str, parent: Optional[str] = None,
                                   physical_node: Optional[ET.Element] = None) -> Dict[str, Any]:
    attrs = _source_fields(node, physical_node)
    attrs.update({"pan_interface_mode": "decrypt-mirror", "pan_parent_interface": parent,
                  "pan_decrypt_mirror_settings": _mode_semantics(node)})
    unknown = collect_unknown_children(node, ["comment"])
    if unknown:
        attrs["pan_unknown_fields"] = unknown
    return {key: value for key, value in attrs.items() if value is not None}


def parse_ethernet_interface(entry: ET.Element, name: str) -> Dict[str, Any]:
    attrs = _source_fields(entry)
    attrs["pan_interface_type"] = "ethernet"
    unknown = collect_unknown_children(entry, [*MODES, "comment", "link-state", "link-speed", "link-duplex", "speed", "duplex", "mtu", "lldp", "aggregate-group", "fec", "poe", "lacp"])
    if unknown:
        attrs["pan_unknown_physical_fields"] = unknown
    return attrs


def parse_aggregate_ethernet_interface(entry: ET.Element, name: str) -> Dict[str, Any]:
    attrs = _source_fields(entry)
    attrs["pan_interface_type"] = "aggregate-ethernet"
    unknown = collect_unknown_children(entry, [*MODES, "comment", "link-state", "link-speed", "link-duplex", "speed", "duplex", "mtu", "lldp", "aggregate-group", "fec", "poe", "lacp"])
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
    ipv6_values = attrs.get("pan_ipv6_addresses", [])
    if any(value.get("ipv6_parse_error") for value in ipv6_values if isinstance(value, dict)):
        issues.append("Malformed IPv6 interface address was retained without inference.")
    if attrs.get("pan_ipv6_dhcp_client"):
        issues.append("DHCPv6 client settings are retained as source-oriented interface semantics.")
    if attrs.get("pan_dhcp_client"):
        issues.append("DHCP client settings include source-specific options.")
    if attrs.get("pan_pppoe"):
        issues.append("PPPoE settings include source-specific options.")
    if attrs.get("pan_adjust_tcp_mss"):
        issues.append("TCP MSS adjustment settings remain source-oriented.")
    if attrs.get("pan_ndp_proxy"):
        issues.append("NDP proxy settings remain source-oriented.")
    if attrs.get("pan_netflow_profile"):
        issues.append("Layer3 NetFlow profile remains source-only.")
    if attrs.get("pan_layer3_lldp"):
        issues.append("Layer3 LLDP settings remain source-only.")
    if attrs.get("pan_ndp_proxy_enable_conflict"):
        issues.append("NDP proxy enabled and enable values conflict; enabled is used as the effective value.")
    if attrs.get("pan_source_only_interface_semantics"):
        issues.append(f"PAN-OS {attrs.get('pan_interface_mode')} interface mode is not fully portable in canonical IR.")
    source_only_physical = {"pan_aggregate_group": "Aggregate-group semantics remain source-oriented.",
                            "pan_lacp": "LACP settings remain source-oriented.",
                            "pan_fec": "FEC settings remain source-oriented.",
                            "pan_poe": "PoE settings remain source-oriented."}
    issues.extend(message for key, message in source_only_physical.items() if attrs.get(key))
    if attrs.get("pan_unknown_layer3_fields") or attrs.get("pan_unknown_physical_fields") or attrs.get("pan_unknown_fields") or attrs.get("pan_sdwan_unknown_fields"):
        issues.append("Unknown interface fields were retained.")
    if attrs.get("pan_link_state_invalid"):
        issues.append("Invalid interface link-state was retained without applying a source default.")
    if attrs.get("pan_mtu_invalid"):
        issues.append("Invalid interface MTU was retained without applying a source default.")
    if attrs.get("pan_vlan_tag_invalid"):
        issues.append("Invalid interface VLAN tag was retained without applying a source default.")
    return issues


def _build_source_interface(name: str, interface_type: str, attrs: Dict[str, Any], *,
                            parent: Optional[str] = None, members: Optional[list[str]] = None) -> IRInterface:
    link_state = attrs.get("pan_link_state")
    status_kwargs = {"status": link_state != "down"} if link_state in {"auto", "up", "down"} else {}
    if link_state is not None and link_state not in {"auto", "up", "down"}:
        attrs["pan_link_state_invalid"] = True
    attrs["status_explicit"] = link_state is not None
    tag_text = attrs.get("pan_vlan_tag")
    vlanid = int(tag_text) if isinstance(tag_text, str) and tag_text.isdigit() else None
    if tag_text is not None and vlanid is None:
        attrs["pan_vlan_tag_invalid"] = True
    netflow = attrs.get("pan_netflow_profile") or attrs.get("pan_layer2_netflow_profile") or attrs.get("pan_virtual_wire_netflow_profile") or attrs.get("pan_tap_netflow_profile")
    lldp_enabled = attrs.get("pan_layer2_lldp_enabled") or attrs.get("pan_virtual_wire_lldp_enabled") or attrs.get("pan_lldp_enabled")
    return IRInterface(name=name, description=attrs.get("pan_comment"), management_profile=attrs.get("pan_management_profile"),
                       parent=parent, vlanid=vlanid, interface_type=interface_type, members=list(members or []),
                       source_mtu=_normalized_mtu(attrs), source_link_state=attrs.get("pan_link_state"),
                       source_speed=attrs.get("pan_speed"), source_duplex=attrs.get("pan_duplex"),
                       source_netflow_profile=netflow, source_lldp_enabled=lldp_enabled, source_attributes=attrs,
                       requires_manual_review=True, migration_status="PARTIALLY_NORMALIZED",
                       review_reasons=["pan-interface-mode-source-only"], **status_kwargs)


def _register_interface(ir, resolver, scope: PANScope, interface: IRInterface, attrs: Dict[str, Any], path: str, extraction) -> None:
    if scope.device_serial:
        attrs["pan_device_serial"] = scope.device_serial
    if scope.template_stack:
        attrs["pan_template_stack"] = scope.template_stack
        attrs["pan_template_provenance"] = scope.template_provenance
    _sanitize_attrs(attrs)
    interface.source_attributes = dict(attrs)
    interface.source_context = f"{scope.kind}:{scope.name}:device:{scope.device_serial}" if scope.device_serial else f"{scope.kind}:{scope.name}"
    ir.interfaces.append(interface)
    resolver.register_object(PANSourceObject(name=interface.name, kind="interface", domain="interface", source_path=path,
                                             scope=scope, attributes=attrs, ir_object=interface), "interface")
    issues = _issues(attrs)
    interface.requires_manual_review = interface.requires_manual_review or bool(issues)
    if issues:
        interface.migration_status = "PARTIALLY_NORMALIZED"
        if "pan-interface-source-semantics" not in interface.review_reasons:
            interface.review_reasons.append("pan-interface-source-semantics")
        record_partial(extraction, "interfaces", path, scope, interface.name, attrs, notes=issues)
    else:
        record_normalized(extraction, "interfaces", path, scope, interface.name, attrs)


def _record_source_only(extraction, scope: PANScope, path: str, name: Optional[str], attrs: Dict[str, Any]) -> None:
    _sanitize_attrs(attrs)
    if not name:
        record_parse_error(extraction, "interfaces", path, scope, None, attrs,
                           notes=["PAN-OS interface is missing its required name."])
        return
    record_extract_only(extraction, "interfaces", path, scope, name, attrs,
                        notes=[f"PAN-OS {attrs.get('pan_interface_mode')} interface semantics retained as source-only evidence."],
                        requires_manual_review=True)


def _append_relationship(interface: IRInterface, key: str, value: Any) -> None:
    values = interface.source_attributes.setdefault(key, [])
    if value not in values:
        values.append(value)


def _virtual_wire_bool(entry: ET.Element, paths: tuple[str, ...], reasons: list[str]) -> Optional[bool]:
    for path in paths:
        node = entry.find(path)
        if node is None:
            continue
        value = text_or_none(entry, path)
        if value in {"yes", "no"}:
            return value == "yes"
        reasons.append(f"{path} must be yes or no, found {value!r}")
        return None
    return None


def _virtual_wire_scope(scope: PANScope) -> PANScope:
    if scope.kind == "vsys":
        return PANScope(kind="device", name=scope.device_name or scope.name,
                        device_name=scope.device_name, device_serial=scope.device_serial)
    return scope


def extract_virtual_wires(network_root: ET.Element, scope: PANScope, ir, resolver, extraction) -> None:
    for entry in network_root.findall("./virtual-wire/entry"):
        name = entry.get("name")
        path = f"network/virtual-wire/entry[@name='{name}']" if name else "network/virtual-wire/entry"
        attrs = sanitize_source_attributes({
            "pan_source_entry": structured_xml_capture(entry),
            "pan_source_context": pan_scope_identity(scope),
        })
        if not name:
            record_parse_error(extraction, "virtual_wires", path, scope, attributes=attrs,
                               notes=["PAN-OS virtual-wire is missing its required name."])
            continue
        interface1 = text_or_none(entry, "./interface1")
        interface2 = text_or_none(entry, "./interface2")
        reasons: list[str] = []
        source_scope = _virtual_wire_scope(scope)
        resolved: list[str] = []
        unresolved: list[str] = []
        resolved_inputs: set[str] = set()
        for interface in (interface1, interface2):
            if not interface:
                continue
            obj = resolver.resolve(interface, "interface", source_scope)
            if obj:
                resolved.append(obj.canonical_name or interface)
                resolved_inputs.add(interface)
            else:
                unresolved.append(interface)
                reasons.append(f"unresolved-interface:{interface}")
        tag_allowed = _virtual_wire_bool(entry, ("./tag-allowed", "./tag-control"), reasons)
        multicast = _virtual_wire_bool(entry, ("./multicast-firewalling", "./multicast"), reasons)
        link_state = _virtual_wire_bool(entry, ("./link-state-pass-through", "./link-state"), reasons)
        attrs.update({
            "pan_interface1": interface1,
            "pan_interface2": interface2,
            "pan_resolved_interfaces": resolved,
            "pan_unresolved_interfaces": unresolved,
            "pan_tag_allowed": tag_allowed,
            "pan_multicast_firewalling": multicast,
            "pan_link_state_pass_through": link_state,
        })
        unknown = collect_unknown_children(entry, [
            "interface1", "interface2", "tag-allowed", "tag-control",
            "multicast-firewalling", "multicast", "link-state-pass-through",
            "link-state", "vsys",
        ])
        if unknown:
            attrs["pan_unknown_fields"] = unknown
            reasons.append("unknown-fields")
        if scope.template_stack:
            attrs.update({
                "pan_template_stack": scope.template_stack,
                "pan_template_provenance": scope.template_provenance,
            })
        item = IRPANVirtualWire(
            name=name, source_context=pan_scope_identity(scope),
            interface1=interface1, interface2=interface2,
            interface1_resolved=(interface1 in resolved_inputs) if interface1 else None,
            interface2_resolved=(interface2 in resolved_inputs) if interface2 else None,
            resolved_interfaces=resolved, unresolved_interfaces=unresolved,
            tag_allowed=tag_allowed, multicast_firewalling=multicast,
            link_state_pass_through=link_state,
            migration_status="PARTIALLY_NORMALIZED" if reasons else "EXTRACT_ONLY",
            requires_manual_review=True, review_reasons=list(dict.fromkeys(reasons)),
            source_attributes=attrs,
        )
        registered = resolver.register_object(
            PANSourceObject(name=name, kind="virtual-wire", domain="virtual_wires",
                            source_path=path, scope=scope, attributes=attrs, ir_object=item),
            "virtual-wire",
        )
        if not registered:
            item.review_reasons.append("duplicate-virtual-wire")
            record_parse_error(extraction, "virtual_wires", path, scope, name, attrs,
                               ["Duplicate PAN-OS virtual-wire in the same scope."])
            continue
        ir.pan_virtual_wires.append(item)
        record_extract_only(
            extraction, "virtual_wires", path, scope, name, attrs,
            ["PAN-OS virtual-wire is retained as typed source-only inventory.", *reasons],
            requires_manual_review=True,
        )


def _annotate_network_interface_relationships(network_root: ET.Element, scope: PANScope, ir, extraction) -> None:
    for vlan in network_root.findall("./vlan/entry"):
        vlan_name = vlan.get("name")
        if not vlan_name:
            continue
        for member in member_texts(vlan, "./interface/member"):
            for interface in _interfaces_in_scope(ir, scope, member):
                _append_relationship(interface, "pan_layer2_vlans", vlan_name)
                _update_interface_inventory(extraction, scope, member,
                                            {"pan_layer2_vlans": list(interface.source_attributes["pan_layer2_vlans"])})
        virtual_interface = text_or_none(vlan, "./virtual-interface/interface")
        if virtual_interface:
            for interface in _interfaces_in_scope(ir, scope, virtual_interface):
                _append_relationship(interface, "pan_vlan_virtual_interface_for", vlan_name)
                _update_interface_inventory(extraction, scope, virtual_interface,
                                            {"pan_vlan_virtual_interface_for": list(interface.source_attributes["pan_vlan_virtual_interface_for"])})
    for virtual_wire in network_root.findall("./virtual-wire/entry"):
        vwire_name = virtual_wire.get("name")
        if not vwire_name:
            continue
        for role in ("interface1", "interface2"):
            member = text_or_none(virtual_wire, f"./{role}")
            if not member:
                continue
            relationship = {"name": vwire_name, "role": role}
            for interface in _interfaces_in_scope(ir, scope, member):
                _append_relationship(interface, "pan_virtual_wires", relationship)
                _update_interface_inventory(extraction, scope, member,
                                            {"pan_virtual_wires": list(interface.source_attributes["pan_virtual_wires"])})


def extract_interfaces(network_root: ET.Element, scope: PANScope, ir, resolver, extraction) -> None:
    root = network_root.find("./interface")
    if root is None:
        extract_virtual_wires(network_root, scope, ir, resolver, extraction)
        return
    physical_parsers = {"ethernet": parse_ethernet_interface, "aggregate-ethernet": parse_aggregate_ethernet_interface}
    mode_parsers = {"layer2": parse_layer2_interface, "virtual-wire": parse_virtual_wire_interface,
                    "tap": parse_tap_interface, "ha": parse_ha_interface, "decrypt-mirror": parse_decrypt_mirror_interface}
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
                attrs.update({"pan_interface_mode": "unconfigured", "pan_interface_family": family,
                              "pan_source_only_interface_semantics": True})
                interface = _build_source_interface(name, family, attrs)
                _register_interface(ir, resolver, scope, interface, attrs, base, extraction)
            layer3 = entry.find("./layer3")
            if layer3 is not None:
                interface, attrs = parse_layer3_interface(layer3, name, family, physical_node=entry)
                attrs["pan_interface_family"] = family
                _register_interface(ir, resolver, scope, interface, attrs, f"{base}/layer3", extraction)
                for unit in parse_subinterfaces(layer3):
                    unit_name = unit.get("name")
                    path = f"{base}/layer3/units/entry[@name='{unit_name}']"
                    if not unit_name:
                        _record_source_only(extraction, scope, path, None,
                                            {"pan_source_entry": structured_xml_capture(unit), "pan_interface_mode": "layer3-subinterface"})
                        continue
                    sub, sub_attrs = parse_layer3_interface(unit, unit_name, f"{family}-subinterface", parent=name)
                    sub_attrs.update({"pan_interface_family": family, "pan_interface_unit_name": unit_name,
                                      "pan_interface_unit_type": "layer3-subinterface"})
                    _register_interface(ir, resolver, scope, sub, sub_attrs, path, extraction)
            for mode, parser in mode_parsers.items():
                mode_node = entry.find(f"./{mode}")
                if mode_node is None:
                    continue
                attrs = parser(mode_node, name, parent=None, physical_node=entry)
                attrs["pan_mode_source_entry"] = structured_xml_capture(mode_node)
                physical_attrs = physical_parser(entry, name)
                for key, value in physical_attrs.items():
                    attrs.setdefault(key, value)
                attrs.update({"pan_interface_mode": mode, "pan_interface_family": family,
                              "pan_source_only_interface_semantics": True})
                interface = _build_source_interface(name, family, attrs)
                _register_interface(ir, resolver, scope, interface, attrs, f"{base}/{mode}", extraction)
                if mode == "layer2":
                    for unit in parse_subinterfaces(mode_node):
                        unit_name = unit.get("name")
                        unit_attrs = parse_layer2_interface(unit, unit_name or "", parent=name)
                        unit_attrs.update({"pan_interface_mode": "layer2-subinterface", "pan_interface_family": family,
                                           "pan_interface_unit_name": unit_name, "pan_interface_unit_type": "layer2-subinterface",
                                           "pan_source_only_interface_semantics": True})
                        path = f"{base}/layer2/units/entry[@name='{unit_name}']"
                        if not unit_name:
                            _record_source_only(extraction, scope, path, None, unit_attrs)
                            continue
                        sub = _build_source_interface(unit_name, f"{family}-subinterface", unit_attrs, parent=name)
                        _register_interface(ir, resolver, scope, sub, unit_attrs, path, extraction)
                if mode == "virtual-wire":
                    for unit in parse_subinterfaces(mode_node):
                        unit_name = unit.get("name")
                        path = f"{base}/virtual-wire/units/entry[@name='{unit_name}']"
                        unit_attrs = parse_virtual_wire_subinterface(unit, unit_name or "", name)
                        unit_attrs.update({"pan_interface_family": family, "pan_interface_unit_name": unit_name,
                                           "pan_interface_unit_type": "virtual-wire-subinterface",
                                           "pan_source_only_interface_semantics": True})
                        if not unit_name:
                            _record_source_only(extraction, scope, path, None, unit_attrs)
                            continue
                        sub = _build_source_interface(unit_name, f"{family}-subinterface", unit_attrs, parent=name)
                        _register_interface(ir, resolver, scope, sub, unit_attrs, path, extraction)
    logical = {"loopback": parse_loopback_interface, "tunnel": parse_tunnel_interface, "vlan": parse_vlan_interface}
    for family, parser in logical.items():
        unit_entries = root.findall(f"./{family}/units/entry")
        entries = list(unit_entries)
        entries.extend(entry for entry in root.findall(f"./{family}/entry") if entry not in entries)
        for entry in entries:
            name = entry.get("name")
            is_unit = entry in unit_entries
            path = f"network/interface/{family}/units/entry[@name='{name}']" if is_unit else f"network/interface/{family}/entry[@name='{name}']"
            if not name:
                _record_source_only(extraction, scope, path, None,
                                    {"pan_source_entry": structured_xml_capture(entry), "pan_interface_mode": family})
                continue
            interface, attrs = parser(entry, name)
            attrs["pan_interface_family"] = family
            if is_unit:
                attrs["pan_interface_unit_name"] = name
            _register_interface(ir, resolver, scope, interface, attrs, path, extraction)
    sdwan_root = root.find("./sdwan")
    if sdwan_root is not None:
        for entry in sdwan_root.findall("./units/entry"):
            name = entry.get("name")
            path = f"network/interface/sdwan/units/entry[@name='{name}']"
            link_tags = member_texts(entry, "./link-tag/member")
            scalar_link_tag = text_or_none(entry, "./link-tag")
            if not link_tags and scalar_link_tag:
                link_tags = [scalar_link_tag]
            interface_members_list = member_texts(entry, "./interface/member")
            protocol = text_or_none(entry, "./protocol")
            unknown = collect_unknown_children(entry, ["comment", "cluster-name", "link-tag", "interface"])
            attrs = {"pan_interface_mode": "sdwan-unit", "pan_interface_family": "sdwan",
                     "pan_interface_unit_name": name, "pan_comment": text_or_none(entry, "./comment"),
                     "pan_sdwan_interface_members": interface_members_list, "pan_sdwan_link_tags": link_tags,
                     "pan_sdwan_link_tag": link_tags[0] if len(link_tags) == 1 else None,
                     "pan_sdwan_cluster_name": text_or_none(entry, "./cluster-name"), "pan_sdwan_protocol": protocol,
                     "pan_sdwan_unknown_fields": unknown or None, "pan_source_entry": structured_xml_capture(entry),
                     "pan_source_only_interface_semantics": True}
            attrs = {key: value for key, value in attrs.items() if value is not None}
            if not name:
                _record_source_only(extraction, scope, path, None, attrs)
                continue
            interface = _build_source_interface(name, "sdwan", attrs, members=interface_members_list)
            _register_interface(ir, resolver, scope, interface, attrs, path, extraction)
    extract_virtual_wires(network_root, scope, ir, resolver, extraction)
    _annotate_network_interface_relationships(network_root, scope, ir, extraction)


def _routing_instance_evidence(instance: PANRoutingInstance) -> Dict[str, Any]:
    evidence = {"pan_routing_instance_name": instance.display_name, "pan_routing_instance_type": instance.instance_type,
                "pan_virtual_router": instance.virtual_router_name, "pan_logical_router": instance.logical_router_name,
                "pan_vrf": instance.vrf_name, "pan_routing_instance_source_path": instance.source_path}
    return {key: value for key, value in evidence.items() if value is not None}


def _scope_context(scope: PANScope) -> str:
    return f"{scope.kind}:{scope.name}:device:{scope.device_serial}" if scope.device_serial else f"{scope.kind}:{scope.name}"


def _interfaces_in_scope(ir, scope: PANScope, name: str) -> list[IRInterface]:
    candidates = [interface for interface in ir.interfaces if interface.name == name]
    if not candidates:
        return []
    context = _scope_context(scope)
    scoped = [interface for interface in candidates if interface.source_context == context or
              (scope.device_serial and interface.source_attributes.get("pan_device_serial") == scope.device_serial)]
    if scoped:
        return scoped
    return candidates if len(candidates) == 1 else []


def _inventory_item_in_scope(item, scope: PANScope) -> bool:
    context = _scope_context(scope)
    if item.source_context == context:
        return True
    attrs = item.source_attributes
    return bool(scope.device_serial and attrs.get("scope_device_serial") == scope.device_serial)


def _update_interface_inventory(extraction, scope: PANScope, name: str, evidence: Dict[str, Any], *,
                                conflict_names: Optional[list[str]] = None) -> None:
    for item in extraction.inventory_items:
        if item.domain != "interfaces" or item.name != name:
            continue
        if not _inventory_item_in_scope(item, scope):
            continue
        item.source_attributes.update(sanitize_source_attributes(evidence))
        if conflict_names:
            item.status = ExtractionStatus.PARTIALLY_NORMALIZED
            item.requires_manual_review = True
            note = "PAN-OS interface is assigned to multiple routing instances: " + ", ".join(conflict_names) + "."
            if note not in item.notes:
                item.notes.append(note)


def apply_routing_instance_associations(network_root: ET.Element, scope: PANScope, ir, extraction) -> None:
    assignments: Dict[str, list[PANRoutingInstance]] = {}
    seen_assignments: Dict[str, set[tuple[Any, ...]]] = {}
    discovered_instances: list[tuple[PANRoutingInstance, list[str]]] = []
    for instance in discover_routing_instances(network_root):
        members = interface_members(instance)
        if not members:
            continue
        discovered_instances.append((instance, members))
        for name in members:
            identity = (instance.instance_type, instance.virtual_router_name, instance.logical_router_name,
                        instance.vrf_name, instance.source_path)
            if identity in seen_assignments.setdefault(name, set()):
                continue
            seen_assignments[name].add(identity)
            assignments.setdefault(name, []).append(instance)
    for name, instances in assignments.items():
        interfaces = _interfaces_in_scope(ir, scope, name)
        if not interfaces:
            continue
        if len(instances) > 1:
            conflict_names = [instance.display_name for instance in instances]
            evidence = {"pan_routing_instance_conflicts": conflict_names,
                        "pan_routing_instance_conflict_details": [_routing_instance_evidence(instance) for instance in instances]}
            for interface in interfaces:
                interface.source_routing_instance = None
                interface.source_routing_instance_type = None
                interface.source_attributes.update(evidence)
                interface.requires_manual_review = True
                interface.migration_status = "PARTIALLY_NORMALIZED"
                if "routing-instance-conflict" not in interface.review_reasons:
                    interface.review_reasons.append("routing-instance-conflict")
                _update_interface_inventory(extraction, scope, name, evidence, conflict_names=conflict_names)
            continue
        instance = instances[0]
        evidence = _routing_instance_evidence(instance)
        for interface in interfaces:
            interface.source_routing_instance = instance.display_name
            interface.source_routing_instance_type = instance.instance_type
            interface.source_attributes.update(evidence)
            _update_interface_inventory(extraction, scope, name, evidence)
    for instance, members in discovered_instances:
        unresolved = [name for name in members if not _interfaces_in_scope(ir, scope, name)]
        if not unresolved:
            continue
        evidence = _routing_instance_evidence(instance)
        evidence.update({"pan_interface_members": members, "pan_unresolved_interface_members": unresolved,
                         "pan_source_path": f"{instance.source_path}/interface/member" if instance.source_path else "network/routing-instance/interface/member"})
        record_partial(extraction, "routing_instances", evidence["pan_source_path"], scope, instance.display_name, evidence,
                       notes=["PAN-OS routing-instance member interfaces were not extracted: " + ", ".join(unresolved) + "."])
