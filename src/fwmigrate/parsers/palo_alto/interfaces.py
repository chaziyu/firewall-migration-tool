"""PAN-OS physical, logical, and mode-specific interface extraction."""

from __future__ import annotations

from typing import Any, Dict, Iterable, Optional, Tuple
import xml.etree.ElementTree as ET

from fwmigrate.ir.core import IRInterface
from fwmigrate.extraction.models import ExtractionStatus

from .extraction import record_extract_only, record_normalized, record_partial, record_parse_error
from .routing_instances import PANRoutingInstance, discover_routing_instances, interface_members
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
        captured_lldp = structured_xml_capture(lldp)
        attrs["pan_lldp"] = captured_lldp
        if physical_node is not None:
            attrs["pan_physical_lldp"] = captured_lldp
    return {key: value for key, value in attrs.items() if value is not None}


def _normalized_mtu(attrs: Dict[str, Any]) -> Optional[int]:
    """Return a numeric PAN-OS MTU without replacing malformed source evidence."""
    value = attrs.get("pan_mtu")
    if value is None:
        return None
    if isinstance(value, str) and value.isdigit():
        return int(value)
    attrs["pan_mtu_invalid"] = True
    return None


def _explicit_lldp_state(node: Optional[ET.Element]) -> Optional[str]:
    """Return a clear PAN-OS LLDP enable state, if one is explicitly set."""
    if node is None:
        return None
    value = text_or_none(node, "./enable")
    normalized = value.lower() if value is not None else None
    return normalized if normalized in {"yes", "no"} else None


def parse_layer3_interface(
    config_node: ET.Element,
    interface_name: str,
    interface_type: str,
    parent: Optional[str] = None,
    physical_node: Optional[ET.Element] = None,
) -> Tuple[IRInterface, Dict[str, Any]]:
    attrs = _source_fields(config_node, physical_node)
    attrs.update({"pan_interface_mode": "layer3", "pan_parent_interface": parent})
    lldp = config_node.find("./lldp")
    if lldp is not None:
        captured_lldp = structured_xml_capture(lldp)
        attrs["pan_layer3_lldp"] = captured_lldp
        # Keep the legacy key useful for Layer3-only configurations.  When a
        # physical LLDP subtree exists, pan_lldp retains its existing physical
        # value and the two locations remain available under distinct keys.
        if physical_node is None or "pan_physical_lldp" not in attrs:
            attrs["pan_lldp"] = captured_lldp
    netflow_profile = text_or_none(config_node, "./netflow-profile")
    if netflow_profile is not None:
        attrs["pan_netflow_profile"] = netflow_profile
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
        ndp_proxy_enabled = text_or_none(ndp_proxy, "./enabled")
        ndp_proxy_legacy_enabled = text_or_none(ndp_proxy, "./enable")
        attrs["pan_ndp_proxy_enabled"] = (
            ndp_proxy_enabled if ndp_proxy_enabled is not None else ndp_proxy_legacy_enabled
        )
        if (
            ndp_proxy_enabled is not None
            and ndp_proxy_legacy_enabled is not None
            and ndp_proxy_enabled != ndp_proxy_legacy_enabled
        ):
            attrs["pan_ndp_proxy_enable_conflict"] = {
                "enabled": ndp_proxy_enabled,
                "enable": ndp_proxy_legacy_enabled,
            }
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
                      "pppoe", "tag", "units", "link-state", "mtu", "adjust-tcp-mss", "ndp-proxy",
                      "lldp", "netflow-profile"])
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
    source_mtu = _normalized_mtu(attrs)
    # A Layer3 override is authoritative when present. Otherwise the
    # physical interface LLDP state is the effective setting for the
    # extracted Layer3 interface.
    physical_lldp = physical_node.find("./lldp") if physical_node is not None else None
    source_lldp_enabled = (
        _explicit_lldp_state(lldp)
        if lldp is not None
        else _explicit_lldp_state(physical_lldp)
    )
    addressing_mode = "dhcp-client" if dhcp is not None else "pppoe" if pppoe is not None else "static" if ipv4 else None
    interface = IRInterface(
        name=interface_name, source_context=None, ip=ipv4[0] if ipv4 else None,
        description=attrs.get("pan_comment"), management_profile=attrs.get("pan_management_profile"),
        parent=parent, vlanid=tag, interface_type=interface_type,
        addressing_mode=addressing_mode, source_mtu=source_mtu,
        source_link_state=attrs.get("pan_link_state"), source_speed=attrs.get("pan_speed"),
        source_duplex=attrs.get("pan_duplex"),
        source_netflow_profile=attrs.get("pan_netflow_profile"),
        source_lldp_enabled=source_lldp_enabled,
        source_attributes=attrs, **status_kwargs,
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
    if attrs.get("pan_netflow_profile"):
        issues.append("Layer3 NetFlow profile remains source-only.")
    if attrs.get("pan_layer3_lldp"):
        issues.append("Layer3 LLDP settings remain source-only.")
    if attrs.get("pan_ndp_proxy_enable_conflict"):
        issues.append("NDP proxy enabled and enable values conflict; enabled is used as the effective value.")
    source_only_physical = {
        "pan_aggregate_group": "Aggregate-group semantics remain source-only.",
        "pan_lacp": "LACP settings remain source-only.",
        "pan_fec": "FEC settings remain source-only.",
        "pan_poe": "PoE settings remain source-only.",
    }
    issues.extend(message for key, message in source_only_physical.items() if attrs.get(key))
    if attrs.get("pan_unknown_layer3_fields") or attrs.get("pan_unknown_physical_fields"):
        issues.append("Unknown interface fields were retained.")
    if attrs.get("pan_link_state_invalid"):
        issues.append("Invalid interface link-state was retained without applying a source default.")
    if attrs.get("pan_mtu_invalid"):
        issues.append("Invalid interface MTU was retained without applying a source default.")
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


def _routing_instance_evidence(instance: PANRoutingInstance) -> Dict[str, Any]:
    evidence = {
        "pan_routing_instance_name": instance.display_name,
        "pan_routing_instance_type": instance.instance_type,
        "pan_virtual_router": instance.virtual_router_name,
        "pan_logical_router": instance.logical_router_name,
        "pan_vrf": instance.vrf_name,
        "pan_routing_instance_source_path": instance.source_path,
    }
    return {key: value for key, value in evidence.items() if value is not None}


def _scope_context(scope: PANScope) -> str:
    return (
        f"{scope.kind}:{scope.name}:device:{scope.device_serial}"
        if scope.device_serial else f"{scope.kind}:{scope.name}"
    )


def _interfaces_in_scope(ir, scope: PANScope, name: str) -> list[IRInterface]:
    candidates = [interface for interface in ir.interfaces if interface.name == name]
    if not candidates:
        return []

    context = _scope_context(scope)
    scoped = [
        interface for interface in candidates
        if interface.source_context == context
        or (
            scope.device_serial
            and interface.source_attributes.get("pan_device_serial") == scope.device_serial
        )
    ]
    if scoped:
        return scoped
    return candidates if len(candidates) == 1 else []


def _inventory_item_in_scope(item, scope: PANScope) -> bool:
    context = _scope_context(scope)
    if item.source_context == context:
        return True
    attrs = item.source_attributes
    return bool(
        scope.device_serial
        and attrs.get("scope_device_serial") == scope.device_serial
    )


def _update_interface_inventory(
    extraction,
    scope: PANScope,
    name: str,
    evidence: Dict[str, Any],
    *,
    conflict_names: Optional[list[str]] = None,
) -> None:
    for item in extraction.inventory_items:
        if item.domain != "interfaces" or item.name != name:
            continue
        if not _inventory_item_in_scope(item, scope):
            continue
        item.source_attributes.update(evidence)
        if conflict_names:
            item.status = ExtractionStatus.PARTIALLY_NORMALIZED
            item.requires_manual_review = True
            note = (
                "PAN-OS interface is assigned to multiple routing instances: "
                + ", ".join(conflict_names)
                + "."
            )
            if note not in item.notes:
                item.notes.append(note)


def apply_routing_instance_associations(network_root: ET.Element, scope: PANScope, ir, extraction) -> None:
    """Associate extracted PAN-OS interfaces with their routing instances."""
    assignments: Dict[str, list[PANRoutingInstance]] = {}
    seen_assignments: Dict[str, set[tuple[Any, ...]]] = {}
    discovered_instances: list[tuple[PANRoutingInstance, list[str]]] = []
    for instance in discover_routing_instances(network_root):
        members = interface_members(instance)
        if not members:
            continue
        discovered_instances.append((instance, members))
        for name in members:
            identity = (
                instance.instance_type,
                instance.virtual_router_name,
                instance.logical_router_name,
                instance.vrf_name,
                instance.source_path,
            )
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
            evidence = {
                "pan_routing_instance_conflicts": conflict_names,
                "pan_routing_instance_conflict_details": [
                    _routing_instance_evidence(instance) for instance in instances
                ],
            }
            for interface in interfaces:
                interface.source_routing_instance = None
                interface.source_routing_instance_type = None
                interface.source_attributes.update(evidence)
                interface.requires_manual_review = True
                interface.migration_status = "PARTIALLY_NORMALIZED"
                if "routing-instance-conflict" not in interface.review_reasons:
                    interface.review_reasons.append("routing-instance-conflict")
                _update_interface_inventory(
                    extraction,
                    scope,
                    name,
                    evidence,
                    conflict_names=conflict_names,
                )
            continue

        instance = instances[0]
        evidence = _routing_instance_evidence(instance)
        for interface in interfaces:
            interface.source_routing_instance = instance.display_name
            interface.source_routing_instance_type = instance.instance_type
            interface.source_attributes.update(evidence)
            _update_interface_inventory(extraction, scope, name, evidence)

    for instance, members in discovered_instances:
        unresolved = [
            name for name in members
            if not _interfaces_in_scope(ir, scope, name)
        ]
        if not unresolved:
            continue
        evidence = _routing_instance_evidence(instance)
        evidence.update({
            "pan_interface_members": members,
            "pan_unresolved_interface_members": unresolved,
            "pan_source_path": (
                f"{instance.source_path}/interface/member"
                if instance.source_path else "network/routing-instance/interface/member"
            ),
        })
        record_partial(
            extraction,
            "routing_instances",
            evidence["pan_source_path"],
            scope,
            instance.display_name,
            evidence,
            notes=[
                "PAN-OS routing-instance member interfaces were not extracted: "
                + ", ".join(unresolved)
                + "."
            ],
        )
