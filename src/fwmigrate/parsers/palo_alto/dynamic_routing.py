"""Structured source-only extraction for PAN-OS dynamic routing."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional
import xml.etree.ElementTree as ET

from fwmigrate.extraction.models import ExtractionStatus

from .extraction import add_source_section, record_extract_only, record_parse_error, record_unsupported
from .source_model import PANScope
from .routing_instances import PANRoutingInstance, discover_routing_instances
from .xml_utils import collect_unknown_children, member_texts, structured_xml_capture, text_or_none


def _enabled(node: ET.Element, path: str = "./enable") -> Optional[bool]:
    value = text_or_none(node, path)
    if value is None:
        return None
    return value.lower() == "yes"


def _integer(node: ET.Element, path: str) -> Optional[int]:
    value = text_or_none(node, path)
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _common(instance: PANRoutingInstance, protocol: str) -> Dict[str, Any]:
    return {
        **instance.context_attributes,
        "protocol_name": protocol,
    }


@dataclass
class PANBGPPeer:
    name: str
    peer_group: str
    peer_as: Optional[str] = None
    peer_address: Optional[str] = None
    local_address: Optional[str] = None
    interface: Optional[str] = None
    enabled: Optional[bool] = None
    authentication_profile: Optional[str] = None
    bfd_profile: Optional[str] = None
    peer_type: Optional[str] = None
    connection_options: Dict[str, Any] = field(default_factory=dict)
    address_families: Dict[str, Any] = field(default_factory=dict)
    import_policy: List[str] = field(default_factory=list)
    export_policy: List[str] = field(default_factory=list)
    timers: Dict[str, Any] = field(default_factory=dict)
    unknown_fields: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PANBGPPeerGroup:
    name: str
    enabled: Optional[bool] = None
    peer_as: Optional[str] = None
    authentication_profile: Optional[str] = None
    bfd_profile: Optional[str] = None
    peer_type: Optional[str] = None
    connection_options: Dict[str, Any] = field(default_factory=dict)
    address_families: Dict[str, Any] = field(default_factory=dict)
    import_policy: List[str] = field(default_factory=list)
    export_policy: List[str] = field(default_factory=list)
    peers: List[str] = field(default_factory=list)
    unknown_fields: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PANBGPConfig:
    router_id: Optional[str] = None
    as_number: Optional[str] = None
    enabled: Optional[bool] = None
    authentication_profile: Optional[str] = None
    bfd_profile: Optional[str] = None
    import_policy: List[str] = field(default_factory=list)
    export_policy: List[str] = field(default_factory=list)
    redistribution_profile_references: List[str] = field(default_factory=list)
    routing_profile_references: List[str] = field(default_factory=list)
    timers: Dict[str, Any] = field(default_factory=dict)
    address_families: Dict[str, Any] = field(default_factory=dict)
    aggregate_routes: Dict[str, Any] = field(default_factory=dict)
    advertised_networks: Dict[str, Any] = field(default_factory=dict)
    graceful_restart: Dict[str, Any] = field(default_factory=dict)
    routing_options: Dict[str, Any] = field(default_factory=dict)
    unknown_fields: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PANOSPFInterface:
    name: str
    enabled: Optional[bool] = None
    cost: Optional[int] = None
    priority: Optional[int] = None
    passive: Optional[bool] = None
    network_type: Optional[str] = None
    authentication_profile: Optional[str] = None
    bfd_profile: Optional[str] = None
    timers: Dict[str, Any] = field(default_factory=dict)
    authentication: Dict[str, Any] = field(default_factory=dict)
    unknown_fields: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PANOSPFArea:
    area_id: str
    area_type: Optional[str] = None
    interfaces: List[str] = field(default_factory=list)
    ranges: Dict[str, Any] = field(default_factory=dict)
    virtual_links: Dict[str, Any] = field(default_factory=dict)
    stub: Dict[str, Any] = field(default_factory=dict)
    nssa: Dict[str, Any] = field(default_factory=dict)
    unknown_fields: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PANOSPFConfig:
    router_id: Optional[str] = None
    enabled: Optional[bool] = None
    bfd_profile: Optional[str] = None
    redistribution_profile_references: List[str] = field(default_factory=list)
    graceful_restart: Dict[str, Any] = field(default_factory=dict)
    default_route: Optional[str] = None
    filter_lists: Dict[str, Any] = field(default_factory=dict)
    routing_options: Dict[str, Any] = field(default_factory=dict)
    routing_profile_references: List[str] = field(default_factory=list)
    unknown_fields: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PANOSPFv3Config(PANOSPFConfig):
    pass


@dataclass
class PANRIPConfig:
    enabled: Optional[bool] = None
    interfaces: List[str] = field(default_factory=list)
    timers: Dict[str, Any] = field(default_factory=dict)
    redistribution_profile_references: List[str] = field(default_factory=list)
    authentication: Dict[str, Any] = field(default_factory=dict)
    bfd: Dict[str, Any] = field(default_factory=dict)
    routing_options: Dict[str, Any] = field(default_factory=dict)
    routing_profile_references: List[str] = field(default_factory=list)
    unknown_fields: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PANRedistributionProfile:
    name: str
    priority: Optional[int] = None
    action: Optional[str] = None
    filter: Dict[str, Any] = field(default_factory=dict)
    protocol_references: List[str] = field(default_factory=list)
    destination_protocol: Optional[str] = None
    metric: Optional[int] = None
    source_protocol: Optional[str] = None
    routing_profile_references: List[str] = field(default_factory=list)
    unknown_fields: Dict[str, Any] = field(default_factory=dict)


def _record(extraction, domain: str, path: str, scope: PANScope, name: str,
            instance: Dict[str, Any], model: Any, node: ET.Element) -> None:
    attributes = {**instance, **asdict(model), "pan_source_entry": structured_xml_capture(node)}
    record_extract_only(
        extraction, domain, path, scope, name, attributes,
        notes=["PAN-OS dynamic-routing configuration retained as structured source-only evidence."],
        requires_manual_review=True,
    )


def _policy_names(node: ET.Element, path: str) -> List[str]:
    values = member_texts(node, f"{path}/member")
    if values:
        return values
    return [entry.get("name") for entry in node.findall(f"{path}/entry") if entry.get("name")]


def _timers(node: ET.Element) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for name in ("keep-alive-interval", "hold-time", "idle-hold-time", "open-delay-time",
                 "min-route-adv-interval", "graceful-restart", "spf-calculation-delay",
                 "lsa-interval", "timers", "update-interval", "expire-interval",
                 "delete-interval", "connection-options"):
        child = node.find(f"./{name}")
        if child is not None:
            result[name] = structured_xml_capture(child)
    return result


def _structured(node: ET.Element, path: str) -> Dict[str, Any]:
    return structured_xml_capture(node.find(path)) or {}


def _parse_bgp(protocol: ET.Element, base: str, scope: PANScope, extraction,
               instance: Dict[str, Any], protocol_tag: str = "protocol") -> int:
    bgp = protocol.find("./bgp")
    if bgp is None:
        return 0
    config = PANBGPConfig(
        router_id=text_or_none(bgp, "./router-id"), as_number=text_or_none(bgp, "./local-as"),
        enabled=_enabled(bgp), authentication_profile=text_or_none(bgp, "./auth-profile"),
        bfd_profile=text_or_none(bgp, "./bfd/profile"),
        import_policy=_policy_names(bgp, "./policy/import/rules"),
        export_policy=_policy_names(bgp, "./policy/export/rules"),
        redistribution_profile_references=_policy_names(bgp, "./redist-rules"),
        routing_profile_references=_policy_names(bgp, "./routing-profile"),
        timers=_timers(bgp),
        address_families=_structured(bgp, "./address-family"),
        aggregate_routes=_structured(bgp, "./aggregate"),
        advertised_networks=_structured(bgp, "./network"),
        graceful_restart=_structured(bgp, "./graceful-restart"),
        routing_options=_structured(bgp, "./routing-options"),
        unknown_fields=collect_unknown_children(bgp, ["enable", "router-id", "local-as", "auth-profile",
            "bfd", "peer-group", "policy", "redist-rules", "aggregate", "network", "dampening-profile",
            "routing-options", "routing-profile", "graceful-restart", "install-route", "reject-default-route"]),
    )
    _record(extraction, "dynamic_routing:bgp", f"{base}/{protocol_tag}/bgp", scope, "bgp", instance, config, bgp)
    count = 1
    for group in bgp.findall("./peer-group/entry"):
        group_name = group.get("name")
        path = f"{base}/{protocol_tag}/bgp/peer-group/entry[@name='{group_name}']"
        if not group_name:
            record_parse_error(extraction, "dynamic_routing:bgp_peer_group", path, scope, None,
                               {**instance, "pan_source_entry": structured_xml_capture(group)},
                               notes=["PAN-OS BGP peer group is missing its required name."])
            count += 1
            continue
        peer_nodes = group.findall("./peer/entry")
        model = PANBGPPeerGroup(
            name=group_name, enabled=_enabled(group), peer_as=text_or_none(group, "./peer-as"),
            authentication_profile=text_or_none(group, "./auth-profile"),
            bfd_profile=text_or_none(group, "./bfd/profile"),
            peer_type=text_or_none(group, "./type"),
            connection_options=_structured(group, "./connection-options"),
            address_families=_structured(group, "./address-family"),
            import_policy=_policy_names(group, "./policy/import/rules"),
            export_policy=_policy_names(group, "./policy/export/rules"),
            peers=[peer.get("name") for peer in peer_nodes if peer.get("name")],
            unknown_fields=collect_unknown_children(group, ["enable", "type", "peer-as", "auth-profile",
                                                     "bfd", "policy", "peer"]),
        )
        _record(extraction, "dynamic_routing:bgp_peer_group", path, scope, group_name, instance, model, group)
        count += 1
        for peer in peer_nodes:
            peer_name = peer.get("name")
            peer_path = f"{path}/peer/entry[@name='{peer_name}']"
            if not peer_name:
                record_parse_error(extraction, "dynamic_routing:bgp_peer", peer_path, scope, None,
                                   {**instance, "pan_source_entry": structured_xml_capture(peer)},
                                   notes=["PAN-OS BGP peer is missing its required name."])
                count += 1
                continue
            peer_model = PANBGPPeer(
                name=peer_name, peer_group=group_name,
                peer_as=text_or_none(peer, "./peer-as"),
                peer_address=text_or_none(peer, "./peer-address/ip") or text_or_none(peer, "./peer-address"),
                local_address=text_or_none(peer, "./local-address/ip") or text_or_none(peer, "./local-address"),
                interface=text_or_none(peer, "./local-address/interface") or text_or_none(peer, "./interface"),
                enabled=_enabled(peer), authentication_profile=text_or_none(peer, "./auth-profile"),
                bfd_profile=text_or_none(peer, "./bfd/profile"),
                peer_type=text_or_none(peer, "./type"),
                connection_options=_structured(peer, "./connection-options"),
                address_families=_structured(peer, "./address-family"),
                import_policy=_policy_names(peer, "./policy/import/rules"),
                export_policy=_policy_names(peer, "./policy/export/rules"), timers=_timers(peer),
                unknown_fields=collect_unknown_children(peer, ["enable", "peer-as", "peer-address",
                    "local-address", "interface", "auth-profile", "bfd", "policy", "connection-options"]),
            )
            _record(extraction, "dynamic_routing:bgp_peer", peer_path, scope, peer_name,
                    {**instance, "peer_group": group_name}, peer_model, peer)
            count += 1
    return count


def _parse_ospf(protocol: ET.Element, tag: str, base: str, scope: PANScope, extraction,
                instance: Dict[str, Any], protocol_tag: str = "protocol") -> int:
    node = protocol.find(f"./{tag}")
    if node is None:
        return 0
    cls = PANOSPFv3Config if tag == "ospfv3" else PANOSPFConfig
    config = cls(
        router_id=text_or_none(node, "./router-id"), enabled=_enabled(node),
        bfd_profile=text_or_none(node, "./bfd/profile"),
        redistribution_profile_references=_policy_names(node, "./redist-rules"),
        routing_options=_structured(node, "./routing-options"),
        routing_profile_references=_policy_names(node, "./routing-profile"),
        graceful_restart=_structured(node, "./graceful-restart"),
        default_route=text_or_none(node, "./default-route"),
        filter_lists=_structured(node, "./filter-list"),
        unknown_fields=collect_unknown_children(node, ["enable", "router-id", "bfd", "area",
                                                  "redist-rules", "routing-options", "routing-profile",
                                                  "graceful-restart", "reject-default-route"]),
    )
    _record(extraction, f"dynamic_routing:{tag}", f"{base}/{protocol_tag}/{tag}", scope, tag, instance, config, node)
    count = 1
    for area in node.findall("./area/entry"):
        area_id = area.get("name")
        path = f"{base}/{protocol_tag}/{tag}/area/entry[@name='{area_id}']"
        if not area_id:
            record_parse_error(extraction, f"dynamic_routing:{tag}_area", path, scope, None,
                               {**instance, "pan_source_entry": structured_xml_capture(area)},
                               notes=[f"PAN-OS {tag.upper()} area is missing its area ID."])
            count += 1
            continue
        interfaces = area.findall("./interface/entry")
        type_node = area.find("./type")
        area_type = (
            next(iter(type_node)).tag if type_node is not None and len(type_node)
            else text_or_none(area, "./type")
            or next((child.tag for child in area if child.tag in {"normal", "stub", "nssa"}), None)
        )
        area_model = PANOSPFArea(
            area_id=area_id, area_type=area_type,
            interfaces=[entry.get("name") for entry in interfaces if entry.get("name")],
            ranges=_structured(area, "./range"),
            virtual_links=_structured(area, "./virtual-link"),
            stub=_structured(area, "./stub"),
            nssa=_structured(area, "./nssa"),
            unknown_fields=collect_unknown_children(area, ["type", "normal", "stub", "nssa", "interface",
                                                          "range", "virtual-link"]),
        )
        _record(extraction, f"dynamic_routing:{tag}_area", path, scope, area_id, instance, area_model, area)
        count += 1
        for intf in interfaces:
            name = intf.get("name")
            intf_path = f"{path}/interface/entry[@name='{name}']"
            if not name:
                record_parse_error(extraction, f"dynamic_routing:{tag}_interface", intf_path, scope, None,
                                   {**instance, "area_id": area_id, "pan_source_entry": structured_xml_capture(intf)},
                                   notes=[f"PAN-OS {tag.upper()} interface is missing its name."])
                count += 1
                continue
            model = PANOSPFInterface(
                name=name, enabled=_enabled(intf), cost=_integer(intf, "./metric") or _integer(intf, "./cost"),
                priority=_integer(intf, "./priority"), passive=_enabled(intf, "./passive"),
                network_type=text_or_none(intf, "./link-type") or text_or_none(intf, "./network-type"),
                authentication_profile=text_or_none(intf, "./auth-profile"),
                bfd_profile=text_or_none(intf, "./bfd/profile"), timers=_timers(intf),
                authentication=_structured(intf, "./authentication"),
                unknown_fields=collect_unknown_children(intf, ["enable", "metric", "cost", "priority", "passive",
                    "link-type", "network-type", "auth-profile", "authentication", "bfd", "timers"]),
            )
            _record(extraction, f"dynamic_routing:{tag}_interface", intf_path, scope, name,
                    {**instance, "area_id": area_id}, model, intf)
            count += 1
    return count


def _parse_rip(protocol: ET.Element, base: str, scope: PANScope, extraction,
               instance: Dict[str, Any], protocol_tag: str = "protocol") -> int:
    rip = protocol.find("./rip")
    if rip is None:
        return 0
    interfaces = [entry.get("name") for entry in rip.findall("./interface/entry") if entry.get("name")]
    config = PANRIPConfig(
        enabled=_enabled(rip), interfaces=interfaces, timers=_timers(rip),
        redistribution_profile_references=_policy_names(rip, "./redist-rules"),
        authentication=_structured(rip, "./authentication"),
        bfd=_structured(rip, "./bfd"),
        routing_options=_structured(rip, "./routing-options"),
        routing_profile_references=_policy_names(rip, "./routing-profile"),
        unknown_fields=collect_unknown_children(rip, ["enable", "interface", "timers", "redist-rules",
                                                 "routing-options", "routing-profile", "reject-default-route",
                                                 "allow-redist-default-route"]),
    )
    _record(extraction, "dynamic_routing:rip", f"{base}/{protocol_tag}/rip", scope, "rip", instance, config, rip)
    count = 1
    for entry in rip.findall("./interface/entry"):
        name = entry.get("name")
        path = f"{base}/{protocol_tag}/rip/interface/entry[@name='{name}']"
        attributes = {**instance, "interface": name, "enabled": _enabled(entry),
                      "authentication_profile": text_or_none(entry, "./auth-profile"),
                      "timers": _timers(entry),
                      "unknown_fields": collect_unknown_children(entry, ["enable", "auth-profile", "mode", "timers"]),
                      "pan_source_entry": structured_xml_capture(entry)}
        if name:
            record_extract_only(extraction, "dynamic_routing:rip_interface", path, scope, name, attributes,
                                notes=["PAN-OS RIP interface retained as structured source-only evidence."],
                                requires_manual_review=True)
        else:
            record_parse_error(extraction, "dynamic_routing:rip_interface", path, scope, None, attributes,
                               notes=["PAN-OS RIP interface is missing its name."])
        count += 1
    return count


def _parse_redistribution(protocol: ET.Element, base: str, scope: PANScope, extraction,
                          instance: Dict[str, Any], protocol_tag: str = "protocol") -> int:
    count = 0
    for entry in protocol.findall("./redist-profile/entry") + protocol.findall("./redistribution-profile/entry"):
        name = entry.get("name")
        container = "redist-profile" if entry in protocol.findall("./redist-profile/entry") else "redistribution-profile"
        path = f"{base}/{protocol_tag}/{container}/entry[@name='{name}']"
        if not name:
            record_parse_error(extraction, "dynamic_routing:redistribution_profile", path, scope, None,
                               {**instance, "pan_source_entry": structured_xml_capture(entry)},
                               notes=["PAN-OS redistribution profile is missing its required name."])
        else:
            model = PANRedistributionProfile(
                name=name, priority=_integer(entry, "./priority"), action=text_or_none(entry, "./action"),
                filter=structured_xml_capture(entry.find("./filter")) or {},
                protocol_references=member_texts(entry, "./filter/type/member"),
                destination_protocol=text_or_none(entry, "./destination-protocol") or text_or_none(entry, "./protocol"),
                metric=_integer(entry, "./metric"),
                source_protocol=text_or_none(entry, "./source-protocol"),
                routing_profile_references=_policy_names(entry, "./routing-profile"),
                unknown_fields=collect_unknown_children(entry, ["priority", "action", "filter", "destination-protocol",
                                                                 "protocol", "metric", "source-protocol", "routing-profile"]),
            )
            _record(extraction, "dynamic_routing:redistribution_profile", path, scope, name, instance, model, entry)
        count += 1
    return count


def extract_dynamic_routing(network_node: ET.Element, context: PANScope, inventory) -> None:
    """Extract dynamic routing from discovered VR/LR-VRF instances."""
    total = 0
    for routing_instance in discover_routing_instances(network_node):
        protocol, protocol_tag = routing_instance.protocol_node()
        if protocol is None or protocol_tag is None:
            continue
        base = routing_instance.source_path or "network/routing-instance"
        instance = _common(routing_instance, "dynamic")
        if context.device_serial:
            instance["pan_device_serial"] = context.device_serial
        total += _parse_bgp(protocol, base, context, inventory, instance, protocol_tag)
        total += _parse_ospf(protocol, "ospf", base, context, inventory, instance, protocol_tag)
        total += _parse_ospf(protocol, "ospfv3", base, context, inventory, instance, protocol_tag)
        total += _parse_rip(protocol, base, context, inventory, instance, protocol_tag)
        total += _parse_redistribution(protocol, base, context, inventory, instance, protocol_tag)
        for child in protocol:
            if child.tag in {"bgp", "ospf", "ospfv3", "rip", "redist-profile",
                             "redistribution-profile"}:
                continue
            path = f"{base}/{protocol_tag}/{child.tag}"
            record_unsupported(
                inventory, f"dynamic_routing:{child.tag}", path, context, child.tag,
                {**instance, "protocol_name": child.tag,
                 "pan_source_entry": structured_xml_capture(child)},
                notes=[f"PAN-OS dynamic-routing family {child.tag} is not implemented."],
            )
            total += 1
    if total:
        add_source_section(
            inventory, "network/dynamic-routing", ExtractionStatus.EXTRACT_ONLY,
            total, total, 0, "extract_dynamic_routing",
            source_context=f"{context.kind}:{context.name}",
        )
