from __future__ import annotations

import xml.etree.ElementTree as ET

from ..model import (
    PANBGPConfig, PANBGPPeer, PANBGPPeerGroup, PANLogicalRouter, PANOSPFConfig,
    PANOSPFInterface, PANOSPFArea, PANOSPFv3Config, PANRIPConfig,
    PANRedistributionProfile, PANStaticRoute, PANVRF, PANVirtualRouter,
)
from ..schema_registry import PANPathSpec
from ..source_context import PANWalkContext
from .common import raw_extra, source_fields, structured_xml_capture, typed_fields, value, values


def _extract_ospf_interface(element: ET.Element) -> PANOSPFInterface:
    extra, explicit = typed_fields(element, {"metric", "cost", "priority", "passive", "link-type", "bfd"}, {"link-type": "link_type", "bfd": "bfd_profile"})
    return PANOSPFInterface(name=element.get("name"), metric=value(element, "metric"), cost=value(element, "cost"), priority=value(element, "priority"), passive=value(element, "passive"), link_type=value(element, "link-type"), bfd_profile=value(element.find("bfd"), "profile"), raw_extra=extra, explicit_fields=explicit)


def _extract_ospf(element: ET.Element, *, v3: bool = False) -> PANOSPFConfig:
    extra, explicit = typed_fields(element, {"enable", "router-id", "area"}, {"router-id": "router_id", "area": "areas"})
    areas: list[PANOSPFArea] = []
    area_node = element.find("area")
    if area_node is not None:
        for area in area_node:
            interface_node = area.find("interface")
            interfaces = [_extract_ospf_interface(item) for item in interface_node] if interface_node is not None else None
            area_extra, area_explicit = typed_fields(area, {"type", "interface"}, {"type": "area_type", "interface": "interfaces"})
            type_node = area.find("type")
            type_branch = next(iter(type_node), None) if type_node is not None else None
            area_type = type_branch.tag if type_branch is not None else value(area, "type")
            areas.append(PANOSPFArea(name=area.get("name"), area_type=area_type, interfaces=interfaces, raw_extra=area_extra, explicit_fields=area_explicit))
    model = PANOSPFv3Config if v3 else PANOSPFConfig
    return model(enable=value(element, "enable"), router_id=value(element, "router-id"), areas=areas or None, raw_extra=extra, explicit_fields=explicit)


def _extract_bgp_peers(group: ET.Element) -> list[PANBGPPeer] | None:
    peer_node = group.find("peer")
    if peer_node is None:
        return None
    peers: list[PANBGPPeer] = []
    for peer in peer_node:
        peer_address = peer.find("peer-address")
        local_address = peer.find("local-address")
        connection_options = peer.find("connection-options")
        extra, explicit = typed_fields(peer, {"enable", "peer-as", "peer-address", "local-address", "bfd", "connection-options"}, {"peer-as": "peer_as", "bfd": "bfd_profile", "connection-options": "hold_time"})
        explicit.discard("peer-address")
        explicit.discard("local-address")
        if peer_address is not None and peer_address.find("ip") is not None:
            explicit.add("peer_address")
        if local_address is not None:
            explicit.update(field for field, child in (("local_interface", "interface"), ("local_ip", "ip")) if local_address.find(child) is not None)
        peers.append(PANBGPPeer(name=peer.get("name"), enable=value(peer, "enable"), peer_as=value(peer, "peer-as"), peer_address=value(peer_address, "ip"), local_interface=value(local_address, "interface"), local_ip=value(local_address, "ip"), bfd_profile=value(peer.find("bfd"), "profile"), hold_time=value(connection_options, "hold-time"), raw_extra=extra, explicit_fields=explicit))
    return peers or None


def _extract_bgp_peer_groups(element: ET.Element) -> list[PANBGPPeerGroup] | None:
    group_node = element.find("peer-group")
    if group_node is None:
        return None
    groups: list[PANBGPPeerGroup] = []
    for group in group_node:
        extra, explicit = typed_fields(group, {"enable", "auth-profile", "peer"}, {"auth-profile": "auth_profile", "peer": "peers"})
        groups.append(PANBGPPeerGroup(name=group.get("name"), enable=value(group, "enable"), auth_profile=value(group, "auth-profile"), peers=_extract_bgp_peers(group), raw_extra=extra, explicit_fields=explicit))
    return groups or None


def _extract_bgp(element: ET.Element) -> PANBGPConfig:
    extra, explicit = typed_fields(element, {"enable", "router-id", "local-as", "bfd", "redist-rules", "peer-group"}, {"router-id": "router_id", "local-as": "local_as", "bfd": "bfd_profile", "redist-rules": "redistribution_rules", "peer-group": "peer_groups"})
    redist = element.find("redist-rules")
    redistribution = [item.get("name") for item in redist if item.get("name") is not None] if redist is not None else None
    return PANBGPConfig(enable=value(element, "enable"), router_id=value(element, "router-id"), local_as=value(element, "local-as"), bfd_profile=value(element.find("bfd"), "profile"), redistribution_rules=redistribution, peer_groups=_extract_bgp_peer_groups(element), raw_extra=extra, explicit_fields=explicit)


def _extract_rip(element: ET.Element) -> PANRIPConfig:
    interface_node = element.find("interface")
    extra, explicit = typed_fields(element, {"enable", "interface"}, {"interface": "interfaces"})
    return PANRIPConfig(enable=value(element, "enable"), interfaces=[_extract_ospf_interface(item) for item in interface_node] if interface_node is not None else None, raw_extra=extra, explicit_fields=explicit)


def _extract_redistribution_profiles(element: ET.Element) -> list[PANRedistributionProfile] | None:
    profile_node = element.find("redist-profile")
    if profile_node is None:
        return None
    profiles: list[PANRedistributionProfile] = []
    for profile in profile_node:
        extra, explicit = typed_fields(profile, {"priority", "action", "filter"})
        explicit.discard("filter")
        profiles.append(PANRedistributionProfile(name=profile.get("name"), priority=value(profile, "priority"), action=value(profile, "action"), raw_extra=extra, explicit_fields=explicit))
    return profiles or None


def _extract_static_routes(element: ET.Element, path: tuple[str, ...], context: PANWalkContext) -> list[PANStaticRoute] | None:
    node = element.find("routing-table/ip/static-route")
    if node is None:
        return None
    routes: list[PANStaticRoute] = []
    for route_order, route in enumerate(node, start=1):
        hop = route.find("nexthop")
        extra, explicit = typed_fields(route, {"destination", "nexthop", "interface", "metric"})
        routes.append(PANStaticRoute(name=route.get("name"), source_path="/".join(path) + "/routing-table/ip/static-route/entry", scope=context.scope, source_order=route_order, destination=value(route, "destination"), nexthop_ip_address=value(hop, "ip-address"), nexthop=value(hop, "ip-address"), interface=value(route, "interface"), metric=value(route, "metric"), raw_extra=extra, explicit_fields=explicit))
    return routes or None


def _extract_logical_router_vrfs(element: ET.Element) -> list[PANVRF] | None:
    node = element.find("vrf")
    if node is None:
        return None
    vrfs: list[PANVRF] = []
    for vrf in node:
        protocol = vrf.find("routing-protocol")
        vrfs.append(PANVRF(name=vrf.get("name"), routing_protocol=structured_xml_capture(protocol) if protocol is not None else None, raw_extra=raw_extra(vrf, {"routing-protocol"}), explicit_fields={"routing_protocol"} if protocol is not None else set()))
    return vrfs or None


def _extract_virtual_router(element: ET.Element, path: tuple[str, ...], context: PANWalkContext, source_order: int, spec: PANPathSpec) -> PANVirtualRouter:
    extra, explicit = source_fields(element, spec)
    explicit.discard("protocol")
    protocol = element.find("protocol")
    rip_node = protocol.find("rip") if protocol is not None else None
    bgp = _extract_bgp(protocol.find("bgp")) if protocol is not None and protocol.find("bgp") is not None else None
    ospf = _extract_ospf(protocol.find("ospf")) if protocol is not None and protocol.find("ospf") is not None else None
    ospfv3 = _extract_ospf(protocol.find("ospfv3"), v3=True) if protocol is not None and protocol.find("ospfv3") is not None else None
    rip = _extract_rip(rip_node) if rip_node is not None else None
    static_routes = _extract_static_routes(element, path, context)
    redistribution_profiles = _extract_redistribution_profiles(element)
    explicit.update(field for field, value_ in (("bgp", bgp), ("ospf", ospf), ("ospfv3", ospfv3), ("rip", rip), ("static_routes", static_routes), ("redistribution_profiles", redistribution_profiles)) if value_ is not None)
    return PANVirtualRouter(name=element.get("name"), source_path="/".join(path), scope=context.scope, source_order=source_order, interfaces=values(element, "interface"), static_routes=static_routes, bgp=bgp, ospf=ospf, ospfv3=ospfv3, rip=rip, redistribution_profiles=redistribution_profiles, raw_extra=extra, explicit_fields=explicit)


def _extract_logical_router(element: ET.Element, path: tuple[str, ...], context: PANWalkContext, source_order: int, spec: PANPathSpec) -> PANLogicalRouter:
    extra, explicit = source_fields(element, spec)
    return PANLogicalRouter(name=element.get("name"), source_path="/".join(path), scope=context.scope, source_order=source_order, vrfs=_extract_logical_router_vrfs(element), raw_extra=extra, explicit_fields=explicit)


def extract_routing(element: ET.Element, path: tuple[str, ...], context: PANWalkContext, source_order: int, spec: PANPathSpec) -> object | None:
    if spec.name == "virtual_router":
        return _extract_virtual_router(element, path, context, source_order, spec)
    if spec.name == "logical_router":
        return _extract_logical_router(element, path, context, source_order, spec)
    return None
