from __future__ import annotations

import xml.etree.ElementTree as ET

from ..model import PANBGPConfig, PANBGPPeer, PANBGPPeerGroup, PANLogicalRouter, PANOSPFConfig, PANOSPFv3Config, PANOSPFInterface, PANOSPFArea, PANRIPConfig, PANRedistributionProfile, PANStaticRoute, PANVRF, PANVirtualRouter
from ..source_context import PANWalkContext
from .common import raw_extra, structured_xml_capture, typed_fields, value, values


def _interface(element: ET.Element) -> PANOSPFInterface:
    extra, explicit = typed_fields(element, {"metric", "cost", "priority", "passive", "link-type", "bfd"})
    return PANOSPFInterface(name=element.get("name"), metric=value(element, "metric"), cost=value(element, "cost"), priority=value(element, "priority"), passive=value(element, "passive"), link_type=value(element, "link-type"), bfd_profile=value(element.find("bfd"), "profile"), raw_extra=extra, explicit_fields=explicit)


def _ospf(element: ET.Element, v3=False):
    extra, explicit = typed_fields(element, {"enable", "router-id", "area"})
    area_node = element.find("area")
    areas = []
    if area_node is not None:
        for area in area_node:
            node = area.find("interface")
            interfaces = [_interface(item) for item in node] if node is not None else None
            areas.append(PANOSPFArea(name=area.get("name"), interfaces=interfaces, raw_extra=raw_extra(area, {"interface", "type"}), explicit_fields={"interfaces"} if node is not None else set()))
    cls = PANOSPFv3Config if v3 else PANOSPFConfig
    return cls(enable=value(element, "enable"), router_id=value(element, "router-id"), areas=areas or None, raw_extra=extra, explicit_fields=explicit)


def _bgp(element: ET.Element):
    extra, explicit = typed_fields(element, {"enable", "router-id", "local-as", "bfd", "redist-rules", "peer-group"})
    redist = element.find("redist-rules")
    redistribution = [item.get("name") for item in redist if item.get("name") is not None] if redist is not None else None
    groups = []
    group_node = element.find("peer-group")
    if group_node is not None:
        for group in group_node:
            peers = []
            peer_node = group.find("peer")
            if peer_node is not None:
                for peer in peer_node:
                    peer_address, local_address = peer.find("peer-address"), peer.find("local-address")
                    p_extra, p_explicit = typed_fields(peer, {"enable", "peer-as", "peer-address", "local-address", "bfd", "hold-time"})
                    peers.append(PANBGPPeer(name=peer.get("name"), enable=value(peer, "enable"), peer_as=value(peer, "peer-as"), peer_address=value(peer_address, "ip"), local_interface=value(local_address, "interface"), local_ip=value(local_address, "ip"), bfd_profile=value(peer.find("bfd"), "profile"), hold_time=value(peer, "hold-time"), raw_extra=p_extra, explicit_fields=p_explicit))
            g_extra, g_explicit = typed_fields(group, {"enable", "auth-profile", "peer"})
            groups.append(PANBGPPeerGroup(name=group.get("name"), enable=value(group, "enable"), auth_profile=value(group, "auth-profile"), peers=peers or None, raw_extra=g_extra, explicit_fields=g_explicit))
    return PANBGPConfig(enable=value(element, "enable"), router_id=value(element, "router-id"), local_as=value(element, "local-as"), bfd_profile=value(element.find("bfd"), "profile"), redistribution_rules=redistribution, peer_groups=groups or None, raw_extra=extra, explicit_fields=explicit)


def _virtual(element: ET.Element, path, context, source_order):
    extra, explicit = typed_fields(element, {"interface", "routing-table", "protocol", "redist-profile"})
    routes = []
    node = element.find("routing-table/ip/static-route")
    if node is not None:
        for route in node:
            hop = route.find("nexthop")
            r_extra, r_explicit = typed_fields(route, {"destination", "nexthop", "interface", "metric"})
            routes.append(PANStaticRoute(name=route.get("name"), source_path="/".join(path) + "/routing-table/ip/static-route/entry", scope=context.scope, source_order=source_order, destination=value(route, "destination"), nexthop_ip_address=value(hop, "ip-address"), nexthop=value(hop, "ip-address"), interface=value(route, "interface"), metric=value(route, "metric"), raw_extra=r_extra, explicit_fields=r_explicit))
    protocol = element.find("protocol")
    bgp = _bgp(protocol.find("bgp")) if protocol is not None and protocol.find("bgp") is not None else None
    ospf = _ospf(protocol.find("ospf")) if protocol is not None and protocol.find("ospf") is not None else None
    ospfv3 = _ospf(protocol.find("ospfv3"), True) if protocol is not None and protocol.find("ospfv3") is not None else None
    rip_node = protocol.find("rip") if protocol is not None else None
    rip = PANRIPConfig(enable=value(rip_node, "enable"), interfaces=[_interface(item) for item in rip_node.find("interface")] if rip_node is not None and rip_node.find("interface") is not None else None, raw_extra=raw_extra(rip_node, {"enable", "interface", "timers"}) if rip_node is not None else {}, explicit_fields={"interfaces"} if rip_node is not None and rip_node.find("interface") is not None else {"enable"} if value(rip_node, "enable") is not None else set()) if rip_node is not None else None
    profiles = []
    profile_node = element.find("redist-profile")
    if profile_node is not None:
        for profile in profile_node:
            p_extra, p_explicit = typed_fields(profile, {"priority", "action", "filter"})
            profiles.append(PANRedistributionProfile(name=profile.get("name"), priority=value(profile, "priority"), action=value(profile, "action"), raw_extra=p_extra, explicit_fields=p_explicit))
    return PANVirtualRouter(name=element.get("name"), source_path="/".join(path), scope=context.scope, source_order=source_order, interfaces=values(element, "interface"), static_routes=routes or None, bgp=bgp, ospf=ospf, ospfv3=ospfv3, rip=rip, redistribution_profiles=profiles or None, raw_extra=extra, explicit_fields=explicit)


def extract_routing(element: ET.Element, path: tuple[str, ...], context: PANWalkContext, source_order: int) -> object | None:
    if path[-2:] == ("virtual-router", "entry"):
        return _virtual(element, path, context, source_order)
    if path[-2:] == ("logical-router", "entry"):
        node = element.find("vrf")
        vrfs = []
        if node is not None:
            for vrf in node:
                protocol = vrf.find("routing-protocol")
                vrfs.append(PANVRF(name=vrf.get("name"), routing_protocol=structured_xml_capture(protocol) if protocol is not None else None, raw_extra=raw_extra(vrf, {"routing-protocol"}), explicit_fields={"routing_protocol"} if protocol is not None else set()))
        extra, explicit = typed_fields(element, {"vrf"})
        return PANLogicalRouter(name=element.get("name"), source_path="/".join(path), scope=context.scope, source_order=source_order, vrfs=vrfs or None, raw_extra=extra, explicit_fields=explicit)
    if path[-2] in {"static", "route", "static-route"}:
        extra, explicit = typed_fields(element, {"destination", "nexthop", "interface", "metric"})
        return PANStaticRoute(name=element.get("name"), source_path="/".join(path), scope=context.scope, source_order=source_order, destination=value(element, "destination"), nexthop=value(element, "nexthop"), interface=value(element, "interface"), metric=value(element, "metric"), raw_extra=extra, explicit_fields=explicit)
    return None
