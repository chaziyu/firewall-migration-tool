"""PAN-OS source-record construction from loaded XML."""

from __future__ import annotations

import xml.etree.ElementTree as ET

from fwmigrate.extraction.sanitize import sanitize_raw_text, sanitize_source_attributes

from .source_context import walk_pan_source
from .extraction.common import capture_unknown_attributes, capture_unknown_children, structured_xml_capture
from .model import (
    PANAddress,
    PANAddressGroup,
    PANInterface,
    PANInterfaceImport,
    PANInterfaceIPv6Address,
    PANInterfaceUnit,
    PANDestinationTranslation,
    PANDNSRewrite,
    PANDynamicDestinationTranslation,
    PANDynamicIPAndPortTranslation,
    PANNATRule,
    PANOSConfig,
    PANPolicy,
    PANDefaultSecurityRule,
    PANProfileSetting,
    PANSecurityRule,
    PANService,
    PANServiceGroup,
    PANServiceOverride,
    PANServiceProtocol,
    PANSchedule,
    PANScheduleRecurring,
    PANStaticRoute,
    PANStaticIPTranslation,
    PANBGPConfig,
    PANBGPPeer,
    PANBGPPeerGroup,
    PANLogicalRouter,
    PANOSPFConfig,
    PANOSPFArea,
    PANOSPFInterface,
    PANOSPFv3Config,
    PANRIPConfig,
    PANRedistributionProfile,
    PANVirtualRouter,
    PANVRF,
)
from .source_model import PANScope, PANSourceRecord, pan_scope_identity
from .xml_loader import load_pan_source


def _record_value(element: ET.Element) -> dict[str, object]:
    values: dict[str, object] = {}
    for child in element:
        if len(child) == 0 and (child.text or "").strip():
            values[child.tag] = (child.text or "").strip()
        elif len(child):
            values[child.tag] = [item.get("name") or (item.text or "").strip() for item in child]
    return values


def _raw_extra(element: ET.Element, known: set[str]) -> dict[str, object]:
    extra: dict[str, object] = capture_unknown_children(element, known)
    attributes = capture_unknown_attributes(element)
    if attributes:
        extra["@attributes"] = attributes
    return sanitize_source_attributes(extra)


def _value(element: ET.Element | None, tag: str) -> str | None:
    if element is None:
        return None
    child = element.find(tag)
    if child is None:
        return None
    return (child.text or "").strip()


def _values(element: ET.Element, tag: str) -> list[str] | None:
    child = element.find(tag)
    if child is None:
        return None
    if len(child) == 0:
        return []
    return [
        (item.text or item.get("name") or "").strip()
        for item in child
    ]


def _typed_fields(element: ET.Element, known: set[str]) -> tuple[dict[str, object], set[str]]:
    return _raw_extra(element, known), {child.tag for child in element if child.tag in known}


def _service_override(element: ET.Element) -> PANServiceOverride | None:
    override = element.find("override")
    if override is None:
        return None
    source = next(iter(override), None)
    if source is None:
        source = override
    known = {"timeout", "halfclose-timeout", "timewait-timeout"}
    extra, explicit = _typed_fields(source, known)
    field_names = {"halfclose-timeout": "halfclose_timeout", "timewait-timeout": "timewait_timeout"}
    return PANServiceOverride(
        timeout=_value(source, "timeout"),
        halfclose_timeout=_value(source, "halfclose-timeout"),
        timewait_timeout=_value(source, "timewait-timeout"),
        raw_extra=extra,
        explicit_fields={field_names.get(item, item) for item in explicit},
    )


def _service_protocol(element: ET.Element | None, name: str) -> PANServiceProtocol | None:
    if element is None:
        return None
    protocol = element.find(name)
    if protocol is None:
        return None
    known = {"port", "source-port", "override"}
    extra, explicit = _typed_fields(protocol, known)
    return PANServiceProtocol(
        port=_value(protocol, "port"),
        source_port=_value(protocol, "source-port"),
        override=_service_override(protocol),
        raw_extra=extra,
        explicit_fields={"source_port" if item == "source-port" else item for item in explicit},
    )


def _schedule_recurring(element: ET.Element | None) -> PANScheduleRecurring | None:
    if element is None:
        return None
    daily = _values(element, "daily")
    weekly_node = element.find("weekly")
    weekly = None
    if weekly_node is not None:
        weekly = {day.tag: _values(weekly_node, day.tag) or [] for day in weekly_node}
    known = {"daily", "weekly"}
    extra, explicit = _typed_fields(element, known)
    return PANScheduleRecurring(
        daily=daily,
        weekly=weekly,
        raw_extra=extra,
        explicit_fields=explicit,
    )


def _interface_ipv6(element: ET.Element | None) -> list[PANInterfaceIPv6Address] | None:
    if element is None:
        return None
    address_node = element.find("ipv6/address")
    if address_node is None:
        return None
    result = []
    for item in address_node:
        extra, explicit = _typed_fields(item, {"enable"})
        result.append(PANInterfaceIPv6Address(address=item.get("name"), enable=_value(item, "enable"), raw_extra=extra, explicit_fields=explicit))
    return result


def _interface_ipv4(element: ET.Element | None) -> list[str] | None:
    if element is None:
        return None
    node = element.find("ip")
    if node is None:
        return None
    return [item.get("name") for item in node if item.tag == "entry"]


def _interface_mode_extra(element: ET.Element, modes: set[str]) -> dict[str, object]:
    extra: dict[str, object] = {}
    known = {
        "layer3": {"interface-management-profile", "mtu", "ip", "ipv6", "units"},
        "layer2": {"units", "lacp", "vlan"},
        "virtual-wire": {"virtual-wire"},
        "tap": set(), "ha": set(), "decrypt-mirror": set(),
    }
    for mode in modes:
        branch = element.find(mode)
        if branch is not None:
            captured = _raw_extra(branch, known.get(mode, set()))
            if captured:
                extra[mode] = captured
    return extra


def _profile_setting(element: ET.Element) -> PANProfileSetting | None:
    setting = element.find("profile-setting")
    if setting is None:
        return None
    profiles_node = setting.find("profiles")
    profiles = None
    if profiles_node is not None:
        profiles = {child.tag: _values(profiles_node, child.tag) or [] for child in profiles_node}
    extra, explicit = _typed_fields(setting, {"group", "profiles"})
    return PANProfileSetting(
        groups=_values(setting, "group"),
        profiles=profiles,
        raw_extra=extra,
        explicit_fields={"groups" if item == "group" else item for item in explicit},
    )


def _policy_fields(element: ET.Element, known: set[str]) -> tuple[dict[str, object], set[str]]:
    extra, explicit = _typed_fields(element, known)
    names = {
        "from": "from_zones", "to": "to_zones", "source": "source",
        "destination": "destination", "source-user": "source_user",
        "application": "application", "service": "service",
        "source-hip": "source_hip", "destination-hip": "destination_hip",
        "negate-source": "negate_source", "negate-destination": "negate_destination",
        "rule-type": "rule_type", "tag": "tags", "group-tag": "group_tag",
        "log-start": "log_start", "log-end": "log_end", "log-setting": "log_setting",
        "profile-setting": "profile_setting", "disable-inspect": "disable_inspect",
        "disable-server-response-inspection": "disable_server_response_inspection",
        "saas-user-list": "saas_user_list", "saas-tenant-list": "saas_tenant_list",
    }
    return extra, {names.get(item, item) for item in explicit}


def _nat_source_translation(element: ET.Element) -> PANDynamicIPAndPortTranslation | PANStaticIPTranslation | None:
    container = element.find("source-translation")
    if container is None:
        return None
    dynamic = container.find("dynamic-ip-and-port")
    if dynamic is not None:
        interface_address = dynamic.find("interface-address")
        extra, explicit = _typed_fields(dynamic, {"translated-address", "interface-address"})
        return PANDynamicIPAndPortTranslation(translated_addresses=_values(dynamic, "translated-address"), interface=_value(interface_address, "interface"), ip=_value(interface_address, "ip"), raw_extra=extra, explicit_fields=explicit)
    static = container.find("static-ip")
    if static is not None:
        extra, explicit = _typed_fields(static, {"translated-address", "bi-directional"})
        return PANStaticIPTranslation(translated_address=_value(static, "translated-address"), bi_directional=_value(static, "bi-directional"), raw_extra=extra, explicit_fields=explicit)
    return None


def _nat_destination_translation(element: ET.Element) -> PANDestinationTranslation | None:
    node = element.find("destination-translation")
    if node is None:
        return None
    extra, explicit = _typed_fields(node, {"translated-address", "translated-port"})
    return PANDestinationTranslation(translated_address=_value(node, "translated-address"), translated_port=_value(node, "translated-port"), raw_extra=extra, explicit_fields=explicit)


def _nat_dynamic_destination_translation(element: ET.Element) -> PANDynamicDestinationTranslation | None:
    node = element.find("dynamic-destination-translation")
    if node is None:
        return None
    rewrite = node.find("dns-rewrite")
    dns_rewrite = None
    if rewrite is not None:
        branch = next(iter(rewrite), None)
        if branch is None:
            dns_rewrite = PANDNSRewrite(enabled=None, explicit_fields=set())
        else:
            extra, explicit = _typed_fields(branch, {"direction"})
            dns_rewrite = PANDNSRewrite(enabled=branch.tag, direction=_value(branch, "direction"), raw_extra=extra, explicit_fields={"enabled", *explicit})
    distribution_node = node.find("distribution")
    distribution = next(iter(distribution_node), None).tag if distribution_node is not None and len(distribution_node) else None
    extra, explicit = _typed_fields(node, {"translated-address", "distribution", "dns-rewrite"})
    return PANDynamicDestinationTranslation(translated_addresses=_values(node, "translated-address"), distribution=distribution, dns_rewrite=dns_rewrite, raw_extra=extra, explicit_fields=explicit)


def _routing_interface(element: ET.Element) -> PANOSPFInterface:
    known = {"metric", "cost", "priority", "passive", "link-type", "bfd"}
    extra, explicit = _typed_fields(element, known)
    bfd = element.find("bfd")
    return PANOSPFInterface(name=element.get("name"), metric=_value(element, "metric"), cost=_value(element, "cost"), priority=_value(element, "priority"), passive=_value(element, "passive"), link_type=_value(element, "link-type"), bfd_profile=_value(bfd, "profile"), raw_extra=extra, explicit_fields=explicit)


def _routing_ospf(element: ET.Element, v3: bool = False) -> PANOSPFConfig | PANOSPFv3Config:
    known = {"enable", "router-id", "area"}
    extra, explicit = _typed_fields(element, known)
    areas = []
    area_node = element.find("area")
    if area_node is not None:
        for area in area_node:
            interfaces_node = area.find("interface")
            interfaces = [_routing_interface(item) for item in interfaces_node] if interfaces_node is not None else None
            areas.append(PANOSPFArea(name=area.get("name"), interfaces=interfaces, raw_extra=_raw_extra(area, {"interface", "type"}), explicit_fields={"interfaces"} if interfaces_node is not None else set()))
    cls = PANOSPFv3Config if v3 else PANOSPFConfig
    return cls(enable=_value(element, "enable"), router_id=_value(element, "router-id"), areas=areas or None, raw_extra=extra, explicit_fields=explicit)


def _routing_bgp(element: ET.Element) -> PANBGPConfig:
    known = {"enable", "router-id", "local-as", "bfd", "redist-rules", "peer-group"}
    extra, explicit = _typed_fields(element, known)
    redistribution = None
    redist = element.find("redist-rules")
    if redist is not None:
        redistribution = [item.get("name") for item in redist if item.get("name") is not None]
    peer_groups = []
    group_node = element.find("peer-group")
    if group_node is not None:
        for group in group_node:
            peers_node = group.find("peer")
            peers = []
            if peers_node is not None:
                for peer in peers_node:
                    peer_address = peer.find("peer-address")
                    local_address = peer.find("local-address")
                    peer_known = {"enable", "peer-as", "peer-address", "local-address", "bfd", "hold-time"}
                    peer_extra, peer_explicit = _typed_fields(peer, peer_known)
                    peers.append(PANBGPPeer(name=peer.get("name"), enable=_value(peer, "enable"), peer_as=_value(peer, "peer-as"), peer_address=_value(peer_address, "ip"), local_interface=_value(local_address, "interface"), local_ip=_value(local_address, "ip"), bfd_profile=_value(peer.find("bfd"), "profile"), hold_time=_value(peer, "hold-time"), raw_extra=peer_extra, explicit_fields=peer_explicit))
            group_extra, group_explicit = _typed_fields(group, {"enable", "auth-profile", "peer"})
            peer_groups.append(PANBGPPeerGroup(name=group.get("name"), enable=_value(group, "enable"), auth_profile=_value(group, "auth-profile"), peers=peers or None, raw_extra=group_extra, explicit_fields=group_explicit))
    return PANBGPConfig(enable=_value(element, "enable"), router_id=_value(element, "router-id"), local_as=_value(element, "local-as"), bfd_profile=_value(element.find("bfd"), "profile"), redistribution_rules=redistribution, peer_groups=peer_groups or None, raw_extra=extra, explicit_fields=explicit)


def _routing_virtual_router(element: ET.Element, path: tuple[str, ...], context, source_order: int) -> PANVirtualRouter:
    known = {"interface", "routing-table", "protocol", "redist-profile"}
    extra, explicit = _typed_fields(element, known)
    routes = []
    static_node = element.find("routing-table/ip/static-route")
    if static_node is not None:
        for route in static_node:
            next_hop = route.find("nexthop")
            route_extra, route_explicit = _typed_fields(route, {"destination", "nexthop", "interface", "metric"})
            routes.append(PANStaticRoute(name=route.get("name"), source_path="/".join(path) + "/routing-table/ip/static-route/entry", scope=context.scope, source_order=source_order, destination=_value(route, "destination"), nexthop_ip_address=_value(next_hop, "ip-address"), nexthop=_value(next_hop, "ip-address"), interface=_value(route, "interface"), metric=_value(route, "metric"), raw_extra=route_extra, explicit_fields=route_explicit))
    protocol = element.find("protocol")
    bgp = _routing_bgp(protocol.find("bgp")) if protocol is not None and protocol.find("bgp") is not None else None
    ospf = _routing_ospf(protocol.find("ospf")) if protocol is not None and protocol.find("ospf") is not None else None
    ospfv3 = _routing_ospf(protocol.find("ospfv3"), True) if protocol is not None and protocol.find("ospfv3") is not None else None
    rip = None
    if protocol is not None and protocol.find("rip") is not None:
        rip_node = protocol.find("rip")
        rip = PANRIPConfig(enable=_value(rip_node, "enable"), interfaces=[_routing_interface(item) for item in rip_node.find("interface")] if rip_node.find("interface") is not None else None, raw_extra=_raw_extra(rip_node, {"enable", "interface", "timers"}), explicit_fields={"enable", "interfaces"} if rip_node.find("interface") is not None else {"enable"} if _value(rip_node, "enable") is not None else set())
    profiles = []
    profile_node = element.find("redist-profile")
    if profile_node is not None:
        for profile in profile_node:
            profile_extra, profile_explicit = _typed_fields(profile, {"priority", "action", "filter"})
            profiles.append(PANRedistributionProfile(name=profile.get("name"), priority=_value(profile, "priority"), action=_value(profile, "action"), raw_extra=profile_extra, explicit_fields=profile_explicit))
    return PANVirtualRouter(name=element.get("name"), source_path="/".join(path), scope=context.scope, source_order=source_order, interfaces=_values(element, "interface"), static_routes=routes or None, bgp=bgp, ospf=ospf, ospfv3=ospfv3, rip=rip, redistribution_profiles=profiles or None, raw_extra=extra, explicit_fields=explicit)


def _routing_logical_router(element: ET.Element, path: tuple[str, ...], context, source_order: int) -> PANLogicalRouter:
    vrfs = []
    vrf_node = element.find("vrf")
    if vrf_node is not None:
        for vrf in vrf_node:
            protocol = vrf.find("routing-protocol")
            vrfs.append(PANVRF(name=vrf.get("name"), routing_protocol=structured_xml_capture(protocol) if protocol is not None else None, raw_extra=_raw_extra(vrf, {"routing-protocol"}), explicit_fields={"routing_protocol"} if protocol is not None else set()))
    extra, explicit = _typed_fields(element, {"vrf"})
    return PANLogicalRouter(name=element.get("name"), source_path="/".join(path), scope=context.scope, source_order=source_order, vrfs=vrfs or None, raw_extra=extra, explicit_fields=explicit)


def _typed_record(element: ET.Element, path: tuple[str, ...], context, source_order: int) -> object | None:
    kind = path[-2] if len(path) > 1 else "entry"
    rule_kind = path[path.index("rules") - 1] if "rules" in path and path.index("rules") else None
    common = {
        "name": element.get("name"),
        "source_path": "/".join(path),
        "scope": context.scope,
        "source_order": source_order,
    }

    if kind == "address":
        known = {"ip-netmask", "ip-range", "ip-wildcard", "fqdn", "description", "tag"}
        extra, explicit = _typed_fields(element, known)
        return PANAddress(**common, ip_netmask=_value(element, "ip-netmask"), ip_range=_value(element, "ip-range"), ip_wildcard=_value(element, "ip-wildcard"), fqdn=_value(element, "fqdn"), description=_value(element, "description"), tags=_values(element, "tag"), raw_extra=extra, explicit_fields=explicit)
    if kind == "address-group":
        known = {"static", "dynamic", "description", "tag"}
        extra, explicit = _typed_fields(element, known)
        dynamic = element.find("dynamic")
        return PANAddressGroup(**common, static_members=_values(element, "static"), dynamic_filter=_value(dynamic, "filter") if dynamic is not None else None, description=_value(element, "description"), tags=_values(element, "tag"), raw_extra=extra, explicit_fields=explicit)
    if kind == "service":
        known = {"protocol", "description", "tag"}
        extra, explicit = _typed_fields(element, known)
        protocol = element.find("protocol")
        return PANService(**common, tcp=_service_protocol(protocol, "tcp"), udp=_service_protocol(protocol, "udp"), description=_value(element, "description"), tags=_values(element, "tag"), raw_extra=extra, explicit_fields=explicit)
    if kind == "service-group":
        known = {"members", "description", "tag"}
        extra, explicit = _typed_fields(element, known)
        return PANServiceGroup(**common, members=_values(element, "members"), description=_value(element, "description"), tags=_values(element, "tag"), raw_extra=extra, explicit_fields=explicit)
    if kind == "schedule":
        known = {"schedule-type"}
        extra, explicit = _typed_fields(element, known)
        schedule_type = element.find("schedule-type")
        recurring_node = schedule_type.find("recurring") if schedule_type is not None else None
        non_recurring = _values(schedule_type, "non-recurring") if schedule_type is not None else None
        return PANSchedule(
            **common,
            recurring=_schedule_recurring(recurring_node),
            non_recurring=non_recurring,
            raw_extra=extra,
            explicit_fields=explicit,
        )
    if path[-3:] == ("import", "network", "interface"):
        interfaces = [child.text.strip() for child in element if child.tag == "member" and child.text]
        extra, explicit = _typed_fields(element, {"member"})
        return PANInterfaceImport(scope=context.scope, interfaces=interfaces, source_path="/".join(path), raw_extra=extra, explicit_fields={"interfaces"} if explicit else set())
    if kind == "units" and context.interface_name:
        known = {"tag", "ip", "ipv6", "interface-management-profile"}
        extra, explicit = _typed_fields(element, known)
        return PANInterfaceUnit(name=element.get("name"), parent=context.interface_name, tag=_value(element, "tag"), ipv4_addresses=_interface_ipv4(element), ipv6_addresses=_interface_ipv6(element), management_profile=_value(element, "interface-management-profile"), raw_extra=extra, explicit_fields=explicit)
    if kind in {"ethernet", "aggregate-ethernet", "loopback", "tunnel", "vlan"} and context.interface_family:
        mode_names = {child.tag for child in element if child.tag in {"layer3", "layer2", "virtual-wire", "tap", "ha", "decrypt-mirror"}}
        known = {"comment", "link-state", "speed", "duplex", "layer3", "layer2", "virtual-wire", "tap", "ha", "decrypt-mirror", "vlan", "lldp"}
        extra, explicit = _typed_fields(element, known)
        extra.update(_interface_mode_extra(element, mode_names))
        layer3 = element.find("layer3")
        return PANInterface(name=element.get("name"), source_path="/".join(path), scope=context.scope, source_order=source_order, interface_family=context.interface_family, mode=next(iter(mode_names)) if len(mode_names) == 1 else (sorted(mode_names) if mode_names else None), comment=_value(element, "comment"), link_state=_value(element, "link-state"), speed=_value(element, "speed"), duplex=_value(element, "duplex"), management_profile=_value(layer3, "interface-management-profile") if layer3 is not None else None, mtu=_value(layer3, "mtu") if layer3 is not None else None, ipv4_addresses=_interface_ipv4(layer3), ipv6_addresses=_interface_ipv6(layer3), vlan=_value(element, "vlan"), lldp_enable=_value(element.find("lldp"), "enable"), raw_extra=extra, explicit_fields=explicit)
    if rule_kind == "security":
        known = {"from", "to", "source", "destination", "source-user", "application", "service", "category", "source-hip", "destination-hip", "negate-source", "negate-destination", "schedule", "action", "rule-type", "description", "tag", "group-tag", "log-start", "log-end", "log-setting", "disabled", "profile-setting", "disable-inspect", "disable-server-response-inspection", "saas-user-list", "saas-tenant-list"}
        extra, explicit = _policy_fields(element, known)
        return PANSecurityRule(**common, rulebase_position=context.rulebase_position, from_zones=_values(element, "from"), to_zones=_values(element, "to"), source=_values(element, "source"), destination=_values(element, "destination"), source_user=_values(element, "source-user"), application=_values(element, "application"), service=_values(element, "service"), category=_values(element, "category"), source_hip=_values(element, "source-hip"), destination_hip=_values(element, "destination-hip"), negate_source=_value(element, "negate-source"), negate_destination=_value(element, "negate-destination"), schedule=_value(element, "schedule"), action=_value(element, "action"), rule_type=_value(element, "rule-type"), description=_value(element, "description"), tags=_values(element, "tag"), group_tag=_value(element, "group-tag"), log_start=_value(element, "log-start"), log_end=_value(element, "log-end"), log_setting=_value(element, "log-setting"), disabled=_value(element, "disabled"), profile_setting=_profile_setting(element), disable_inspect=_value(element, "disable-inspect"), disable_server_response_inspection=_value(element, "disable-server-response-inspection"), saas_user_list=_values(element, "saas-user-list"), saas_tenant_list=_values(element, "saas-tenant-list"), raw_extra=extra, explicit_fields=explicit)
    if rule_kind == "default-security-rules":
        known = {"action", "disabled", "log-start", "log-end", "log-setting", "description", "tag", "group-tag", "profile-setting", "disable-server-response-inspection", "option", "icmp-unreachable"}
        extra, explicit = _policy_fields(element, known)
        option = element.find("option")
        nested_disable = _value(option, "disable-server-response-inspection") if option is not None else None
        if nested_disable is not None:
            explicit.add("disable_server_response_inspection")
        return PANDefaultSecurityRule(**common, rulebase_position=context.rulebase_position, action=_value(element, "action"), disabled=_value(element, "disabled"), log_start=_value(element, "log-start"), log_end=_value(element, "log-end"), log_setting=_value(element, "log-setting"), description=_value(element, "description"), tags=_values(element, "tag"), group_tag=_value(element, "group-tag"), profile_setting=_profile_setting(element), disable_server_response_inspection=_value(element, "disable-server-response-inspection") or nested_disable, icmp_unreachable=_value(element, "icmp-unreachable"), raw_extra=extra, explicit_fields=explicit)
    if rule_kind == "nat":
        known = {"from", "to", "source", "destination", "service", "source-translation", "destination-translation", "dynamic-destination-translation", "disabled", "active-active-device-binding"}
        extra, explicit = _typed_fields(element, known)
        return PANNATRule(**common, rulebase_position=context.rulebase_position, from_zones=_values(element, "from"), to_zones=_values(element, "to"), source=_values(element, "source"), destination=_values(element, "destination"), service=_value(element, "service"), disabled=_value(element, "disabled"), active_active_device_binding=_value(element, "active-active-device-binding"), source_translation=_nat_source_translation(element), destination_translation=_nat_destination_translation(element), dynamic_destination_translation=_nat_dynamic_destination_translation(element), raw_extra=extra, explicit_fields=explicit)
    if kind == "virtual-router":
        return _routing_virtual_router(element, path, context, source_order)
    if kind == "logical-router":
        return _routing_logical_router(element, path, context, source_order)
    if kind in {"static", "route", "static-route"}:
        known = {"destination", "nexthop", "interface", "metric"}
        extra, explicit = _typed_fields(element, known)
        return PANStaticRoute(**common, destination=_value(element, "destination"), nexthop=_value(element, "nexthop"), interface=_value(element, "interface"), metric=_value(element, "metric"), raw_extra=extra, explicit_fields=explicit)
    return None


def build_panos_config(content: str) -> PANOSConfig:
    source = load_pan_source(content)
    scopes: list[PANScope] = []
    records: list[PANSourceRecord] = []
    typed: dict[str, list[object]] = {
        "addresses": [], "address_groups": [], "services": [], "service_groups": [],
        "schedules": [], "security_rules": [], "default_security_rules": [], "interfaces": [], "interface_imports": [], "interface_units": [], "nat_rules": [], "static_routes": [], "virtual_routers": [], "logical_routers": [],
    }

    for element, path, context in walk_pan_source(source.root):
        if context.scope and pan_scope_identity(context.scope) not in {
            pan_scope_identity(item) for item in scopes
        }:
            scopes.append(context.scope)
        if element.tag != "entry":
            if element.tag == "interface" and path[-3:] == ("import", "network", "interface"):
                model = _typed_record(element, path, context, len(records) + 1)
                if model is not None:
                    typed["interface_imports"].append(model)
            continue
        records.append(
            PANSourceRecord(
                kind=path[-2] if len(path) > 1 else "entry",
                source_path="/".join(path),
                name=element.get("name"),
                scope=context.scope,
                rulebase_position=context.rulebase_position,
                values=sanitize_source_attributes(_record_value(element)),
                source_order=len(records) + 1,
                raw_xml=sanitize_raw_text(ET.tostring(element, encoding="unicode")),
            )
        )
        model = _typed_record(element, path, context, len(records))
        if model is not None:
            key = {
                "PANAddress": "addresses", "PANAddressGroup": "address_groups",
                "PANService": "services", "PANServiceGroup": "service_groups",
                "PANSchedule": "schedules", "PANSecurityRule": "security_rules", "PANDefaultSecurityRule": "default_security_rules", "PANInterfaceImport": "interface_imports", "PANInterfaceUnit": "interface_units", "PANVirtualRouter": "virtual_routers", "PANLogicalRouter": "logical_routers",
                "PANInterface": "interfaces", "PANNATRule": "nat_rules",
                "PANStaticRoute": "static_routes",
            }[type(model).__name__]
            typed[key].append(model)

    return PANOSConfig(
        hostname=source.hostname,
        source_version=source.source_version,
        scopes=scopes,
        **typed,
        source_inventory=records,
    )
