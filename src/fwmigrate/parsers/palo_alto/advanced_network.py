import xml.etree.ElementTree as ET
from typing import Iterable
from fwmigrate.ir.core import IRDHCPServer, IRPANDNSProxy, IRPANDNSProxyDomainServer, IRPANMonitorProfile, IRPANQoSProfile, IRPANQoSClass
from .source_model import PANScope, pan_scope_identity
from .extraction import record_extract_only, record_parse_error
from .residual import record_unknown_children
from .xml_utils import member_texts, structured_xml_capture, text_or_none
from fwmigrate.extraction.sanitize import sanitize_source_attributes

def _b(e,path,reasons=None):
    v=text_or_none(e,path)
    if v == "yes": return True
    if v == "no": return False
    if v is not None and reasons is not None: reasons.append(f"Invalid PAN yes/no value at {path}: {v}")
    return None
def _n(e,path,reasons=None):
    v=text_or_none(e,path)
    try:return int(v) if v is not None else None
    except ValueError:
        if reasons is not None: reasons.append(f"Invalid integer at {path}: {v}")
        return None

def _f(e, path, reasons=None):
    value = text_or_none(e, path)
    if value is None:
        return None
    try:
        return float(value)
    except ValueError:
        if reasons is not None: reasons.append(f"Invalid number at {path}: {value}")
        return None

def _profile_entries(net, profiles, names: Iterable[str]):
    for name in names:
        entries = net.findall(f"./{name}/entry")
        if not entries and profiles is not None:
            entries = profiles.findall(f"./{name}/entry")
        if entries:
            return name, entries
    return None, []

def _members_or_value(entry, name):
    values = member_texts(entry, f"./{name}/member")
    scalar = text_or_none(entry, f"./{name}")
    return values or ([scalar] if scalar else [])


def _dhcp_children(entry, names):
    for name in names:
        found = entry.findall(f"./{name}/entry")
        if found:
            return found
    return []


def _extract_dhcp(scope, net, extraction):
    dhcp = net.find("./dhcp")
    if dhcp is None:
        return
    for index, entry in enumerate(dhcp.findall("./interface/entry")):
        server = IRDHCPServer(source_id=index, source_context=pan_scope_identity(scope),
                               interface=entry.get("name"), source_attributes=sanitize_source_attributes(structured_xml_capture(entry)))
        server.source_attributes.update({"pan_scope_kind": scope.kind, "pan_scope_name": scope.name,
                                         "pan_server_options": structured_xml_capture(entry.find("./options")),
                                         "pan_ip_pools": [structured_xml_capture(node) for node in _dhcp_children(entry, ("ip-pool", "pool"))],
                                         "pan_reservations": [structured_xml_capture(node) for node in _dhcp_children(entry, ("reservations", "reservation"))],
                                         "pan_user_defined_options": [structured_xml_capture(node) for node in _dhcp_children(entry, ("user-defined-options", "option"))]})
        extraction.canonical_ir.dhcp_servers.append(server)
        record_extract_only(extraction, "pan_dhcp_servers", "network/dhcp/interface/entry", scope, entry.get("name"),
                             server.source_attributes, notes=["PAN-OS DHCP server is source-only; DHCP client parsing is separate."], requires_manual_review=True)
    for family, nodes in (("ipv4", dhcp.findall("./relay/entry")), ("ipv6", dhcp.findall("./ipv6/relay/entry")),
                          ("ipv6", dhcp.findall("./dhcpv6/relay/entry")), ("ipv6", net.findall("./dhcpv6/relay/entry"))):
        for entry in nodes:
            name = entry.get("name")
            record_extract_only(extraction, f"pan_dhcp_{family}_relays", f"network/dhcp/{family}/relay/entry", scope, name,
                                sanitize_source_attributes({"pan_source_entry": structured_xml_capture(entry), "pan_scope_kind": scope.kind, "pan_scope_name": scope.name,
                                                             "pan_relay_servers": [structured_xml_capture(node) for node in entry.findall("./server/entry")]}),
                                notes=[f"PAN-OS {family} DHCP relay is source-only; IP-version lists remain separate."], requires_manual_review=True)

def extract_pan_advanced_network(scope: PANScope, root: ET.Element, extraction, resolver) -> None:
    net=root if root.tag == "network" else root.find("./network")
    if net is None:return
    _extract_dhcp(scope, net, extraction)
    for e in net.findall("./dns-proxy/entry"):
        if not e.get("name"):
            record_parse_error(extraction, "pan_dns_proxies", "network/dns-proxy/entry", scope, attributes=structured_xml_capture(e), notes=["PAN DNS Proxy is missing its name."])
            continue
        reasons=[]
        record_unknown_children(extraction, e, {'cache', 'default', 'default-server', 'tcp-queries', 'interface', 'enabled', 'domain-servers', 'domain-server'}, scope, f'network/dns-proxy/entry[@name="{e.get("name")}"]', 'pan_dns_proxies', 'Unknown PAN DNS Proxy child.')
        for parent, known, path in ((e.find('./cache'), {'enabled', 'cache-enabled', 'max-ttl'}, 'cache'), (e.find('./cache/max-ttl'), {'enabled'}, 'cache/max-ttl'), (e.find('./domain-servers'), {'entry'}, 'domain-servers'), (e.find('./default'), {'primary', 'secondary'}, 'default'), (e.find('./default-server'), {'primary', 'secondary'}, 'default-server'), (e.find('./tcp-queries'), {'enabled'}, 'tcp-queries')):
            if parent is not None: record_unknown_children(extraction, parent, known, scope, f'network/dns-proxy/entry[@name="{e.get("name")}"]/{path}', 'pan_dns_proxies', 'Unknown PAN DNS Proxy nested child.')
        p=IRPANDNSProxy(name=e.get("name") or "<unnamed>",source_context=pan_scope_identity(scope),enabled=_b(e,"./enabled",reasons),cache_enabled=_b(e,"./cache/enabled",reasons) if e.find("./cache/enabled") is not None else _b(e,"./cache/cache-enabled",reasons),max_ttl_enabled=_b(e,"./cache/max-ttl/enabled",reasons) if e.find("./cache/max-ttl/enabled") is not None else _b(e,"./cache/max-ttl-enabled",reasons),default_primary=text_or_none(e,"./default/primary") or text_or_none(e,"./default-server/primary"),default_secondary=text_or_none(e,"./default/secondary") or text_or_none(e,"./default-server/secondary"),tcp_queries_enabled=_b(e,"./tcp-queries/enabled",reasons) if e.find("./tcp-queries/enabled") is not None else _b(e,"./tcp-queries",reasons),interfaces=member_texts(e,"./interface/member"),review_reasons=reasons,source_attributes=sanitize_source_attributes(structured_xml_capture(e)))
        for d in e.findall("./domain-servers/entry") or e.findall("./domain-server/entry"):
            d_reasons=[]; name=d.get("name")
            if not name:
                record_parse_error(extraction, "pan_dns_proxies", "network/dns-proxy/entry/domain-servers/entry", scope, attributes=structured_xml_capture(d), notes=["PAN DNS Proxy domain server is missing its name."])
                continue
            p.domain_servers.append(IRPANDNSProxyDomainServer(name=name,domain_names=member_texts(d,"./domain-name/member") or member_texts(d,"./domain/member"),primary=text_or_none(d,"./primary"),secondary=text_or_none(d,"./secondary"),cacheable=_b(d,"./cacheable",d_reasons),review_reasons=d_reasons,source_attributes=sanitize_source_attributes(structured_xml_capture(d))))
            record_unknown_children(extraction, d, {'name', 'domain-name', 'domain', 'primary', 'secondary', 'cacheable'}, scope, f'network/dns-proxy/entry[@name="{e.get("name")}"]/domain-servers/entry[@name="{name}"]', 'pan_dns_proxies', 'Unknown PAN DNS Proxy domain-server child.')
        ir=extraction.canonical_ir; ir.pan_dns_proxies.append(p)
        for name in p.interfaces:
            obj = resolver.resolve(name, "interface", scope)
            if obj:
                p.resolved_interfaces.append(obj.canonical_name or name)
            else:
                p.unresolved_interfaces.append(name)
                reason = f"Unresolved PAN DNS Proxy interface: {name}"
                if reason not in p.review_reasons:
                    p.review_reasons.append(reason)
        record_extract_only(extraction,"pan_dns_proxies","network/dns-proxy/entry",scope,p.name,p.source_attributes,notes=["PAN DNS Proxy is source-only."],requires_manual_review=True)
    profiles=net.find("./profiles")
    if profiles is not None:
        for e in profiles.findall("./monitor-profile/entry"):
            if not e.get("name"):
                record_parse_error(extraction, "pan_monitor_profiles", "network/profiles/monitor-profile/entry", scope, attributes=structured_xml_capture(e), notes=["PAN monitor profile is missing its name."])
                continue
            p=IRPANMonitorProfile(name=e.get("name"),source_context=pan_scope_identity(scope),interval_seconds=_n(e,"./interval"),threshold=_n(e,"./threshold"),action=text_or_none(e,"./action"),source_attributes=sanitize_source_attributes(structured_xml_capture(e)))
            record_unknown_children(extraction, e, {'name', 'interval', 'threshold', 'action'}, scope, f'network/profiles/monitor-profile/entry[@name="{e.get("name")}"]', 'pan_monitor_profiles', 'Unknown PAN monitor profile child.')
            extraction.canonical_ir.pan_monitor_profiles.append(p); record_extract_only(extraction,"pan_monitor_profiles","network/profiles/monitor-profile/entry",scope,p.name,p.source_attributes,notes=["PAN monitor profile is source-only."],requires_manual_review=True)
    qos_entries=net.findall("./qos/profile/entry") or (profiles.findall("./qos/entry") if profiles is not None else [])
    for e in qos_entries:
        record_unknown_children(extraction, e, {'name', 'class-bandwidth-type', 'egress-max', 'egress-guaranteed'}, scope, f'network/profiles/qos/entry[@name="{e.get("name")}"]', 'pan_qos_profiles', 'Unknown PAN QoS profile child.')
        p=IRPANQoSProfile(name=e.get("name") or "<unnamed>",source_context=pan_scope_identity(scope),bandwidth_type="mbps" if e.find("./class-bandwidth-type/mbps") is not None else "percentage" if e.find("./class-bandwidth-type/percentage") is not None else None,egress_max=_f(e,"./egress-max"),egress_guaranteed=_f(e,"./egress-guaranteed"),source_attributes=sanitize_source_attributes(structured_xml_capture(e)))
        base=e.find("./class-bandwidth-type")
        if base is None: base=e
        for c in base.findall(".//class/entry"):
            record_unknown_children(extraction, c, {'name', 'priority', 'egress-max', 'egress-guaranteed'}, scope, f'network/profiles/qos/entry[@name="{e.get("name")}"]/class/entry', 'pan_qos_profiles', 'Unknown PAN QoS class child.')
            priority = text_or_none(c, "./priority")
            attrs = sanitize_source_attributes(structured_xml_capture(c))
            if priority is not None and not priority.isdigit():
                attrs["review_reasons"] = [f"Invalid QoS class numeric priority: {priority}"]
            p.classes.append(IRPANQoSClass(name=c.get("name") or "<unnamed>",priority=priority,egress_max=_f(c,"./egress-max"),egress_guaranteed=_f(c,"./egress-guaranteed"),source_attributes=attrs))
        if base is not e:
            record_unknown_children(extraction, base, {'mbps', 'percentage'}, scope, f'network/profiles/qos/entry[@name="{e.get("name")}"]/class-bandwidth-type', 'pan_qos_profiles', 'Unknown PAN QoS bandwidth type.')
        extraction.canonical_ir.pan_qos_profiles.append(p); record_extract_only(extraction,"pan_qos_profiles","network/profiles/qos/entry",scope,p.name,p.source_attributes,notes=["PAN QoS profile is source-only."],requires_manual_review=True)

    qos_interfaces = net.findall("./qos/interface/entry")
    for entry in qos_interfaces:
        attrs = sanitize_source_attributes({"pan_source_entry": structured_xml_capture(entry),
                                             "pan_interface": entry.get("name"),
                                             "pan_enabled": text_or_none(entry, "./enabled"),
                                             "pan_bandwidth": text_or_none(entry, "./bandwidth"),
                                             "pan_tunnel": structured_xml_capture(entry.find("./tunnel")),
                                             "pan_regular": structured_xml_capture(entry.find("./regular")),
                                             "pan_groups": [structured_xml_capture(node) for node in entry.findall("./*/member")]})
        record_extract_only(extraction, "pan_qos_interfaces", "network/qos/interface/entry", scope, entry.get("name"), attrs,
                            notes=["PAN QoS interface assignment is separate from QoS profile definitions."], requires_manual_review=True)

    for domain, names in (
        ("pan_sdwan_interface_profiles", ("sdwan-interface-profile",)),
        ("pan_sdwan_path_quality_profiles", ("sdwan-path-quality", "sdwan-path-quality-profile")),
        ("pan_sdwan_traffic_distribution_profiles", ("traffic-distribution-profile", "sdwan-traffic-distribution-profile")),
    ):
        source_name, entries = _profile_entries(net, profiles, names)
        for entry in entries:
            name = entry.get("name")
            path = f"network/profiles/{source_name}/entry[@name='{name}']"
            attrs = {"pan_source_entry": sanitize_source_attributes(structured_xml_capture(entry)),
                     "pan_scope_kind": scope.kind, "pan_scope_name": scope.name,
                     "pan_source_context": pan_scope_identity(scope)}
            if domain == "pan_sdwan_interface_profiles":
                path_monitoring = entry.find("./path-monitoring")
                attrs.update({"pan_path_monitoring": structured_xml_capture(path_monitoring) if path_monitoring is not None else None,
                              "pan_vpn_failover_metric": text_or_none(entry, "./vpn-failover/metric") or text_or_none(entry, "./vpn-failover-metric"),
                              "pan_probe_settings": structured_xml_capture(entry.find("./probe")) if entry.find("./probe") is not None else structured_xml_capture(entry.find("./path-monitoring/probe")) if entry.find("./path-monitoring/probe") is not None else None})
            elif domain == "pan_sdwan_path_quality_profiles":
                attrs.update({"pan_latency": _n(entry, "./latency"), "pan_jitter": _n(entry, "./jitter"),
                              "pan_packet_loss": _n(entry, "./packet-loss"), "pan_sensitivity": text_or_none(entry, "./sensitivity")})
            else:
                attrs.update({"pan_traffic_distribution_method": text_or_none(entry, "./method") or text_or_none(entry, "./distribution-method"),
                              "pan_link_tags": _members_or_value(entry, "link-tag"), "pan_weights": _members_or_value(entry, "weight")})
            record_extract_only(extraction, domain, path, scope, name, attrs,
                                notes=["PAN-OS SD-WAN profile retained as typed source-only evidence."],
                                requires_manual_review=True)

    zone_profiles = net.findall("./profiles/zone-protection-profile/entry")
    for entry in zone_profiles:
        name = entry.get("name")
        path = f"network/profiles/zone-protection-profile/entry[@name='{name}']"
        attrs = {"pan_profile_type": "zone-protection-profile",
                 "pan_flood_settings": structured_xml_capture(entry.find("./flood")),
                 "pan_reconnaissance_settings": structured_xml_capture(entry.find("./reconnaissance")),
                 "pan_packet_based_settings": structured_xml_capture(entry.find("./packet-based")),
                 "pan_network_inspection_settings": structured_xml_capture(entry.find("./network-inspection")),
                 "pan_source_entry": sanitize_source_attributes(structured_xml_capture(entry))}
        if name:
            resolver.register_object(PANSourceObject(name=name, kind="zone-protection-profile", domain="zone-protection-profile", source_path=path, scope=scope, attributes=attrs), "zone-protection-profile")
        record_extract_only(extraction, "zone_protection_profiles", path, scope, name, attrs,
                            notes=["PAN-OS zone-protection profile retained as typed source-only evidence."], requires_manual_review=True)
