import xml.etree.ElementTree as ET
from fwmigrate.ir.core import IRPANDNSProxy, IRPANDNSProxyDomainServer, IRPANMonitorProfile, IRPANQoSProfile, IRPANQoSClass
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

def extract_pan_advanced_network(scope: PANScope, root: ET.Element, extraction, resolver) -> None:
    net=root if root.tag == "network" else root.find("./network")
    if net is None:return
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
        p=IRPANQoSProfile(name=e.get("name") or "<unnamed>",source_context=pan_scope_identity(scope),bandwidth_type="mbps" if e.find("./class-bandwidth-type/mbps") is not None else "percentage" if e.find("./class-bandwidth-type/percentage") is not None else None,egress_max=float(text_or_none(e,"./egress-max")) if text_or_none(e,"./egress-max") else None,egress_guaranteed=float(text_or_none(e,"./egress-guaranteed")) if text_or_none(e,"./egress-guaranteed") else None,source_attributes=sanitize_source_attributes(structured_xml_capture(e)))
        base=e.find("./class-bandwidth-type")
        if base is None: base=e
        for c in base.findall(".//class/entry"):
            record_unknown_children(extraction, c, {'name', 'priority', 'egress-max', 'egress-guaranteed'}, scope, f'network/profiles/qos/entry[@name="{e.get("name")}"]/class/entry', 'pan_qos_profiles', 'Unknown PAN QoS class child.')
            priority = text_or_none(c, "./priority")
            attrs = sanitize_source_attributes(structured_xml_capture(c))
            if priority is not None and not priority.isdigit():
                attrs["review_reasons"] = [f"Invalid QoS class numeric priority: {priority}"]
            p.classes.append(IRPANQoSClass(name=c.get("name") or "<unnamed>",priority=priority,egress_max=None,egress_guaranteed=None,source_attributes=attrs))
        if base is not e:
            record_unknown_children(extraction, base, {'mbps', 'percentage'}, scope, f'network/profiles/qos/entry[@name="{e.get("name")}"]/class-bandwidth-type', 'pan_qos_profiles', 'Unknown PAN QoS bandwidth type.')
        extraction.canonical_ir.pan_qos_profiles.append(p); record_extract_only(extraction,"pan_qos_profiles","network/profiles/qos/entry",scope,p.name,p.source_attributes,notes=["PAN QoS profile is source-only."],requires_manual_review=True)
