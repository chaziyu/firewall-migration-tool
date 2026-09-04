import xml.etree.ElementTree as ET
from fwmigrate.ir.core import IRPANDNSProxy, IRPANDNSProxyDomainServer, IRPANMonitorProfile, IRPANQoSProfile, IRPANQoSClass
from .source_model import PANScope, pan_scope_identity
from .extraction import record_extract_only
from .xml_utils import member_texts, structured_xml_capture, text_or_none
from fwmigrate.extraction.sanitize import sanitize_source_attributes

def _b(e,path):
    v=text_or_none(e,path); return True if v=="yes" else False if v=="no" else None
def _n(e,path):
    v=text_or_none(e,path)
    try:return int(v) if v is not None else None
    except ValueError:return None

def extract_pan_advanced_network(scope: PANScope, root: ET.Element, extraction, resolver) -> None:
    net=root if root.tag == "network" else root.find("./network")
    if net is None:return
    for e in net.findall("./dns-proxy/entry"):
        p=IRPANDNSProxy(name=e.get("name") or "<unnamed>",source_context=pan_scope_identity(scope),enabled=_b(e,"./enabled"),cache_enabled=_b(e,"./cache/cache-enabled"),max_ttl_enabled=_b(e,"./cache/max-ttl-enabled"),default_primary=text_or_none(e,"./default-server/primary"),default_secondary=text_or_none(e,"./default-server/secondary"),tcp_queries_enabled=_b(e,"./tcp-queries"),interfaces=member_texts(e,"./interface/member"),source_attributes=sanitize_source_attributes(structured_xml_capture(e)))
        for d in e.findall("./domain-server/entry"):
            p.domain_servers.append(IRPANDNSProxyDomainServer(name=d.get("name") or "<unnamed>",domain_names=member_texts(d,"./domain/member") or member_texts(d,"./domain-name/member"),primary=text_or_none(d,"./primary"),secondary=text_or_none(d,"./secondary"),cacheable=_b(d,"./cacheable"),source_attributes=sanitize_source_attributes(structured_xml_capture(d))))
        ir=extraction.canonical_ir; ir.pan_dns_proxies.append(p); record_extract_only(extraction,"pan_dns_proxies","network/dns-proxy/entry",scope,p.name,p.source_attributes,notes=["PAN DNS Proxy is source-only."],requires_manual_review=True)
    profiles=net.find("./profiles")
    if profiles is None:return
    for e in profiles.findall("./monitor-profile/entry"):
        p=IRPANMonitorProfile(name=e.get("name") or "<unnamed>",source_context=pan_scope_identity(scope),interval_seconds=_n(e,"./interval"),threshold=_n(e,"./threshold"),action=text_or_none(e,"./action"),source_attributes=sanitize_source_attributes(structured_xml_capture(e)))
        extraction.canonical_ir.pan_monitor_profiles.append(p); record_extract_only(extraction,"pan_monitor_profiles","network/profiles/monitor-profile/entry",scope,p.name,p.source_attributes,notes=["PAN monitor profile is source-only."],requires_manual_review=True)
    for e in profiles.findall("./qos/entry"):
        p=IRPANQoSProfile(name=e.get("name") or "<unnamed>",source_context=pan_scope_identity(scope),bandwidth_type="mbps" if e.find("./class-bandwidth-type/mbps") is not None else "percentage" if e.find("./class-bandwidth-type/percentage") is not None else None,source_attributes=sanitize_source_attributes(structured_xml_capture(e)))
        base=e.find("./class-bandwidth-type") or e
        for c in base.findall(".//class/entry"):
            p.classes.append(IRPANQoSClass(name=c.get("name") or "<unnamed>",priority=text_or_none(c,"./priority"),egress_max=None,egress_guaranteed=None,source_attributes=sanitize_source_attributes(structured_xml_capture(c))))
        extraction.canonical_ir.pan_qos_profiles.append(p); record_extract_only(extraction,"pan_qos_profiles","network/profiles/qos/entry",scope,p.name,p.source_attributes,notes=["PAN QoS profile is source-only."],requires_manual_review=True)
