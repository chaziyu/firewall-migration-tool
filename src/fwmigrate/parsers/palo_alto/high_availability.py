import xml.etree.ElementTree as ET
from fwmigrate.ir.core import IRPANHighAvailability, IRPANHAInterface, IRPANHALinkMonitorGroup, IRPANHAPathMonitorGroup
from .source_model import PANScope, pan_scope_identity
from .extraction import record_extract_only
from .xml_utils import member_texts, structured_xml_capture, text_or_none
from fwmigrate.extraction.sanitize import sanitize_source_attributes

def _b(e,p):
    v=text_or_none(e,p); return True if v=='yes' else False if v=='no' else None
def _i(e,p):
    v=text_or_none(e,p)
    try:return int(v) if v is not None else None
    except ValueError:return None

def extract_pan_high_availability(scope: PANScope, device: ET.Element, extraction) -> None:
    node=device.find('./deviceconfig/high-availability')
    if node is None:return
    p=IRPANHighAvailability(source_context=pan_scope_identity(scope),enabled=_b(node,'./enabled'),group_id=_i(node,'./group/group-id'),description=text_or_none(node,'./group/description'),peer_ip=text_or_none(node,'./group/peer-ip'),preemptive=_b(node,'./election-option/preemptive'),recommended_timers=node.find('./election-option/recommended-timers') is not None,ha2_keep_alive_enabled=_b(node,'./synchronization/ha2-keep-alive/enabled'),source_attributes=sanitize_source_attributes(structured_xml_capture(node)))
    link=node.find('./link-monitoring')
    if link is not None:
        p.link_monitoring_enabled=_b(link,'./enabled'); p.link_monitoring_failure_condition=text_or_none(link,'./failure-condition')
        for e in link.findall('.//group/entry'):
            p.link_groups.append(IRPANHALinkMonitorGroup(name=e.get('name') or '<unnamed>',interfaces=member_texts(e,'./interface/member'),enabled=_b(e,'./enabled'),failure_condition=text_or_none(e,'./failure-condition'),source_attributes=sanitize_source_attributes(structured_xml_capture(e))))
    path=node.find('./path-monitoring')
    if path is not None:
        p.path_monitoring_enabled=_b(path,'./enabled'); p.path_monitoring_failure_condition=text_or_none(path,'./failure-condition')
        for e in path.findall('.//group/entry'):
            p.path_groups.append(IRPANHAPathMonitorGroup(name=e.get('name') or '<unnamed>',routing_instance=text_or_none(e,'./routing-instance'),destination_ips=member_texts(e,'./destination-ip/member'),failure_condition=text_or_none(e,'./failure-condition'),ping_interval_ms=_i(e,'./ping-interval'),source_attributes=sanitize_source_attributes(structured_xml_capture(e))))
    for tag in ('ha1','ha1-backup','ha2','ha2-backup','ha3'):
        e=node.find(f'./interface/{tag}')
        if e is not None:p.interfaces.append(IRPANHAInterface(name=tag,ip_address=text_or_none(e,'./ip-address'),netmask=text_or_none(e,'./netmask'),source_attributes=sanitize_source_attributes(structured_xml_capture(e))))
    extraction.canonical_ir.pan_high_availability=p
    record_extract_only(extraction,'pan_high_availability','deviceconfig/high-availability',scope,scope.name,p.source_attributes,notes=['PAN high availability is source-only.'],requires_manual_review=True)
