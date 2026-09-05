import xml.etree.ElementTree as ET
from fwmigrate.ir.core import IRPANHighAvailability, IRPANHAInterface, IRPANHALinkMonitorGroup, IRPANHAPathMonitorGroup
from .source_model import PANScope, pan_scope_identity
from .extraction import record_extract_only, record_parse_error
from .residual import record_unknown_children
from .xml_utils import member_texts, structured_xml_capture, text_or_none
from fwmigrate.extraction.sanitize import sanitize_source_attributes

def _b(e,p,reasons=None):
    v=text_or_none(e,p)
    if v in ('yes', 'no'): return v == 'yes'
    if v is not None and reasons is not None: reasons.append(f'Invalid PAN yes/no value at {p}: {v}')
    return None
def _i(e,p,reasons=None):
    v=text_or_none(e,p)
    try:return int(v) if v is not None else None
    except ValueError:
        if reasons is not None: reasons.append(f'Invalid integer at {p}: {v}')
        return None

def extract_pan_high_availability(scope: PANScope, device: ET.Element, extraction, resolver) -> None:
    node=device.find('./deviceconfig/high-availability')
    if node is None:return
    group=node.find('./group'); election=node.find('./election-option'); sync=node.find('./state-synchronization')
    record_unknown_children(extraction, node, {'group', 'interface', 'enabled', 'election-option', 'state-synchronization', 'monitoring'}, scope, 'deviceconfig/high-availability', 'pan_high_availability', 'Unknown PAN HA child.')
    for parent, known, path in ((group, {'group-id', 'description', 'peer-ip', 'election-option', 'state-synchronization', 'monitoring'}, 'group'), (election, {'preemptive', 'timers'}, 'election-option'), (election.find('./timers') if election is not None else None, {'recommended'}, 'election-option/timers'), (sync, {'ha2-keep-alive'}, 'state-synchronization'), (sync.find('./ha2-keep-alive') if sync is not None else None, {'enabled'}, 'state-synchronization/ha2-keep-alive')):
        if parent is not None: record_unknown_children(extraction, parent, known, scope, f'deviceconfig/high-availability/{path}', 'pan_high_availability', 'Unknown PAN HA nested child.')
    reasons=[]
    p=IRPANHighAvailability(source_context=pan_scope_identity(scope),enabled=_b(node,'./enabled',reasons),group_id=_i(group,'./group-id',reasons),description=text_or_none(group,'./description'),peer_ip=text_or_none(group,'./peer-ip'),preemptive=_b(election,'./preemptive',reasons),recommended_timers=election is not None and election.find('./timers/recommended') is not None,ha2_keep_alive_enabled=_b(sync,'./ha2-keep-alive/enabled',reasons),review_reasons=reasons,source_attributes=sanitize_source_attributes(structured_xml_capture(node)))
    monitoring=node.find('./monitoring')
    if monitoring is None: monitoring=node
    link=monitoring.find('./link-monitoring')
    if link is not None:
        record_unknown_children(extraction, link, {'link-group', 'enabled', 'failure-condition'}, scope, 'deviceconfig/high-availability/monitoring/link-monitoring', 'pan_high_availability', 'Unknown PAN HA link-monitoring child.')
        p.link_monitoring_enabled=_b(link,'./enabled'); p.link_monitoring_failure_condition=text_or_none(link,'./failure-condition')
        for e in link.findall('./link-group/entry') or link.findall('.//group/entry'):
            if not e.get('name'):
                record_parse_error(extraction, 'pan_high_availability', 'deviceconfig/high-availability/monitoring/link-monitoring/link-group/entry', scope, attributes=structured_xml_capture(e), notes=['PAN HA link-monitor group is missing its name.'])
                continue
            p.link_groups.append(IRPANHALinkMonitorGroup(name=e.get('name') or '<unnamed>',interfaces=member_texts(e,'./interface/member'),enabled=_b(e,'./enabled'),failure_condition=text_or_none(e,'./failure-condition'),source_attributes=sanitize_source_attributes(structured_xml_capture(e))))
            record_unknown_children(extraction, e, {'name', 'interface', 'enabled', 'failure-condition'}, scope, 'deviceconfig/high-availability/monitoring/link-monitoring/link-group/entry', 'pan_high_availability', 'Unknown PAN HA link group child.')
    path=monitoring.find('./path-monitoring')
    if path is not None:
        record_unknown_children(extraction, path, {'path-group', 'enabled', 'failure-condition'}, scope, 'deviceconfig/high-availability/monitoring/path-monitoring', 'pan_high_availability', 'Unknown PAN HA path-monitoring child.')
        path_group = path.find('./path-group')
        if path_group is not None:
            record_unknown_children(extraction, path_group, {'virtual-router', 'enabled', 'failure-condition'}, scope, 'deviceconfig/high-availability/monitoring/path-monitoring/path-group', 'pan_high_availability', 'Unknown PAN HA path-group child.')
            virtual_router = path_group.find('./virtual-router')
            if virtual_router is not None: record_unknown_children(extraction, virtual_router, {'entry'}, scope, 'deviceconfig/high-availability/monitoring/path-monitoring/path-group/virtual-router', 'pan_high_availability', 'Unknown PAN HA virtual-router child.')
        p.path_monitoring_enabled=_b(path,'./enabled'); p.path_monitoring_failure_condition=text_or_none(path,'./failure-condition')
        for e in path.findall('./path-group/virtual-router/entry') or path.findall('.//group/entry'):
            if not e.get('name'):
                record_parse_error(extraction, 'pan_high_availability', 'deviceconfig/high-availability/monitoring/path-monitoring/path-group/virtual-router/entry', scope, attributes=structured_xml_capture(e), notes=['PAN HA path-monitor group is missing its name.'])
                continue
            p.path_groups.append(IRPANHAPathMonitorGroup(name=e.get('name') or '<unnamed>',routing_instance=e.get('name') if path.findall('./path-group/virtual-router/entry') else text_or_none(e,'./routing-instance'),destination_ips=member_texts(e,'./destination-ip/member'),failure_condition=text_or_none(e,'./failure-condition'),ping_interval_ms=_i(e,'./ping-interval'),source_attributes=sanitize_source_attributes(structured_xml_capture(e))))
            record_unknown_children(extraction, e, {'name', 'destination-ip', 'failure-condition', 'ping-interval', 'routing-instance'}, scope, 'deviceconfig/high-availability/monitoring/path-monitoring/path-group/virtual-router/entry', 'pan_high_availability', 'Unknown PAN HA path group child.')
    for tag in ('ha1','ha1-backup','ha2','ha2-backup','ha3'):
        e=node.find(f'./interface/{tag}')
        if e is not None:
            record_unknown_children(extraction, e, {'ip-address', 'netmask'}, scope, f'deviceconfig/high-availability/interface/{tag}', 'pan_high_availability', 'Unknown PAN HA interface child.')
            p.interfaces.append(IRPANHAInterface(name=tag,ip_address=text_or_none(e,'./ip-address'),netmask=text_or_none(e,'./netmask'),source_attributes=sanitize_source_attributes(structured_xml_capture(e))))
    extraction.canonical_ir.pan_high_availability=p
    for group in p.link_groups:
        for name in group.interfaces:
            obj = resolver.resolve(name, "interface", scope)
            if obj:
                group.resolved_interfaces.append(obj.canonical_name or name)
            else:
                group.unresolved_interfaces.append(name)
                p.source_attributes.setdefault("pan_review_reasons", []).append(
                    f"Unresolved PAN HA link-monitor interface: {name}"
                )
    for group in p.path_groups:
        if not group.routing_instance:
            continue
        obj = resolver.resolve(group.routing_instance, "routing-instance", scope)
        group.routing_instance_resolved = obj.canonical_name if obj else False
        group.resolved_routing_instance = obj.canonical_name if obj else None
        if not obj:
            p.source_attributes.setdefault("pan_review_reasons", []).append(
                f"Unresolved PAN HA path-monitor routing instance: {group.routing_instance}"
            )
    record_extract_only(extraction,'pan_high_availability','deviceconfig/high-availability',scope,scope.name,p.source_attributes,notes=['PAN high availability is source-only.'],requires_manual_review=True)
