"""Version-verified effective values, separate from explicit FortiGate state."""
from dataclasses import dataclass

from .policies import effective_policy_action


@dataclass(frozen=True, slots=True)
class FGEffectiveValue:
    vdom: str
    kind: str
    name: str
    field: str
    value: str | int
    version: str
    reference: str
    origin: str = 'FORTIOS_DEFAULT'


def derive_effective_values(config, source_metadata=None):
    version = getattr(source_metadata, 'fortios_version', None)
    if version != '7.2.13':
        return ()
    policy_reference = 'https://docs2.fortinet.com/document/fortigate/7.2.13/cli-reference/333889629/config-firewall-policy'
    vip_reference = 'https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/9b85aed5-fafc-11f0-8b43-d2943efe5b2f/FortiOS-7.2.13-CLI_Reference.pdf'
    result = [FGEffectiveValue(item.vdom or 'root', 'policy', str(item.policy_id), 'action',
        effective_policy_action(item.action), version, policy_reference)
        for item in config.policies if item.action is None]
    result.extend(FGEffectiveValue(item.vdom or 'root', 'vip', item.name, 'type', 'static-nat',
        version, vip_reference) for item in config.vips if item.type is None)
    for item in config.addresses:
        if item.address_family != 'ipv4':
            continue
        if item.type is None:
            result.append(FGEffectiveValue(item.vdom or 'root', 'address', item.name, 'type', 'ipmask',
                version, vip_reference + '#page=355'))
        if item.type in {None, 'ipmask'} and item.subnet is None:
            result.append(FGEffectiveValue(item.vdom or 'root', 'address', item.name, 'subnet', '0.0.0.0 0.0.0.0',
                version, vip_reference + '#page=354'))
    for kind, items, defaults in (
        ('ip_pool', config.ip_pools, (('type', 'overload', 403),)),
        ('vip', config.vips, (('protocol', 'tcp', 572),)),
        ('policy', config.policies, (('nat', 'disable', 435), ('status', 'enable', 441),
            ('srcaddr_negate', 'disable', 440), ('dstaddr_negate', 'disable', 428),
            ('service_negate', 'disable', 440), ('utm_status', 'disable', 442),
            ('logtraffic', 'utm', 434))),
        ('interface', config.interfaces, (('mode', 'static', 1405), ('status', 'up', 1414))),
        ('static_route', config.static_routes, (('status', 'enable', 1013), ('distance', 10, 1012),
            ('dst', '0.0.0.0 0.0.0.0', 1012), ('priority', 1, 1013))),
        ('service', tuple(item for item in config.services if item.protocol == 'IP'), (('protocol_number', 0, 504),)),
        ('dhcp_server', config.dhcp_servers, (('status', 'enable', 1238), ('server_type', 'regular', 1238),
            ('ip_mode', 'range', 1237), ('dns_service', 'specify', 1236), ('lease_time', 604800, 1237))),
    ):
        for item in items:
            name = (item.policy_id if kind == 'policy' else item.id if kind == 'dhcp_server'
                    else item.seq_num if kind == 'static_route' else item.name)
            for field, value, page in defaults:
                if getattr(item, field) is None:
                    result.append(FGEffectiveValue(item.vdom or 'root', kind, str(name), field, value,
                        version, vip_reference + f'#page={page}'))
    # FortiOS 7.2.13 CLI reference, phase2-interface table, printed page 1939.
    for item in config.ipsec_phase2:
        for field, value in (('pfs', 'enable'), ('keylifeseconds', 43200)):
            if getattr(item, field) is None:
                result.append(FGEffectiveValue(item.vdom or 'root', 'ipsec_phase2', item.name, field,
                    value, version, vip_reference + '#page=1939'))
    return tuple(result)


def effective_value(derived, vdom, kind, name, field):
    return next((item.value for item in getattr(derived, 'effective_values', ())
        if (item.vdom, item.kind, item.name, item.field) == (vdom or 'root', kind, str(name), field)), None)
