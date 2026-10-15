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
