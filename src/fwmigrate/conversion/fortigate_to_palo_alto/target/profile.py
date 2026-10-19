"""Explicit design settings; configured XML interfaces are not hardware inventory."""
import re
from dataclasses import replace
from ipaddress import ip_network

# PA-800 Hardware Reference: data ports 1-12; MGT and HA are separate.
MODEL_PORTS = {'PA-820': tuple(f'ethernet1/{number}' for number in range(1, 13))}


def _valid_scoped_key(value, kinds=None):
    if not isinstance(value, str):
        return False
    vdom, separator, identity = value.partition('/')
    if not vdom or not separator or not identity or '\n' in identity:
        return False
    if kinds is None:
        return True
    kind, separator, identity = identity.partition('/')
    return bool(separator and identity and kind in kinds and '\n' not in identity)


def parse_conversion_settings(value):
    if value is None:
        return {}
    if not isinstance(value, dict) or set(value) - {'target_model', 'panos_version', 'excluded_interfaces', 'management_profiles', 'generated_management_profiles', 'existing_vpns', 'vpn_parameters', 'security_profiles', 'identity_mappings', 'identity_prerequisites', 'vip_external_zones'}:
        raise ValueError('Invalid conversion settings')
    result = dict(value)
    from .name_validation import zone_name_issue
    vip_zones = result.get('vip_external_zones', {})
    if not isinstance(vip_zones, dict):
        raise ValueError('VIP external zones must map VDOM to VIP name and target zone')
    for vdom, mappings in vip_zones.items():
        if not isinstance(vdom, str) or not vdom or not isinstance(mappings, dict):
            raise ValueError('Invalid scoped VIP external zones')
        for name, zone in mappings.items():
            if not isinstance(name, str) or not name or not isinstance(zone, str) or zone == 'any' or zone_name_issue(zone):
                raise ValueError('VIP original-packet destination zone must be an explicit valid target zone')
    identities = result.get('identity_mappings', {})
    if not isinstance(identities, dict):
        raise ValueError('Invalid scoped identity mappings')
    for vdom, mappings in identities.items():
        if not isinstance(vdom, str) or not isinstance(mappings, dict):
            raise ValueError('Invalid scoped identity mappings')
        for key, name in mappings.items():
            if (not isinstance(key, str) or not key.startswith(('user/', 'group/')) or not key.split('/', 1)[1]
                    or not valid_target_identity(name)):
                raise ValueError('Identity mappings require explicit target user/group names')
    prerequisites = result.get('identity_prerequisites', [])
    if not isinstance(prerequisites, list) or any(not isinstance(vdom, str) or not vdom for vdom in prerequisites):
        raise ValueError('Identity prerequisites must select source VDOMs')
    generated = result.get('generated_management_profiles', {})
    if not isinstance(generated, dict):
        raise ValueError('Invalid generated management profiles')
    normalized = {}
    for key, settings in generated.items():
        if (not isinstance(key, str) or '/' not in key or not isinstance(settings, dict)
                or set(settings) != {'permitted_ips'} or not isinstance(settings['permitted_ips'], list)
                or not 1 <= len(settings['permitted_ips']) <= 64):
            raise ValueError('Generated management profiles require reviewed permitted networks')
        try:
            networks = [str(ip_network(network, strict=True)) for network in settings['permitted_ips'] if isinstance(network, str)]
            if len(networks) != len(settings['permitted_ips']):
                raise ValueError('Invalid network')
        except ValueError as exc:
            raise ValueError('Management permitted networks must be explicit valid CIDRs') from exc
        normalized[key] = {'permitted_ips': sorted(set(networks))}
    if 'generated_management_profiles' in result:
        result['generated_management_profiles'] = normalized
    if result.get('target_model') not in {None, '', *MODEL_PORTS}:
        raise ValueError('Unsupported target hardware model')
    if result.get('panos_version') not in {None, '', '11.1'}:
        raise ValueError('Supported PAN-OS command version is 11.1')
    excluded = result.get('excluded_interfaces', [])
    if not isinstance(excluded, list) or any(not _valid_scoped_key(key) for key in excluded):
        raise ValueError('Excluded interfaces must preserve VDOM/name identity')
    if 'excluded_interfaces' in result:
        result['excluded_interfaces'] = sorted(set(excluded))
    existing_vpns = result.get('existing_vpns', [])
    if not isinstance(existing_vpns, list) or any(not _valid_scoped_key(key) for key in existing_vpns):
        raise ValueError('Existing VPN prerequisites must preserve VDOM/name identity')
    if 'existing_vpns' in result:
        result['existing_vpns'] = sorted(set(existing_vpns))
    profiles = result.get('management_profiles', {})
    if not isinstance(profiles, dict) or any(not isinstance(key, str) or '/' not in key
            or not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,31}', name) for key, name in profiles.items()):
        raise ValueError('Management profiles must map VDOM/interface to an existing target profile name')
    security_profiles = result.get('security_profiles', {})
    if not isinstance(security_profiles, dict) or any(not isinstance(key, str) or '/' not in key
            or not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_. -]{1,63}', name) or not name.strip()
            for key, name in security_profiles.items()):
        raise ValueError('Invalid reviewed target security profile groups')
    parameters = result.get('vpn_parameters', {})
    if not isinstance(parameters, dict):
        raise ValueError('VPN parameters must be scoped target-design decisions')
    for key, fields in parameters.items():
        if (not _valid_scoped_key(key, {'ipsec_phase1', 'ipsec_phase2'})
                or not isinstance(fields, dict) or set(fields) - {'lifetime_seconds', 'dh_group', 'pfs', 'ike_version'}):
            raise ValueError('Invalid non-secret VPN parameters')
        lifetime = fields.get('lifetime_seconds')
        if lifetime is not None and (type(lifetime) is not int or not 180 <= lifetime <= 65535 * 3600):
            raise ValueError('Invalid VPN lifetime')
        if fields.get('pfs') not in {None, 'enable', 'disable'} or fields.get('ike_version') not in {None, '1', '2'}:
            raise ValueError('Invalid VPN PFS or IKE version')
        if fields.get('dh_group') not in {None, 'group14', 'group15', 'group16', 'group19', 'group20', 'group21'}:
            raise ValueError('Unsupported reviewed DH group')
    return result


def bind_vip_external_zones(plan, settings, target=None, device=None):
    """Verify explicit target choices against planned zones or selected destination evidence."""
    from .target_suggestions import _device
    references = set()
    for vdom, mappings in settings.get('vip_external_zones', {}).items():
        for name, zone in mappings.items():
            rules = [rule for rule in plan.nat_rules if (rule.source_vdom or 'root') == vdom
                     and rule.source_kind == 'vip' and rule.source_name == name]
            vsys = rules[0].target_vsys if rules else None
            if not vsys:
                raise ValueError(f'VIP {vdom}/{name} requires a selected target VSYS')
            if any(item.target_vsys == vsys and item.target_name == zone for item in plan.zones):
                continue
            matches = [item for item in getattr(getattr(target, 'config', None), 'zones', ())
                       if device and _device(item) == device and getattr(item.scope, 'vsys', None) == vsys
                       and item.name == zone]
            if len(matches) != 1 or matches[0].network_type != 'layer3' or matches[0].raw_extra:
                raise ValueError(f'VIP {vdom}/{name}: original-packet destination zone is unavailable in target VSYS {vsys}')
            references.add((vsys, zone))
    return replace(plan, target_zone_references=tuple(sorted(references)))


def site_to_site_phase1(source):
    return {(item.vdom or 'root', item.name): item for item in getattr(source, 'ipsec_phase1', ())
            if item.interface and item.remote_gw and item.type != 'dynamic'
            and item.raw_extra.get('mode-cfg') not in {'enable', 'yes'}
            and not item.raw_extra.get('xauthtype')}


def valid_target_identity(value):
    return (isinstance(value, str) and bool(value.strip()) and value == value.strip() and len(value) <= 255
        and value.casefold() not in {'any', 'known-user', 'unknown', 'pre-logon'}
        and not any(ord(character) < 32 or ord(character) == 127 for character in value))


def policy_identity_groups(source):
    groups = {}
    for policy in getattr(source, 'policies', ()):
        vdom = policy.vdom or 'root'
        for kind, identities in (('user', policy.users), ('group', policy.groups)):
            for name in identities or ():
                key = f'{kind}/{name}'
                group = groups.setdefault((vdom, key), {'source_vdom': vdom, 'identity': key,
                    'message': f'{kind} {name}', 'proposed_value': name, 'member_keys': []})
                group['member_keys'].append(str(policy.policy_id))
    return list(groups.values())


def management_profile_groups(source):
    groups = {}
    for item in getattr(source, 'interfaces', ()):
        if not item.allowaccess:
            continue
        vdom = item.vdom or 'root'
        protocols = tuple(sorted(set(item.allowaccess)))
        group = groups.setdefault((vdom, protocols), {'source_vdom': vdom,
            'identity': f'{vdom}/' + ','.join(protocols),
            'message': 'Explicit source administrative protocols: ' + ', '.join(protocols), 'member_keys': []})
        group['member_keys'].append(f'{vdom}/{item.name}')
    return list(groups.values())


def interface_consumers(source):
    consumers = {(item.vdom or 'root', item.interface) for item in source.interfaces if item.interface}
    consumers.update((item.vdom or 'root', name) for item in source.interfaces for name in item.members or ())
    consumers.update((item.vdom or 'root', name) for item in source.zones for name in item.members or ())
    consumers.update((item.vdom or 'root', name) for item in source.policies for name in (*(item.srcintf or ()), *(item.dstintf or ())))
    consumers.update((item.vdom or 'root', item.device) for item in source.static_routes)
    consumers.update((item.vdom or 'root', item.interface) for item in (*source.dhcp_servers, *source.ipsec_phase1))
    consumers.update((item.vdom or 'root', item.extintf) for item in source.vips)
    return consumers


def interface_scope_suggestions(source):
    consumers = interface_consumers(source)
    return [{'identity': f'{item.vdom or "root"}/{item.name}', 'reason': 'No explicit addressing, management access or source consumers; review before excluding.'}
            for item in source.interfaces if (item.type or '').lower() in {'physical', 'ethernet'}
            and not item.ip and not item.secondary_ips and not item.allowaccess and item.mode in {None, 'static'}
            and not (set(item.raw_extra) - {'snmp-index'}) and (item.vdom or 'root', item.name) not in consumers]
