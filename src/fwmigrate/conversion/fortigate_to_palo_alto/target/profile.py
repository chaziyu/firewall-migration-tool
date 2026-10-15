"""Explicit design settings; configured XML interfaces are not hardware inventory."""
import re

# PA-800 Hardware Reference: data ports 1-12; MGT and HA are separate.
MODEL_PORTS = {'PA-820': tuple(f'ethernet1/{number}' for number in range(1, 13))}


def parse_conversion_settings(value):
    if value is None:
        return {}
    if not isinstance(value, dict) or set(value) - {'target_model', 'panos_version', 'excluded_interfaces', 'management_profiles', 'existing_vpns', 'vpn_parameters', 'security_profiles'}:
        raise ValueError('Invalid conversion settings')
    result = dict(value)
    if result.get('target_model') not in {None, '', *MODEL_PORTS}:
        raise ValueError('Unsupported target hardware model')
    if result.get('panos_version') not in {None, '', '11.1'}:
        raise ValueError('Supported PAN-OS command version is 11.1')
    excluded = result.get('excluded_interfaces', [])
    if not isinstance(excluded, list) or any(not isinstance(key, str) or not re.fullmatch(r'[^/]+/.+', key) for key in excluded):
        raise ValueError('Excluded interfaces must preserve VDOM/name identity')
    if 'excluded_interfaces' in result:
        result['excluded_interfaces'] = sorted(set(excluded))
    existing_vpns = result.get('existing_vpns', [])
    if not isinstance(existing_vpns, list) or any(not isinstance(key, str) or not re.fullmatch(r'[^/]+/.+', key) for key in existing_vpns):
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
        if (not isinstance(key, str) or not re.fullmatch(r'[^/]+/ipsec_phase[12]/.+', key)
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


def site_to_site_phase1(source):
    return {(item.vdom or 'root', item.name): item for item in getattr(source, 'ipsec_phase1', ())
            if item.interface and item.remote_gw and item.type != 'dynamic'
            and item.raw_extra.get('mode-cfg') not in {'enable', 'yes'}
            and not item.raw_extra.get('xauthtype')}


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
