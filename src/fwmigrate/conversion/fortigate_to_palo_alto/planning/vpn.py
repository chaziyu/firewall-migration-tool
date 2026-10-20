"""Non-secret crypto profiles only; gateways, authentication and tunnels stay manual."""

from ..models import (PANMigrationStatus, PlannedIKECryptoProfile, PlannedIPsecCryptoProfile,
    PlannedIKEGateway, PlannedIPsecTunnel, PlannedVPNProxyID)
from fwmigrate.vendors.fortigate.transform.effective_values import effective_value


# One proposal avoids turning ordered proposal pairs into an algorithm cross product.
PROPOSALS = {
    'aes128-sha256': ('aes-128-cbc', 'sha256'),
    'aes256-sha256': ('aes-256-cbc', 'sha256'),
    'aes128-sha384': ('aes-128-cbc', 'sha384'),
    'aes256-sha384': ('aes-256-cbc', 'sha384'),
    'aes128-sha512': ('aes-128-cbc', 'sha512'),
    'aes256-sha512': ('aes-256-cbc', 'sha512'),
}
DH_GROUPS = {14, 15, 16, 19, 20, 21}


def crypto_lifetime(seconds):
    if type(seconds) is int and 180 <= seconds <= 65535:
        return 'seconds', seconds
    if type(seconds) is int and seconds % 3600 == 0 and 1 <= seconds // 3600 <= 65535:
        return 'hours', seconds // 3600
    return None


def vpn_parameter_requirements(source, derived=None):
    groups = {}
    for kind, records in (('ipsec_phase1', source.ipsec_phase1), ('ipsec_phase2', source.ipsec_phase2)):
        for item in records:
            fields = []
            if (item.keylife if kind == 'ipsec_phase1' else item.keylifeseconds) is None and effective_value(derived, item.vdom, kind, item.name, 'keylifeseconds' if kind == 'ipsec_phase2' else 'keylife') is None:
                fields.append('lifetime_seconds')
            if not item.dhgrp:
                fields.append('dh_group')
            if kind == 'ipsec_phase2' and item.pfs is None and effective_value(derived, item.vdom, kind, item.name, 'pfs') is None:
                fields.append('pfs')
            if kind == 'ipsec_phase1' and item.ike_version is None:
                fields.append('ike_version')
            if fields:
                vdom = item.vdom or 'root'
                group = groups.setdefault((vdom, kind, tuple(fields)), {'source_vdom': vdom, 'source_kind': kind,
                    'fields': fields, 'member_keys': []})
                group['member_keys'].append(f'{vdom}/{kind}/{item.name}')
    return list(groups.values())


def validate_vpn_parameters(source, settings, derived=None):
    if not settings.get('vpn_parameters'):
        return
    eligible = {key: set(group['fields']) for group in vpn_parameter_requirements(source) for key in group['member_keys']}
    for key, fields in settings.get('vpn_parameters', {}).items():
        if key not in eligible or set(fields) - eligible[key]:
            raise ValueError('Reviewed VPN values may only fill current absent source parameters')
        vdom, kind, name = key.split('/', 2)
        for field, value in fields.items():
            source_field = 'keylifeseconds' if field == 'lifetime_seconds' and kind == 'ipsec_phase2' else field
            derived_value = effective_value(derived, vdom, kind, name, source_field)
            if derived_value is not None and value != derived_value:
                raise ValueError('Reviewed VPN values cannot replace verified effective source values')


def plan_vpn_crypto(source, options, derived=None):
    ike, ipsec = [], []
    phase1s = {(item.vdom or 'root', item.name): item for item in getattr(source, 'ipsec_phase1', ())}
    for family, records, cls, destination in (
        ('ike_crypto_profile', getattr(source, 'ipsec_phase1', ()), PlannedIKECryptoProfile, ike),
        ('ipsec_crypto_profile', getattr(source, 'ipsec_phase2', ()), PlannedIPsecCryptoProfile, ipsec),
    ):
        for item in records:
            vdom = item.vdom or 'root'
            ownership = options.vdoms.get(vdom)
            warnings = []
            kind = 'ipsec_phase1' if family == 'ike_crypto_profile' else 'ipsec_phase2'
            reviewed = getattr(options, 'conversion_settings', {}).get('vpn_parameters', {}).get(f'{vdom}/{kind}/{item.name}', {})
            proposal = PROPOSALS.get(item.proposal[0]) if len(item.proposal) == 1 else None
            if proposal is None:
                warnings.append('Crypto profile requires one supported AES-CBC/SHA256, SHA384 or SHA512 proposal')
            lifetime = item.keylife if family == 'ike_crypto_profile' else item.keylifeseconds
            if lifetime is None:
                lifetime = effective_value(derived, vdom, kind, item.name, 'keylife' if kind == 'ipsec_phase1' else 'keylifeseconds')
            if lifetime is None:
                lifetime = reviewed.get('lifetime_seconds')
            if crypto_lifetime(lifetime) is None:
                warnings.append('Crypto profile requires an explicit or reviewed lifetime representable in PAN-OS seconds or hours')
            dh_group = None
            dh_groups = ()
            pfs = item.pfs if family == 'ipsec_crypto_profile' else None
            if family == 'ipsec_crypto_profile' and pfs is None:
                pfs = effective_value(derived, vdom, kind, item.name, 'pfs')
            if family == 'ipsec_crypto_profile' and pfs is None:
                pfs = reviewed.get('pfs')
            if family == 'ipsec_crypto_profile' and pfs == 'disable':
                dh_group = 'no-pfs'
            elif len(item.dhgrp or ()) == 1 and item.dhgrp[0] in DH_GROUPS:
                dh_group = f'group{item.dhgrp[0]}'
            elif (family == 'ike_crypto_profile' and item.dhgrp and len(item.dhgrp) <= len(DH_GROUPS)
                    and len(set(item.dhgrp)) == len(item.dhgrp) and set(item.dhgrp) <= DH_GROUPS):
                dh_groups = tuple(f'group{group}' for group in item.dhgrp)
                dh_group = dh_groups[0]
            elif not item.dhgrp:
                dh_group = reviewed.get('dh_group')
            if dh_group is None:
                warnings.append('Crypto profile requires one explicit supported DH group')
            if family == 'ipsec_crypto_profile':
                if pfs not in {'enable', 'disable'}:
                    warnings.append('IPsec PFS state is not explicit')
                if item.keylifekbs is not None:
                    warnings.append('IPsec byte lifetime requires manual review')
                if not item.phase1name or (vdom, item.phase1name) not in phase1s:
                    warnings.append('Referenced interface-based Phase 1 gateway is missing in this VDOM')
            if set(item.raw_extra) - ({'peertype', 'net-device', 'npu-offload'} if family == 'ike_crypto_profile' else set()):
                warnings.append('VPN contains preserved unsupported source semantics')
            if not ownership or not ownership.vsys:
                warnings.append(f'missing Palo Alto vsys mapping for VDOM {vdom!r}')
            destination.append(cls(
                source_vdom=vdom, source_kind='ipsec_phase1' if family == 'ike_crypto_profile' else 'ipsec_phase2',
                source_object_type=family, source_name=item.name,
                target_vsys=getattr(ownership, 'vsys', None),
                target_name=f'{vdom}-{item.name}-' + ('ike' if family == 'ike_crypto_profile' else 'ipsec'),
                status=PANMigrationStatus.MANUAL_REVIEW if warnings else PANMigrationStatus.SUPPORTED,
                warnings=tuple(warnings), encryption=proposal[0] if proposal else None,
                authentication=proposal[1] if proposal else None, dh_group=dh_group, lifetime_seconds=lifetime,
                **({'phase1_name': item.phase1name} if family == 'ipsec_crypto_profile' else {}),
                **({'dh_groups': dh_groups} if family == 'ike_crypto_profile' else {}),
            ))
    return tuple(ike), tuple(ipsec)


def plan_vpn_structure(source, options):
    """Account for non-secret VPN structure; incomplete authentication never renders."""
    gateways, tunnels = [], []
    for phase1 in source.ipsec_phase1:
        vdom = phase1.vdom or 'root'
        ownership = options.vdoms.get(vdom)
        mappings = options.interfaces.get(vdom, {})
        physical = mappings.get(phase1.interface)
        tunnel = mappings.get(phase1.name)
        parameters = options.conversion_settings.get('vpn_parameters', {}).get(f'{vdom}/ipsec_phase1/{phase1.name}', {})
        gateway_name = f'{vdom}-{phase1.name}-gateway'
        gateways.append(PlannedIKEGateway(source_vdom=vdom, source_kind='ipsec_phase1', source_object_type='ike_gateway',
            source_name=phase1.name, target_name=gateway_name, target_vsys=getattr(ownership, 'vsys', None),
            status=PANMigrationStatus.UNSUPPORTED,
            warnings=('Configure or verify gateway authentication securely on the target; sanitized source cannot supply credentials.',
                'Review local/peer identity, IKE version, DPD, NAT traversal and preserved Phase 1 settings before activation.'),
            interface=getattr(physical, 'target_interface', None), local_address=phase1.local_gw,
            peer_address=phase1.remote_gw, ike_version=str(phase1.ike_version) if phase1.ike_version is not None else parameters.get('ike_version'),
            crypto_profile=f'{vdom}-{phase1.name}-ike', authentication_method=phase1.authmethod))
        def selector_value(item, prefix):
            return (getattr(item, f'{prefix}_subnet', None) or getattr(item, f'{prefix}_name', None)
                or '-'.join(str(value) for value in (getattr(item, f'{prefix}_start_ip', None), getattr(item, f'{prefix}_end_ip', None)) if value) or None)
        selectors = tuple(PlannedVPNProxyID(source_name=phase2.name, local=selector_value(phase2, 'src'), remote=selector_value(phase2, 'dst'),
            protocol=str(phase2.protocol) if phase2.protocol is not None else None,
            local_port=str(phase2.src_port) if phase2.src_port is not None else None,
            remote_port=str(phase2.dst_port) if phase2.dst_port is not None else None,
            crypto_profile=f'{vdom}-{phase2.name}-ipsec') for phase2 in source.ipsec_phase2
            if (phase2.vdom or 'root') == vdom and phase2.phase1name == phase1.name)
        tunnels.append(PlannedIPsecTunnel(source_vdom=vdom, source_kind='ipsec_phase1', source_object_type='ipsec_tunnel',
            source_name=phase1.name, target_name=f'{vdom}-{phase1.name}-vpn', target_vsys=getattr(ownership, 'vsys', None),
            status=PANMigrationStatus.UNSUPPORTED, interface=getattr(tunnel, 'target_interface', None),
            ike_gateway=gateway_name, proxy_ids=selectors,
            warnings=('Complete the gateway and verify all Phase 2 selectors and their crypto compatibility before creating the IPsec tunnel.',)))
    return tuple(gateways), tuple(tunnels)


def represented_vpn_sources(plan):
    return {(item.source_vdom or 'root', 'ipsec_phase1', item.source_name) for item in plan.ike_gateways} | {
        (item.source_vdom or 'root', 'ipsec_phase2', selector.source_name) for item in plan.ipsec_tunnels for selector in item.proxy_ids}
