"""Non-secret crypto profiles only; gateways, authentication and tunnels stay manual."""

from ..models import PANMigrationStatus, PlannedIKECryptoProfile, PlannedIPsecCryptoProfile


# One proposal avoids turning ordered proposal pairs into an algorithm cross product.
PROPOSALS = {
    'aes128-sha256': ('aes-128-cbc', 'sha256'),
    'aes256-sha256': ('aes-256-cbc', 'sha256'),
}
DH_GROUPS = {14, 15, 16, 19, 20, 21}


def plan_vpn_crypto(source, options):
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
            proposal = PROPOSALS.get(item.proposal[0]) if len(item.proposal) == 1 else None
            if proposal is None:
                warnings.append('Crypto profile requires one explicit supported AES-CBC/SHA256 proposal')
            lifetime = item.keylife if family == 'ike_crypto_profile' else item.keylifeseconds
            if lifetime is None or not 180 <= lifetime <= 65535:
                warnings.append('Crypto profile requires explicit lifetime seconds between 180 and 65535')
            dh_group = None
            if family == 'ipsec_crypto_profile' and item.pfs == 'disable':
                dh_group = 'no-pfs'
            elif len(item.dhgrp or ()) == 1 and item.dhgrp[0] in DH_GROUPS:
                dh_group = f'group{item.dhgrp[0]}'
            if dh_group is None:
                warnings.append('Crypto profile requires one explicit supported DH group')
            if family == 'ipsec_crypto_profile':
                if item.pfs not in {'enable', 'disable'}:
                    warnings.append('IPsec PFS state is not explicit')
                if item.keylifekbs is not None:
                    warnings.append('IPsec byte lifetime requires manual review')
                if not item.phase1name or (vdom, item.phase1name) not in phase1s:
                    warnings.append('Referenced interface-based Phase 1 gateway is missing in this VDOM')
            if item.raw_extra:
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
            ))
    return tuple(ike), tuple(ipsec)
