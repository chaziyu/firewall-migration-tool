"""Allocate target names and rewrite planned references without changing source."""
from collections import defaultdict
from dataclasses import replace
import hashlib
import json
import re

from ..models import PANMigrationStatus
from ..target.target_suggestions import _device


FAMILIES = {
    'addresses': 'address', 'address_groups': 'address',
    'services': 'service', 'service_groups': 'service',
    'schedules': 'schedule', 'security_rules': 'security_rule', 'nat_rules': 'nat_rule',
    'ike_crypto_profiles': 'ike_crypto_profile', 'ipsec_crypto_profiles': 'ipsec_crypto_profile',
    'ike_gateways': 'ike_gateway', 'ipsec_tunnels': 'ipsec_tunnel',
    'management_profiles': 'management_profile',
    'static_routes': 'static_route',
}


def allocate_plan_names(plan, target=None, target_device=None, service_names=None):
    reserved = defaultdict(set)
    if target is not None:
        for router in getattr(target.config, 'virtual_routers', ()):
            if _device(router) == target_device:
                reserved[(router.name, 'static_route')].update(route.name for route in router.static_routes or ())
        target_families = {**FAMILIES, 'policies': 'security_rule'}
        for attribute, namespace in target_families.items():
            for item in getattr(target.config, attribute, ()):
                if _device(item) == target_device or getattr(getattr(item, 'scope', None), 'kind', None) == 'shared':
                    scope = None if namespace in {'ike_crypto_profile', 'ipsec_crypto_profile', 'ike_gateway', 'ipsec_tunnel'} else getattr(getattr(item, 'scope', None), 'vsys', None)
                    reserved[(scope, namespace)].add(item.name)
    records = [(attribute, index, item) for attribute in FAMILIES for index, item in enumerate(getattr(plan, attribute))]
    def namespace(attribute, item):
        family = FAMILIES[attribute]
        if family == 'static_route':
            return item.virtual_router, family
        return (None if family in {'ike_crypto_profile', 'ipsec_crypto_profile', 'ike_gateway', 'ipsec_tunnel', 'management_profile'} else item.target_vsys, family)
    def valid(attribute, name):
        pattern = r'[A-Za-z0-9_.-]{1,31}' if FAMILIES[attribute].endswith('crypto_profile') else r'[A-Za-z0-9_. -]{1,63}'
        return isinstance(name, str) and bool(name.strip()) and bool(re.fullmatch(pattern, name))
    originals = defaultdict(set)
    protected_targets = defaultdict(set)
    for attribute, _, item in records:
        name = item.target_name or item.source_name
        if valid(attribute, name):
            originals[namespace(attribute, item)].add(name)
        if attribute == 'services' and item.source_name in (service_names or {}).get(item.source_vdom or 'root', {}):
            protected_targets[namespace(attribute, item)].add(name)
    allocated = {}
    claimed = defaultdict(set)
    references = defaultdict(set)
    for attribute, index, item in sorted(records, key=lambda row: (str(namespace(row[0], row[2])), row[2].target_name or row[2].source_name or '', row[2].source_kind or '', row[2].source_vdom or '', row[2].source_policy_id or 0, row[1])):
        old = item.target_name or item.source_name
        if not old:
            allocated[(attribute, index)] = item
            continue
        scope = namespace(attribute, item)
        name = old
        protected = old in protected_targets[scope]
        if not protected and (not valid(attribute, old) or old in claimed[scope]):
            limit = 31 if FAMILIES[attribute].endswith('crypto_profile') else 63
            stem = re.sub(r'[^A-Za-z0-9_.-]', '_', old).strip('_.-') or 'converted'
            identity = [attribute, item.source_vdom, item.source_kind, item.source_name, item.source_policy_id, old]
            digest = hashlib.sha256(json.dumps(identity, ensure_ascii=True).encode()).hexdigest()
            number = 0
            while True:
                suffix = '-' + digest[:10] + (f'-{number}' if number else '')
                name = stem[:limit-len(suffix)] + suffix
                if name not in claimed[scope] | originals[scope] | reserved[scope]:
                    break
                number += 1
        claimed[scope].add(name)
        references[(item.source_vdom or 'root', item.target_vsys, FAMILIES[attribute], old)].add(name)
        allocated[(attribute, index)] = replace(item, target_name=name)
    updated = {attribute: [] for attribute in FAMILIES}
    for attribute, index, _ in records:
        item = allocated[(attribute, index)]
        warnings = []
        def ref(family, name):
            choices = references.get((item.source_vdom or 'root', item.target_vsys, family, name), ())
            if len(choices) > 1:
                warnings.append(f'Ambiguous source {family} reference {name!r}; automatic renaming cannot choose its identity')
                return name
            return next(iter(choices), name)
        changes = {}
        if attribute in {'address_groups', 'service_groups'}:
            changes['members'] = tuple(ref(FAMILIES[attribute], name) for name in item.members)
        elif attribute == 'security_rules':
            changes.update(sources=tuple(ref('address', name) for name in item.sources), destinations=tuple(ref('address', name) for name in item.destinations),
                services=tuple(ref('service', name) for name in item.services), schedule=ref('schedule', item.schedule) if item.schedule else None)
        elif attribute == 'nat_rules':
            changes.update(source_addresses=tuple(ref('address', name) for name in item.source_addresses), destination_addresses=tuple(ref('address', name) for name in item.destination_addresses),
                service=ref('service', item.service) if item.service else None)
        elif attribute == 'ike_gateways':
            changes['crypto_profile'] = ref('ike_crypto_profile', item.crypto_profile) if item.crypto_profile else None
        elif attribute == 'ipsec_tunnels':
            changes['ike_gateway'] = ref('ike_gateway', item.ike_gateway) if item.ike_gateway else None
            changes['proxy_ids'] = tuple(replace(selector, crypto_profile=ref('ipsec_crypto_profile', selector.crypto_profile)) for selector in item.proxy_ids)
        if warnings:
            changes.update(status=PANMigrationStatus.MANUAL_REVIEW, warnings=(*item.warnings, *warnings))
        updated[attribute].append(replace(item, **changes))
    return replace(plan, **{key: tuple(items) for key, items in updated.items()})
