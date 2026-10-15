"""Read-only presentation helpers shared by FortiGate preview and Excel."""
from collections import Counter, defaultdict

from .security.extraction import sanitize_source_attributes


def credential_presence(value: bool | None) -> str:
    return "Not explicitly configured" if value is None else "Yes" if value else "Explicitly unset"


def policy_nat_entries(config, derived):
    counts = Counter((item.vdom, item.policy_id) for item in config.policies)
    grouped = defaultdict(list)
    for item in derived.nat:
        grouped[(item.vdom, item.policy_id)].append(item)
    return counts, grouped


def policy_nat_review(key, counts, entries):
    if key[1] is None or counts[key] != 1:
        return ['Ambiguous policy identity; NAT entries were not joined.']
    reasons = [reason for item in entries for reason in item.issues]
    if len(entries) > 1:
        reasons.append('Multiple NAT modes: ' + ', '.join(item.translation_type for item in entries))
    return reasons


def address_value(item):
    selectors = {
        'geography': ('country',),
        'dynamic': ('sub-type', 'sdn', 'sdn-addr-type', 'sdn-tag', 'filter', 'clearpass-spt',
                    'fsso-group', 'obj-type', 'obj-id', 'obj-tag', 'tag-type', 'tag-detection-level',
                    'hw-model', 'hw-vendor', 'os', 'sw-version', 'organization', 'tenant',
                    'epg-name', 'policy-group', 'node-ip-only'),
        'interface-subnet': ('interface', 'subnet-name'),
        'mac': ('macaddr',),
        'route-tag': ('route-tag',),
    }
    if item.type in selectors:
        raw = sanitize_source_attributes(item.raw_extra, preserve_keys=True)
        configured = [f'{key}={raw[key]}' for key in selectors[item.type]
                      if key in raw and raw[key] not in (None, '', [], {})]
        return '; '.join(configured) if configured else f'Unknown: {item.type} selector not explicitly configured'
    values = {
        key: value for key, value in (
            ('subnet', item.subnet), ('ip6', item.ip6),
            ('iprange', f'{item.start_ip or "?"}-{item.end_ip or "?"}'
             if item.start_ip is not None or item.end_ip is not None else None),
            ('fqdn', item.fqdn), ('wildcard', item.wildcard),
            ('wildcard-fqdn', item.wildcard_fqdn),
        ) if value is not None
    }
    # FortiOS explicitly selects the representation with type. No default type
    # is supplied for absent source fields.
    selected = {'ipmask': 'subnet', 'ipprefix': 'ip6', 'iprange': 'iprange', 'fqdn': 'fqdn',
                'wildcard': 'wildcard'}.get(item.type)
    if item.type is not None and selected is None:
        return f'Unsupported address type: {item.type}'
    if selected in values:
        return values[selected]
    if selected is not None:
        return f'Unknown: {item.type} selector not explicitly configured'
    if len(values) == 1:
        return next(iter(values.values()))
    if len(values) > 1:
        return 'Ambiguous: ' + '; '.join(f'{key}={value}' for key, value in values.items())
    return None
