"""Read-only presentation helpers shared by FortiGate preview and Excel."""
from collections import Counter, defaultdict


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
    selected = {'ipmask': 'subnet', 'iprange': 'iprange', 'fqdn': 'fqdn',
                'wildcard': 'wildcard'}.get(item.type)
    if selected in values:
        return values[selected]
    if len(values) == 1:
        return next(iter(values.values()))
    if len(values) > 1:
        return 'Ambiguous: ' + '; '.join(f'{key}={value}' for key, value in values.items())
    return None
