"""Pair-specific decision impact and planned-item dependencies."""

from dataclasses import dataclass
import json
import heapq

from .models import PANMigrationPlan


def item_key(item):
    return json.dumps((item.source_object_type, item.source_vdom, item.source_kind, item.source_name,
                       item.source_policy_id, item.target_vsys, item.target_name or item.source_name),
                      separators=(",", ":"))


def _items(plan):
    for family in ("addresses", "address_groups", "services", "service_groups", "schedules", "interfaces", "zones",
                   "static_routes", "dhcp_servers", "security_rules", "nat_rules"):
        yield from getattr(plan, family)


def _identity(item):
    return item.target_vsys, item.source_object_type, item.target_name or item.source_name


@dataclass(frozen=True, slots=True)
class PANPlanDependencyIndex:
    decision_keys_by_item: dict[str, tuple[str, ...]]
    item_keys_by_decision: dict[str, tuple[str, ...]]
    dependents_by_item: dict[str, tuple[str, ...]]


def build_plan_dependency_index(plan: PANMigrationPlan, decisions) -> PANPlanDependencyIndex:
    items = tuple(_items(plan))
    keys = {id(item): item_key(item) for item in items}
    identities = {}
    for item in items:
        identities.setdefault(_identity(item), []).append(item)

    def resolve(vsys, families, name):
        return [entry for family in families for entry in identities.get((vsys, family, name), ())]

    dependents = {keys[id(item)]: [] for item in items}
    direct_decisions = {keys[id(item)]: [] for item in items}
    items_by_decision = {}
    for item in items:
        kind = item.source_object_type
        refs = []
        if kind == "address_group":
            refs = [(('address', 'address_group'), name) for name in item.members]
        elif kind == "service_group":
            refs = [(('service', 'service_group'), name) for name in item.members]
        elif kind == "interface" and getattr(item, "parent", None):
            refs = [(('interface',), item.parent)]
        elif kind == "zone":
            refs = [(('interface',), name) for name in item.interfaces]
        elif kind in {"security_rule", "nat_rule"}:
            addresses = (item.sources + item.destinations) if kind == "security_rule" else (item.source_addresses + item.destination_addresses)
            services = item.services if kind == "security_rule" else ((item.service,) if item.service else ())
            refs = [(('address', 'address_group'), name) for name in addresses]
            refs += [(('service', 'service_group'), name) for name in services]
            refs += [(('zone',), name) for name in item.from_zones + item.to_zones]
            if kind == "nat_rule" and item.to_interface:
                refs.append((('interface',), item.to_interface))
            if kind == "security_rule" and item.schedule:
                refs.append((('schedule',), item.schedule))
        elif kind == "static_route" and item.interface:
            refs = [(('interface',), item.interface)]
        elif kind == "dhcp_server" and item.interface:
            refs = [(('interface',), item.interface)]
        for families, name in refs:
            for dependency in resolve(item.target_vsys, families, name):
                if dependency is not item:
                    dependents[keys[id(dependency)]].append(keys[id(item)])

    by_vdom = {}
    by_source = {}
    by_interface = {}
    by_zone = {}
    positions = {}
    for position, item in enumerate(items):
        key = keys[id(item)]
        positions.setdefault(key, position)
        by_vdom.setdefault(item.source_vdom, []).append(key)
        by_source.setdefault((item.source_vdom, item.source_kind, item.source_name), []).append(key)
        names = set(getattr(item, 'interfaces', ()))
        names.update(value for value in (getattr(item, 'interface', None), getattr(item, 'to_interface', None)) if value)
        zones = set(getattr(item, 'from_zones', ())) | set(getattr(item, 'to_zones', ()))
        if item.source_object_type == 'zone' and item.target_name:
            zones.add(item.target_name)
        for name in names:
            by_interface.setdefault((item.source_vdom, name), []).append(key)
        for name in zones:
            by_zone.setdefault((item.source_vdom, name), []).append(key)
    by_key = {keys[id(item)]: item for item in items}
    for decision in getattr(decisions, 'decisions', ()):
        if decision.source_kind == 'vdom':
            affected = [key for key in by_vdom.get(decision.source_vdom, ())
                        if decision.target_field == 'vsys' or (decision.target_field == 'virtual_router'
                            and by_key[key].source_object_type in {'interface', 'static_route'})]
        else:
            matched = set(by_source.get((decision.source_vdom, decision.source_kind, decision.source_name), ()))
            if decision.source_kind == 'interface' and decision.value:
                references = by_interface if decision.target_field == 'target_interface' else by_zone if decision.target_field == 'target_zone' else {}
                matched.update(references.get((decision.source_vdom, decision.value), ()))
            affected = sorted(matched, key=positions.__getitem__)
        for key in affected:
            direct_decisions[key].append(decision.key)
        if decision.source_kind == 'interface' and affected:
            seen = set(affected)
            pending = [(0, positions[key], key) for key in affected]
            heapq.heapify(pending)
            while pending:
                wave, position, source = heapq.heappop(pending)
                for target in dependents.get(source, ()):
                    if target not in seen:
                        seen.add(target)
                        affected.append(target)
                        direct_decisions[target].append(decision.key)
                        # Keep the old forward-scan ordering, including backward edges and cycles.
                        heapq.heappush(pending, (wave + (positions[target] <= position), positions[target], target))
        items_by_decision[decision.key] = list(dict.fromkeys(affected))

    return PANPlanDependencyIndex(
        {key: tuple(dict.fromkeys(values)) for key, values in direct_decisions.items()},
        {key: tuple(values) for key, values in items_by_decision.items()},
        {key: tuple(dict.fromkeys(values)) for key, values in dependents.items()},
    )


def affected_items_for_decision(index: PANPlanDependencyIndex, decision) -> tuple[str, ...]:
    return index.item_keys_by_decision.get(decision.key, ())


def expand_plan_dependents(index: PANPlanDependencyIndex, initial_item_keys) -> tuple[str, ...]:
    result = list(dict.fromkeys(initial_item_keys))
    seen = set(result)
    for key in result:
        for dependent in index.dependents_by_item.get(key, ()):
            if dependent not in seen:
                seen.add(dependent)
                result.append(dependent)
    return tuple(result)
