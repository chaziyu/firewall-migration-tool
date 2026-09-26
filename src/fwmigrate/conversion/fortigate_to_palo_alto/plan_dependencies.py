"""Pair-specific decision impact and planned-item dependencies."""

from dataclasses import dataclass
import json

from .models import PANMigrationPlan


def item_key(item):
    return json.dumps((item.source_object_type, item.source_vdom, item.source_kind, item.source_name,
                       item.source_policy_id, item.target_vsys, item.target_name or item.source_name),
                      separators=(",", ":"))


def _items(plan):
    for family in ("addresses", "address_groups", "services", "service_groups", "schedules", "zones",
                   "static_routes", "security_rules", "nat_rules"):
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
        elif kind in {"security_rule", "nat_rule"}:
            addresses = (item.sources + item.destinations) if kind == "security_rule" else (item.source_addresses + item.destination_addresses)
            services = item.services if kind == "security_rule" else ((item.service,) if item.service else ())
            refs = [(('address', 'address_group'), name) for name in addresses]
            refs += [(('service', 'service_group'), name) for name in services]
            refs += [(('zone',), name) for name in item.from_zones + item.to_zones]
            if kind == "security_rule" and item.schedule:
                refs.append((('schedule',), item.schedule))
        elif kind == "static_route" and item.interface:
            refs = [(('zone',), zone.target_name or zone.source_name)
                    for zone in plan.zones if item.interface in zone.interfaces]
        for families, name in refs:
            for dependency in resolve(item.target_vsys, families, name):
                if dependency is not item:
                    dependents[keys[id(dependency)]].append(keys[id(item)])

    # ponytail: O(decisions x items); index source identities if real plans grow materially.
    for decision in getattr(decisions, "decisions", ()):
        affected = []
        for item in items:
            if item.source_vdom != decision.source_vdom:
                continue
            kind = item.source_object_type
            if decision.source_kind == "vdom":
                match = decision.target_field == "vsys" or (decision.target_field == "virtual_router" and kind == "static_route")
            elif decision.source_kind == item.source_kind and decision.source_name == item.source_name:
                match = True
            elif decision.source_kind == "interface":
                target = decision.value
                names = set(getattr(item, "interfaces", ()))
                names.update(value for value in (getattr(item, "interface", None), getattr(item, "to_interface", None)) if value)
                zones = set(getattr(item, "from_zones", ())) | set(getattr(item, "to_zones", ()))
                match = bool(target) and (
                    decision.target_field == "target_interface" and target in names
                    or decision.target_field == "target_zone" and (target in zones or kind == "zone" and item.target_name == target)
                )
            else:
                match = False
            if match:
                key = keys[id(item)]
                direct_decisions[key].append(decision.key)
                affected.append(key)

        # Interface mapping failures also block consumers of the affected zones.
        if decision.source_kind == "interface" and affected:
            changed = True
            while changed:
                changed = False
                for source, targets in dependents.items():
                    if source in affected:
                        for target in targets:
                            if target not in affected:
                                affected.append(target)
                                direct_decisions[target].append(decision.key)
                                changed = True
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
