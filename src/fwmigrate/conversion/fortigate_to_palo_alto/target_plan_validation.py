"""Target-aware render decisions kept separate from planner output."""

import json
from dataclasses import dataclass
from enum import StrEnum


class PANRenderDisposition(StrEnum):
    CREATE = "CREATE"
    REUSE = "REUSE"
    BLOCK = "BLOCK"


_FAMILIES = {
    "address": "addresses", "address_group": "address_groups", "service": "services",
    "service_group": "service_groups", "schedule": "schedules", "zone": "zones",
    "static_route": "static_routes", "security_rule": "security_rules", "nat_rule": "nat_rules",
}
_REUSABLE = {"address", "address_group", "service", "service_group", "schedule"}


def _reuse_code(status):
    return "TARGET_NAME_CONFLICT" if status == "NAME_CONFLICT" else "TARGET_OBJECT_AMBIGUOUS"


@dataclass(frozen=True, slots=True)
class PANTargetPlanFinding:
    code: str
    source_vdom: str | None
    source_kind: str | None
    source_name: str | None
    target_name: str | None = None
    decision_key: str | None = None
    evidence: object = None

    def to_dict(self):
        return {"code": self.code, "source_vdom": self.source_vdom, "source_kind": self.source_kind,
                "source_name": self.source_name, "target_name": self.target_name,
                "decision_key": self.decision_key, "evidence": self.evidence}


def item_key(item):
    return json.dumps((item.source_object_type, item.source_vdom, item.source_kind, item.source_name,
                       item.source_policy_id, item.target_vsys, item.target_name or item.source_name),
                      separators=(",", ":"))


def decision_keys_for_item(item, decisions):
    keys = []
    for decision in decisions.decisions:
        if decision.source_vdom != item.source_vdom:
            continue
        if decision.source_kind == "vdom":
            if decision.target_field == "vsys" or (decision.target_field == "virtual_router" and item.source_object_type == "static_route"):
                keys.append(decision.key)
        elif decision.source_kind == item.source_kind and decision.source_name == item.source_name:
            keys.append(decision.key)
        elif decision.source_kind == "interface":
            target = decision.value
            if not target:
                continue
            names = set(getattr(item, "interfaces", ()))
            names.update((getattr(item, "interface", None), getattr(item, "to_interface", None)))
            zones = set(getattr(item, "from_zones", ())) | set(getattr(item, "to_zones", ()))
            if decision.target_field == "target_interface" and (target in names or item.source_object_type == "zone" and target in names):
                keys.append(decision.key)
            elif decision.target_field == "target_zone" and (target in zones or item.source_object_type == "zone" and item.target_name == target):
                keys.append(decision.key)
    return list(dict.fromkeys(keys))


def _items(plan):
    for family in _FAMILIES.values():
        yield from getattr(plan, family)


def _decision_parts(finding, decisions):
    decision = next((item for item in decisions.decisions if item.key == finding.decision_key), None)
    return decision


def validate_target_plan(plan, classifications=(), target_findings=(), decisions=None):
    """Return target conflicts as findings; leave planner output untouched."""
    result = []
    for item in classifications:
        status = item.get("status")
        if status not in {"NAME_CONFLICT", "AMBIGUOUS", "EXACT_MATCH"}:
            continue
        if status == "EXACT_MATCH" and item.get("family") in _REUSABLE:
            continue
        code = "TARGET_NAME_CONFLICT" if status == "NAME_CONFLICT" else "TARGET_OBJECT_AMBIGUOUS"
        result.append(PANTargetPlanFinding(code, item.get("source_vdom"), item.get("family"),
                                           item.get("source_name"), item.get("target_name"),
                                           evidence=item.get("evidence")))
    for finding in target_findings:
        if finding.severity != "error":
            continue
        code = "TARGET_SCOPE_CONFLICT" if finding.code == "TARGET_SCOPE_AMBIGUOUS" else "TARGET_MAPPING_CONFLICT"
        decision = _decision_parts(finding, decisions) if decisions else None
        affected = _dependents(plan, _affected(plan, finding, decision)) if decision else []
        result.append(PANTargetPlanFinding(code,
            decision.source_vdom if decision else None, decision.source_kind if decision else None,
            decision.source_name if decision else None, finding.target_object, finding.decision_key,
            {"original_code": finding.code, "affected_items": [item_key(item) for item in affected]}))
    return tuple(result)


def _affected(plan, finding, decision):
    items = list(_items(plan))
    vdom = decision.source_vdom
    if decision.source_kind == "vdom":
        if decision.target_field == "vsys":
            return [item for item in items if item.source_vdom == vdom]
        if decision.target_field == "virtual_router":
            return [item for item in plan.static_routes if item.source_vdom == vdom]
    if decision.source_kind == "interface":
        name = decision.value
        zones = [zone for zone in plan.zones if name in zone.interfaces or zone.target_name == name]
        zone_names = {zone.target_name or zone.source_name for zone in zones}
        affected = list(zones)
        affected.extend(route for route in plan.static_routes if route.source_vdom == vdom and route.interface == name)
        affected.extend(rule for rule in plan.nat_rules if rule.source_vdom == vdom and
                        (rule.to_interface == name or set(rule.from_zones + rule.to_zones) & zone_names))
        affected.extend(rule for rule in plan.security_rules if rule.source_vdom == vdom and
                        set(rule.from_zones + rule.to_zones) & zone_names)
        if decision.target_field == "target_zone":
            affected.extend(item for item in (*plan.nat_rules, *plan.security_rules)
                            if item.source_vdom == vdom and decision.value in (item.from_zones + item.to_zones))
        return affected
    return [item for item in items if item.source_vdom == vdom and item.source_kind == decision.source_kind
            and item.source_name == decision.source_name]


def _dependents(plan, blocked):
    blocked_names = {(item.target_vsys, item.target_name or item.source_name) for item in blocked}
    changed = True
    while changed:
        changed = False
        for item in _items(plan):
            if item in blocked:
                continue
            refs = set(getattr(item, "members", ()))
            refs.update(getattr(item, "sources", ()))
            refs.update(getattr(item, "destinations", ()))
            refs.update(getattr(item, "services", ()))
            refs.update(getattr(item, "from_zones", ()))
            refs.update(getattr(item, "to_zones", ()))
            refs.update(getattr(item, "source_addresses", ()))
            refs.update(getattr(item, "destination_addresses", ()))
            refs.update(value for value in (getattr(item, "service", None), getattr(item, "schedule", None)) if value)
            if any((item.target_vsys, ref) in blocked_names for ref in refs):
                blocked.append(item)
                blocked_names.add((item.target_vsys, item.target_name or item.source_name))
                changed = True
    return blocked


def assess_target_plan(plan, classifications=(), target_findings=(), decisions=None):
    """Return dispositions and blockers without changing the immutable plan."""
    items = list(_items(plan))
    dispositions = {item_key(item): PANRenderDisposition.CREATE for item in items}
    blockers = {item_key(item): [] for item in items}
    by_identity = {(entry["family"], entry.get("source_vdom", "root"), entry.get("source_name")): entry
                   for entry in classifications}
    for item in items:
        family = item.source_object_type
        result = by_identity.get((family, item.source_vdom or "root", item.source_name))
        if not result:
            continue
        status = result.get("status")
        if status == "EXACT_MATCH" and family in _REUSABLE:
            dispositions[item_key(item)] = PANRenderDisposition.REUSE
        elif status in {"NAME_CONFLICT", "AMBIGUOUS", "EXACT_MATCH"}:
            dispositions[item_key(item)] = PANRenderDisposition.BLOCK
            blockers[item_key(item)].append(_reuse_code(status))
    if decisions:
        for finding in target_findings:
            if finding.severity != "error":
                continue
            decision = _decision_parts(finding, decisions)
            if decision is None:
                continue
            affected = _dependents(plan, _affected(plan, finding, decision))
            for item in affected:
                dispositions[item_key(item)] = PANRenderDisposition.BLOCK
                blockers[item_key(item)].append("TARGET_SCOPE_CONFLICT" if finding.code == "TARGET_SCOPE_AMBIGUOUS"
                                                else "TARGET_MAPPING_CONFLICT")
    for item in items:
        if item.status.value != "SUPPORTED":
            dispositions[item_key(item)] = PANRenderDisposition.BLOCK
    return dispositions, {key: list(dict.fromkeys(values)) for key, values in blockers.items() if values}
