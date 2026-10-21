"""Fail-closed exact reuse and target-conflict classification."""

from dataclasses import replace
import shlex

from ..rendering.renderer import _commands
from .evidence import SRXTargetEvidence, _ITEM_FAMILY


def _prefix(item):
    settings = dict(item.settings)
    if item.family in {"address", "address_group"}:
        return ("security", "address-book", "global", "address" if item.family == "address" else "address-set", item.target_name)
    if item.family in {"service", "service_group"}:
        return ("applications", "application" if item.family == "service" else "application-set", item.target_name)
    if item.family == "interface":
        return ("interfaces", settings["physical_interface"], "unit", str(settings["unit"]))
    if item.family == "zone":
        return ("security", "zones", "security-zone", item.target_name)
    if item.family == "static_route":
        return ("routing-options", "static", "route", str(settings["destination"]))
    if item.family == "policy":
        return ("security", "policies", "from-zone", settings["from_zone"], "to-zone", settings["to_zone"], "policy", item.target_name)
    return ()


def _has_prefix(prefix, path):
    return len(path) >= len(prefix) and tuple(part.casefold() for part in path[:len(prefix)]) == tuple(part.casefold() for part in prefix)


def classify_target_reuse(plan, evidence: SRXTargetEvidence):
    by_key = {row.key: row for row in plan.items}
    actual = {tuple(row.get("target_path") or ()) for row in evidence.statements
              if row.get("context", "root") == "root" and row.get("status") == "EFFECTIVE"}
    result = []
    for item in plan.items:
        family = _ITEM_FAMILY.get(item.family)
        if not family or item.blockers or item.family.startswith("inactive_"):
            result.append(item)
            continue
        reasons = [*evidence.global_blockers, *evidence.blockers_for(family)]
        if item.family == "policy":
            reasons.extend(evidence.blockers_for("nat"))
            if any(path[:2] == ("security", "nat") for path in actual):
                reasons.append("TARGET_NAT_INTERACTION_UNVERIFIED")
            if any((row.get("origin") or "").casefold() != "local"
                   and tuple(row.get("target_path") or ())[:2] == ("security", "policies")
                   for row in evidence.statements):
                reasons.append("TARGET_INHERITED_POLICY_CONFIGURATION_UNVERIFIED")
            table = ("security", "policies", "from-zone", dict(item.settings)["from_zone"],
                     "to-zone", dict(item.settings)["to_zone"], "policy")
            existing_table_names = {path[len(table)] for path in actual if _has_prefix(table, path) and len(path) > len(table)}
            planned_table_names = {row.target_name for row in plan.items if row.family == "policy"
                                   and dict(row.settings).get("from_zone") == dict(item.settings)["from_zone"]
                                   and dict(row.settings).get("to_zone") == dict(item.settings)["to_zone"]}
            if existing_table_names and existing_table_names != planned_table_names:
                reasons.append("TARGET_POLICY_TABLE_POPULATED_OR_ORDER_AMBIGUOUS")
        if item.family == "static_route" and any(path[:1] == ("routing-instances",) for path in actual):
            reasons.append("TARGET_ROUTING_INSTANCE_AMBIGUITY")
        if item.family in {"policy", "static_route"}:
            expected_root = ("security", "policies") if item.family == "policy" else ("routing-options", "static")
            if any(_has_prefix(expected_root, tuple(row.get("path") or ()))
                   or _has_prefix(tuple(row.get("path") or ()), expected_root)
                   for row in evidence.inactive_hierarchies):
                reasons.append("TARGET_RELEVANT_HIERARCHY_INACTIVE_OR_UNKNOWN")
        if reasons:
            result.append(replace(item, blockers=tuple(dict.fromkeys((*item.blockers, *reasons))))); continue
        prefix = _prefix(item)
        existing = {path for path in actual if _has_prefix(prefix, path)}
        desired = set()
        for command in _commands(item, by_key):
            tokens = shlex.split(command)
            if tokens and tokens[0] == "set":
                desired.add(tuple(tokens[1:]))
        if existing == desired:
            result.append(replace(item, target_disposition="REUSE"))
        elif existing:
            result.append(replace(item, blockers=tuple(dict.fromkeys((*item.blockers, "TARGET_OBJECT_CONFLICT")))))
        else:
            result.append(item)
    return tuple(result)
