from __future__ import annotations

from .models import PANDecisionDependency, PANDecisionGraph
from ..decisions import PANMigrationDecisionSet, make_decision_key
from ..requirements import build_mapping_requirements


def build_decision_graph(config, derived, decisions: PANMigrationDecisionSet, requirements=None) -> PANDecisionGraph:
    """Build ordering from planner requirements and explicit FortiGate topology."""
    requirements = requirements or build_mapping_requirements(config, derived)
    by_key = {item.key: item for item in decisions.decisions}
    parents: dict[str, set[str]] = {key: set() for key in by_key}
    interfaces = {
        (item.vdom or "root", item.name): item
        for item in getattr(config, "interfaces", ())
        if item.name
    }
    zones = {
        (item.vdom or "root", item.name): item
        for item in getattr(config, "zones", ())
        if item.name
    }
    vdom_requirements = {
        item["source_vdom"]: tuple(item.get("requires", ()))
        for item in requirements.get("vdoms", ())
    }

    def add_if_present(key, prerequisite):
        if key in parents and prerequisite in by_key and prerequisite != key:
            parents[key].add(prerequisite)

    for decision in decisions.decisions:
        if decision.source_kind == "interface" and decision.target_field == "target_interface":
            for field in vdom_requirements.get(decision.source_vdom, ()):
                add_if_present(decision.key, make_decision_key(decision.source_vdom, "vdom", decision.source_vdom, field))
            source = interfaces.get((decision.source_vdom, decision.source_name))
            if source and source.interface:
                add_if_present(
                    decision.key,
                    make_decision_key(decision.source_vdom, "interface", source.interface, "target_interface"),
                )
        elif decision.source_kind == "interface" and decision.target_field == "target_zone":
            add_if_present(
                decision.key,
                make_decision_key(decision.source_vdom, "interface", decision.source_name, "target_interface"),
            )
        elif decision.source_kind == "zone" and decision.target_field == "target_zone":
            source_zone = zones.get((decision.source_vdom, decision.source_name))
            for member in getattr(source_zone, "members", ()) or ():
                add_if_present(
                    decision.key,
                    make_decision_key(decision.source_vdom, "interface", member, "target_interface"),
                )

    return PANDecisionGraph(tuple(
        PANDecisionDependency(key, tuple(sorted(parents[key])))
        for key in sorted(parents)
    ))
