"""Validated, engineer-triggered propagation over explicit FortiGate relationships."""

from dataclasses import replace

from .decisions import PANDecisionReviewState, PANMigrationDecisionSet, make_decision_key


def dependent_decision_keys(config, decisions):
    by_key = {item.key: item for item in decisions.decisions}
    interfaces = {(item.vdom or "root", item.name): item for item in getattr(config, "interfaces", ())}
    result = {}
    for decision in decisions.decisions:
        if decision.source_kind != "interface" or decision.target_field != "target_interface":
            continue
        children = [item for item in interfaces.values()
                    if (item.vdom or "root") == decision.source_vdom and item.interface == decision.source_name]
        result[decision.key] = [key for child in children
                                if (key := make_decision_key(decision.source_vdom, "interface", child.name,
                                                            "target_interface")) in by_key
                                and by_key[key].review_state != PANDecisionReviewState.CONFIRMED]
    return result


def zone_member_decision_keys(config, decisions, source_key):
    by_key = {item.key: item for item in decisions.decisions}
    source = by_key.get(source_key)
    if not source or source.source_kind != "zone" or source.target_field != "target_zone":
        return []
    zone = next((item for item in getattr(config, "zones", ())
                 if (item.vdom or "root", item.name) == (source.source_vdom, source.source_name)), None)
    if zone is None or "members" not in getattr(zone, "explicit_fields", set()):
        return []
    keys = []
    for member in zone.members or ():
        key = make_decision_key(source.source_vdom, "interface", member, "target_zone")
        decision = by_key.get(key)
        if decision and decision.review_state != PANDecisionReviewState.CONFIRMED and decision.mode.value != "UNSUPPORTED":
            keys.append(key)
    return keys


def apply_zone_to_members(config, decisions, *, source_key, value, apply_to):
    by_key = {item.key: item for item in decisions.decisions}
    source = by_key.get(source_key)
    if (not source or source.source_kind != "zone" or source.target_field != "target_zone"
            or source.review_state != PANDecisionReviewState.CONFIRMED or source.value != value):
        raise ValueError("A confirmed source-zone target mapping is required")
    eligible = set(zone_member_decision_keys(config, decisions, source_key))
    if not isinstance(apply_to, list) or not apply_to or any(not isinstance(key, str) for key in apply_to):
        raise ValueError("apply_to must be a non-empty array of decision keys")
    if len(set(apply_to)) != len(apply_to) or not set(apply_to) <= eligible:
        raise ValueError("apply_to contains a decision that is not an unresolved explicit zone member")
    for key in apply_to:
        by_key[key] = replace(by_key[key], value=value, review_state=PANDecisionReviewState.CONFIRMED,
                              evidence_source="ENGINEER", evidence_type="ENGINEER_ZONE_TO_MEMBERS",
                              evidence_value=source.source_name, target_object=value)
    return PANMigrationDecisionSet(tuple(sorted(by_key.values(), key=lambda item: item.key)))
