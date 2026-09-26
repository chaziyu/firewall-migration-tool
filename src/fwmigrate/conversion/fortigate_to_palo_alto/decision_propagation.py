"""Validated, engineer-triggered propagation over explicit FortiGate relationships."""

from dataclasses import replace
from enum import StrEnum

from .decisions import PANDecisionReviewState, PANMigrationDecisionSet, make_decision_key


class MigrationRuleType(StrEnum):
    VDOM_SCOPE = "VDOM_SCOPE"
    PARENT_INTERFACE = "PARENT_INTERFACE"
    ZONE_TO_MEMBERS = "ZONE_TO_MEMBERS"
    VLAN_PARENT = "VLAN_PARENT"


def dependent_decision_keys(config, decisions):
    by_key = {item.key: item for item in decisions.decisions}
    interfaces = {(item.vdom or "root", item.name): item for item in getattr(config, "interfaces", ())}
    result = {}
    for decision in decisions.decisions:
        if decision.source_kind == "vdom" and decision.target_field in {"vsys", "virtual_router"}:
            result[decision.key] = [item.key for item in decisions.decisions
                                    if item.source_vdom == decision.source_vdom and item.key != decision.key
                                    and item.review_state != PANDecisionReviewState.CONFIRMED]
            continue
        if decision.source_kind != "interface" or decision.target_field != "target_interface":
            continue
        children = [item for item in interfaces.values()
                    if (item.vdom or "root") == decision.source_vdom and item.interface == decision.source_name]
        result[decision.key] = [key for child in children
                                if (key := make_decision_key(decision.source_vdom, "interface", child.name,
                                                            "target_interface")) in by_key
                                and by_key[key].review_state != PANDecisionReviewState.CONFIRMED]
        zone_key = make_decision_key(decision.source_vdom, "interface", decision.source_name, "target_zone")
        if zone_key in by_key and by_key[zone_key].review_state != PANDecisionReviewState.CONFIRMED:
            result[decision.key].append(zone_key)
        vdom_keys = [make_decision_key(decision.source_vdom, "vdom", decision.source_vdom, field)
                     for field in ("vsys", "virtual_router")]
        result[decision.key].extend(key for key in vdom_keys if key in by_key
                                    and by_key[key].review_state != PANDecisionReviewState.CONFIRMED)
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


def rule_affected_decision_keys(config, decisions, rule_type, source_key):
    """List current pending decision keys for a supported explicit relationship rule."""
    rule_type = MigrationRuleType(rule_type)
    by_key = {item.key: item for item in decisions.decisions}
    source = by_key.get(source_key)
    if source is None or source.review_state != PANDecisionReviewState.CONFIRMED or not source.value:
        raise ValueError("A confirmed source decision is required")
    if rule_type == MigrationRuleType.ZONE_TO_MEMBERS:
        keys = zone_member_decision_keys(config, decisions, source_key)
    elif rule_type == MigrationRuleType.VDOM_SCOPE:
        if source.source_kind != "vdom" or source.target_field not in {"vsys", "virtual_router"}:
            raise ValueError("VDOM_SCOPE requires a confirmed VDOM mapping")
        keys = [item.key for item in decisions.decisions
                if item.source_vdom == source.source_vdom and item.key != source_key
                and item.review_state != PANDecisionReviewState.CONFIRMED
                and item.mode.value != "UNSUPPORTED"]
    else:
        if source.source_kind != "interface" or source.target_field != "target_interface":
            raise ValueError(f"{rule_type.value} requires a confirmed interface mapping")
        interfaces = {(item.vdom or "root", item.name): item
                      for item in getattr(config, "interfaces", ()) if item.name}
        source_interface = interfaces.get((source.source_vdom, source.source_name))
        if source_interface is None:
            raise ValueError("Source interface is not present in the current configuration")
        if rule_type == MigrationRuleType.PARENT_INTERFACE:
            if any((item.vdom or "root", item.interface) == (source.source_vdom, source.source_name)
                   and item.vlanid is not None for item in interfaces.values()):
                keys = [make_decision_key(source.source_vdom, "interface", item.name, "target_interface")
                        for item in interfaces.values()
                        if (item.vdom or "root", item.interface) == (source.source_vdom, source.source_name)
                        and item.vlanid is not None]
                keys = [key for key in keys if key in by_key
                        and by_key[key].review_state != PANDecisionReviewState.CONFIRMED
                        and by_key[key].mode.value != "UNSUPPORTED"]
            else:
                raise ValueError("PARENT_INTERFACE requires explicit VLAN children")
        else:
            if source_interface.vlanid is None:
                raise ValueError("VLAN_PARENT requires an explicit VLAN interface")
            keys = dependent_decision_keys(config, decisions).get(source_key, ())
    return sorted(set(keys))


def repeated_zone_action_suggestions(config, decisions, *, min_confirmations=3):
    """Suggest explicit-member zone batches from repeated engineer mappings."""
    by_key = {item.key: item for item in decisions.decisions}
    interfaces = {(item.vdom or "root", item.name): item
                  for item in getattr(config, "interfaces", ()) if item.name}
    result = []
    for zone in getattr(config, "zones", ()):
        if "members" not in getattr(zone, "explicit_fields", set()):
            continue
        vdom = zone.vdom or "root"
        members = tuple(dict.fromkeys(zone.members or ()))
        mapped = {}
        pending = []
        for name in members:
            if (vdom, name) not in interfaces:
                continue
            key = make_decision_key(vdom, "interface", name, "target_zone")
            decision = by_key.get(key)
            if decision is None or decision.mode.value == "UNSUPPORTED":
                continue
            if decision.review_state == PANDecisionReviewState.CONFIRMED:
                if (decision.evidence_source == "ENGINEER" and decision.value
                        and decision.evidence_type != "ENGINEER_REPEATED_ACTION_RULE"):
                    mapped.setdefault(decision.value, []).append(name)
            else:
                pending.append((name, key))
        for target_zone, confirmed_names in mapped.items():
            if len(set(confirmed_names)) < min_confirmations:
                continue
            result.append({"rule_type": "REPEATED_ZONE_ACTION", "source_vdom": vdom,
                "source_zone": zone.name, "target_zone": target_zone,
                "confirmed_count": len(set(confirmed_names)),
                "affected": [name for name, _ in pending],
                "apply_to": [key for _, key in pending]})
    return sorted(result, key=lambda item: (item["source_vdom"], item["source_zone"], item["target_zone"]))


def apply_repeated_zone_action(config, decisions, *, source_vdom, source_zone, value, apply_to,
                               min_confirmations=3):
    suggestions = repeated_zone_action_suggestions(config, decisions,
        min_confirmations=min_confirmations)
    suggestion = next((item for item in suggestions if
        (item["source_vdom"], item["source_zone"], item["target_zone"])
        == (source_vdom, source_zone, value)), None)
    if suggestion is None:
        raise ValueError("Repeated engineer pattern is no longer present")
    if (not isinstance(apply_to, list) or not apply_to
            or any(not isinstance(key, str) for key in apply_to)
            or len(set(apply_to)) != len(apply_to)
            or not set(apply_to) <= set(suggestion["apply_to"])):
        raise ValueError("apply_to contains a decision outside the current explicit-member pattern")
    by_key = {item.key: item for item in decisions.decisions}
    for key in apply_to:
        by_key[key] = replace(by_key[key], value=value, review_state=PANDecisionReviewState.CONFIRMED,
            evidence_source="ENGINEER", evidence_type="ENGINEER_REPEATED_ACTION_RULE",
            evidence_value=f"{source_vdom}/{source_zone}", target_object=value)
    return PANMigrationDecisionSet(tuple(sorted(by_key.values(), key=lambda item: item.key)))


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
