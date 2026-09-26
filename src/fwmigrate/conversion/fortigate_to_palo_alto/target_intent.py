"""Compact, pair-specific engineer intent backed by migration decisions."""

from dataclasses import replace

import yaml

from .decisions import PANDecisionReviewState, PANMigrationDecisionSet, make_decision_key


def parse_target_intent(value):
    """Parse the supported YAML mapping without creating a target model."""
    if isinstance(value, str):
        try:
            value = yaml.safe_load(value)
        except yaml.YAMLError as exc:
            raise ValueError("Invalid target intent YAML") from exc
    if value is None:
        value = {}
    if not isinstance(value, dict) or set(value) - {"vdoms", "interfaces", "zones"}:
        raise ValueError("Target intent must contain only vdoms, interfaces, and zones")
    result = {"vdoms": {}, "interfaces": {}, "zones": {}}
    for section, allowed in (("vdoms", {"vsys", "virtual_router"}), ("interfaces", None), ("zones", None)):
        items = value.get(section, {})
        if not isinstance(items, dict):
            raise ValueError(f"Target intent {section} must be a mapping")
        for source, mapping in items.items():
            if not isinstance(source, str) or not source or (section == "vdoms" and not isinstance(mapping, dict)):
                raise ValueError(f"Each {section} entry must map a source name to target fields")
            if allowed is None:
                field = "interface" if section == "interfaces" else "zone"
                if isinstance(mapping, str):
                    target = mapping
                elif isinstance(mapping, dict) and set(mapping) == {field}:
                    target = mapping[field]
                else:
                    raise ValueError(f"Invalid target intent fields for {section}.{source}")
                if not isinstance(target, str) or not target:
                    raise ValueError("Target intent values must be non-empty strings")
                result[section].setdefault(source, {})[field] = target
            else:
                if set(mapping) - allowed or not mapping or any(not isinstance(target, str) or not target for target in mapping.values()):
                    raise ValueError(f"Invalid target intent fields for {section}.{source}")
                result[section][source] = dict(mapping)
    return result


def apply_target_intent(config, decisions: PANMigrationDecisionSet, intent):
    intent = parse_target_intent(intent)
    vdoms = {item.source_vdom for item in decisions.decisions}
    interfaces = {(item.vdom or "root", item.name) for item in getattr(config, "interfaces", ()) if item.name}
    zones = {(item.vdom or "root", item.name) for item in getattr(config, "zones", ()) if item.name}
    by_key = {item.key: item for item in decisions.decisions}

    def confirm(vdom, kind, source, field, target):
        key = make_decision_key(vdom, kind, source, field)
        old = by_key.get(key)
        if old is None or old.mode.value == "UNSUPPORTED":
            raise ValueError(f"Target intent has no supported decision for {vdom}.{source}.{field}")
        by_key[key] = replace(old, value=target, review_state=PANDecisionReviewState.CONFIRMED,
                              evidence_source="ENGINEER", evidence_type="TARGET_INTENT",
                              evidence_value=target, target_object=target)

    for source, mapping in intent["vdoms"].items():
        if source not in vdoms:
            raise ValueError(f"Unknown FortiGate VDOM: {source}")
        for field, target in mapping.items():
            confirm(source, "vdom", source, field, target)
    for source, mapping in intent["interfaces"].items():
        requested_vdom, separator, name = source.partition("/")
        matches = sorted(vdom for vdom, interface_name in interfaces
                         if interface_name == (name if separator else source)
                         and (not separator or vdom == requested_vdom))
        if not matches:
            raise ValueError(f"Unknown FortiGate interface: {source}")
        if len(matches) != 1:
            raise ValueError(f"Interface {source} is ambiguous across VDOMs; use a scoped decision document")
        confirm(matches[0], "interface", name if separator else source, "target_interface", mapping["interface"])
    for source, mapping in intent["zones"].items():
        requested_vdom, separator, name = source.partition("/")
        matches = sorted(vdom for vdom, zone_name in zones
                         if zone_name == (name if separator else source)
                         and (not separator or vdom == requested_vdom))
        if not matches:
            raise ValueError(f"Unknown FortiGate zone: {source}")
        if len(matches) != 1:
            raise ValueError(f"Zone {source} is ambiguous across VDOMs; use a scoped decision document")
        confirm(matches[0], "zone", name if separator else source, "target_zone", mapping["zone"])
    return PANMigrationDecisionSet(tuple(sorted(by_key.values(), key=lambda item: item.key)))


def export_target_intent(decisions):
    result = {"vdoms": {}, "interfaces": {}, "zones": {}}
    interface_counts = {}
    zone_counts = {}
    for item in decisions.decisions:
        if item.source_kind == "interface" and item.target_field == "target_interface":
            interface_counts[item.source_name] = interface_counts.get(item.source_name, 0) + 1
        elif item.source_kind == "zone" and item.target_field == "target_zone":
            zone_counts[item.source_name] = zone_counts.get(item.source_name, 0) + 1
    for item in decisions.decisions:
        if item.review_state != PANDecisionReviewState.CONFIRMED or not item.value:
            continue
        if item.source_kind == "vdom":
            result["vdoms"].setdefault(item.source_vdom, {})[item.target_field] = item.value
        elif item.source_kind == "interface" and item.target_field == "target_interface":
            name = f"{item.source_vdom}/{item.source_name}" if interface_counts[item.source_name] > 1 or item.source_vdom != "root" else item.source_name
            result["interfaces"][name] = item.value
        elif item.source_kind == "zone" and item.target_field == "target_zone":
            name = f"{item.source_vdom}/{item.source_name}" if zone_counts[item.source_name] > 1 or item.source_vdom != "root" else item.source_name
            result["zones"][name] = item.value
    return yaml.safe_dump(result, sort_keys=False, allow_unicode=True)
