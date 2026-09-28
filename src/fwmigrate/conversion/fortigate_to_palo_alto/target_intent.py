"""Compact, pair-specific engineer intent backed by migration decisions."""

from dataclasses import replace

import yaml

from .decisions import PANDecisionReviewState, PANMigrationDecisionSet, make_decision_key


def parse_target_intent(value):
    """Parse pair-specific engineer intent without creating a target model."""
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

    vdoms = value.get("vdoms", {})
    if not isinstance(vdoms, dict):
        raise ValueError("Target intent vdoms must be a mapping")
    for source, mapping in vdoms.items():
        if not isinstance(source, str) or not source or not isinstance(mapping, dict):
            raise ValueError("Each vdoms entry must map a source name to target fields")
        if set(mapping) - {"vsys", "virtual_router"} or not mapping:
            raise ValueError(f"Invalid target intent fields for vdoms.{source}")
        if any(not isinstance(target, str) or not target for target in mapping.values()):
            raise ValueError("Target intent values must be non-empty strings")
        result["vdoms"][source] = dict(mapping)

    interfaces = value.get("interfaces", {})
    if not isinstance(interfaces, dict):
        raise ValueError("Target intent interfaces must be a mapping")
    for source, mapping in interfaces.items():
        if not isinstance(source, str) or not source:
            raise ValueError("Each interfaces entry must have a non-empty source name")
        if isinstance(mapping, str):
            fields = {"interface": mapping}
        elif isinstance(mapping, dict) and mapping and not set(mapping) - {"interface", "zone"}:
            fields = dict(mapping)
        else:
            raise ValueError(f"Invalid target intent fields for interfaces.{source}")
        if any(not isinstance(target, str) or not target for target in fields.values()):
            raise ValueError("Target intent values must be non-empty strings")
        result["interfaces"][source] = fields

    zones = value.get("zones", {})
    if not isinstance(zones, dict):
        raise ValueError("Target intent zones must be a mapping")
    for source, mapping in zones.items():
        if not isinstance(source, str) or not source:
            raise ValueError("Each zones entry must have a non-empty source name")
        if isinstance(mapping, str):
            target = mapping
        elif isinstance(mapping, dict) and set(mapping) == {"zone"}:
            target = mapping["zone"]
        else:
            raise ValueError(f"Invalid target intent fields for zones.{source}")
        if not isinstance(target, str) or not target:
            raise ValueError("Target intent values must be non-empty strings")
        result["zones"][source] = {"zone": target}

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
        by_key[key] = replace(
            old,
            value=target,
            review_state=PANDecisionReviewState.CONFIRMED,
            evidence_source="ENGINEER",
            evidence_type="TARGET_INTENT",
            evidence_value=target,
            target_object=target,
        )

    for source, mapping in intent["vdoms"].items():
        if source not in vdoms:
            raise ValueError(f"Unknown FortiGate VDOM: {source}")
        for field, target in mapping.items():
            confirm(source, "vdom", source, field, target)

    for source, mapping in intent["interfaces"].items():
        requested_vdom, separator, name = source.partition("/")
        actual_name = name if separator else source
        matches = sorted(
            vdom for vdom, interface_name in interfaces
            if interface_name == actual_name and (not separator or vdom == requested_vdom)
        )
        if not matches:
            raise ValueError(f"Unknown FortiGate interface: {source}")
        if len(matches) != 1:
            raise ValueError(
                f"Interface {source} is ambiguous across VDOMs; use a scoped decision document"
            )
        vdom = matches[0]
        if "interface" in mapping:
            confirm(vdom, "interface", actual_name, "target_interface", mapping["interface"])
        if "zone" in mapping:
            confirm(vdom, "interface", actual_name, "target_zone", mapping["zone"])

    for source, mapping in intent["zones"].items():
        requested_vdom, separator, name = source.partition("/")
        actual_name = name if separator else source
        matches = sorted(
            vdom for vdom, zone_name in zones
            if zone_name == actual_name and (not separator or vdom == requested_vdom)
        )
        if not matches:
            raise ValueError(f"Unknown FortiGate zone: {source}")
        if len(matches) != 1:
            raise ValueError(
                f"Zone {source} is ambiguous across VDOMs; use a scoped decision document"
            )
        confirm(matches[0], "zone", actual_name, "target_zone", mapping["zone"])

    return PANMigrationDecisionSet(tuple(sorted(by_key.values(), key=lambda item: item.key)))


def export_target_intent(decisions):
    result = {"vdoms": {}, "interfaces": {}, "zones": {}}
    interface_counts = {}
    zone_counts = {}
    for item in decisions.decisions:
        if item.source_kind == "interface" and item.target_field in {"target_interface", "target_zone"}:
            interface_counts[item.source_name] = interface_counts.get(item.source_name, 0) + 1
        elif item.source_kind == "zone" and item.target_field == "target_zone":
            zone_counts[item.source_name] = zone_counts.get(item.source_name, 0) + 1

    for item in decisions.decisions:
        if item.review_state != PANDecisionReviewState.CONFIRMED or not item.value:
            continue
        if item.source_kind == "vdom":
            result["vdoms"].setdefault(item.source_vdom, {})[item.target_field] = item.value
        elif item.source_kind == "interface" and item.target_field in {"target_interface", "target_zone"}:
            scoped = interface_counts.get(item.source_name, 0) > 1 or item.source_vdom != "root"
            name = f"{item.source_vdom}/{item.source_name}" if scoped else item.source_name
            field = "interface" if item.target_field == "target_interface" else "zone"
            result["interfaces"].setdefault(name, {})[field] = item.value
        elif item.source_kind == "zone" and item.target_field == "target_zone":
            name = (
                f"{item.source_vdom}/{item.source_name}"
                if zone_counts.get(item.source_name, 0) > 1 or item.source_vdom != "root"
                else item.source_name
            )
            result["zones"][name] = item.value

    # Preserve the legacy compact form when an interface has only a target
    # interface value. Zone-aware entries use the explicit mapping form.
    for name, mapping in list(result["interfaces"].items()):
        if set(mapping) == {"interface"}:
            result["interfaces"][name] = mapping["interface"]

    return yaml.safe_dump(result, sort_keys=False, allow_unicode=True)
