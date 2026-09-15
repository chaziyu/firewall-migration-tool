from typing import Any

from fwmigrate.ir.version import IR_SCHEMA_VERSION


def migrate_1_67_to_1_68(payload: dict[str, Any]) -> dict[str, Any]:
    """Add Junos NAT fidelity and source-topology fields without guessing."""
    if payload.get("schema_version") != "1.67":
        return dict(payload)

    migrated = dict(payload)
    metadata = migrated.get("metadata")
    if isinstance(metadata, dict):
        metadata.setdefault("source_format", None)

    for rule in migrated.get("nat_rules", []):
        if not isinstance(rule, dict):
            continue
        rule.setdefault("source_rule_set", None)
        rule.setdefault("from_routing_instances", [])
        rule.setdefault("to_routing_instances", [])
        source_attributes = rule.get("source_attributes")
        if (
            isinstance(source_attributes, dict)
            and source_attributes.get("junos_static_nat") is True
            and rule.get("type") == "destination"
        ):
            rule["type"] = "static"
            rule["source_translation_bidirectional"] = True

    for pool in migrated.get("ip_pools", []):
        if not isinstance(pool, dict):
            continue
        pool.setdefault("addresses", [])
        pool.setdefault("address_ranges", [])
        source_attributes = pool.get("source_attributes")
        if not isinstance(source_attributes, dict):
            continue

        addresses = source_attributes.get("junos_addresses")
        if isinstance(addresses, list) and all(isinstance(item, str) for item in addresses):
            pool["addresses"] = list(addresses)

        ranges = source_attributes.get("junos_address_ranges")
        if isinstance(ranges, list):
            typed_ranges = [
                {"start_ip": item["start"], "end_ip": item["end"]}
                for item in ranges
                if isinstance(item, dict)
                and isinstance(item.get("start"), str)
                and isinstance(item.get("end"), str)
            ]
            if len(typed_ranges) == len(ranges):
                pool["address_ranges"] = typed_ranges

    for group in migrated.get("address_groups", []):
        if isinstance(group, dict):
            group.setdefault("source_direct_members", [])
            group.setdefault("source_nested_group_members", [])

    migrated["schema_version"] = IR_SCHEMA_VERSION
    return migrated
