"""FortiGate semantic checks that are separate from reference resolution."""

from __future__ import annotations

from typing import Iterable, List

from fwmigrate.extraction.models import DependencyRecord, SourceInventoryItem
from fwmigrate.ir.core import IRAuditEntry, IRConfig, MigrationConfidence


def _items(items: Iterable[SourceInventoryItem]) -> Iterable[SourceInventoryItem]:
    for item in items:
        yield item
        yield from _items(item.children)


def _direction(item: SourceInventoryItem) -> str | None:
    value = item.source_attributes.get("direction")
    if value is None:
        command = next((c for c in item.commands if c.key == "direction"), None)
        value = command.values[0] if command and command.values else None
    return str(value).strip().lower() if value is not None else "both"


INTERNET_SERVICE_GROUP_REFERENCE_DIRECTIONS = {
    ("firewall local-in-policy", "internet-service-src-group"): "source",
    ("firewall local-in-policy6", "internet-service6-src-group"): "source",
    ("firewall policy", "internet-service-src-group"): "source",
    ("firewall policy", "internet-service-group"): "destination",
    ("firewall policy", "internet-service6-src-group"): "source",
    ("firewall policy", "internet-service6-group"): "destination",
    ("firewall security-policy", "internet-service-src-group"): "source",
    ("firewall security-policy", "internet-service-group"): "destination",
    ("firewall security-policy", "internet-service6-src-group"): "source",
    ("firewall security-policy", "internet-service6-group"): "destination",
}


def _is_group_direction_compatible(
    configured_direction: str | None,
    required_direction: str,
) -> bool:
    direction = configured_direction or "both"
    return direction == "both" or direction == required_direction


def _rule_for_dependency(dependency: DependencyRecord, ir_config: IRConfig):
    collections = {
        "firewall local-in-policy": ir_config.local_in_policies,
        "firewall local-in-policy6": ir_config.local_in_policies,
        "firewall security-policy": ir_config.security_policies,
        "firewall policy": ir_config.policies,
    }
    identifier = "source_rule_id" if dependency.source_path == "firewall policy" else "source_id"
    family = {
        "firewall local-in-policy": "local-in-policy-ipv4",
        "firewall local-in-policy6": "local-in-policy-ipv6",
    }.get(dependency.source_path)
    return next(
        (
            rule for rule in collections.get(dependency.source_path, [])
            if (rule.source_context or "root") == (dependency.source_context or "root")
            and getattr(rule, identifier, None) == dependency.source_object
            and (family is None or rule.family == family)
        ),
        None,
    )


def validate_internet_service_group_directions(
    inventory_items: Iterable[SourceInventoryItem],
    dependencies: Iterable[DependencyRecord],
    ir_config: IRConfig,
) -> List[str]:
    """Record source-group direction mismatches without changing dependency identity."""
    inventory = list(_items(inventory_items))
    groups = {
        (item.source_context or "root", item.name): item
        for item in inventory
        if item.source_path == "firewall internet-service-group" and item.name
    }
    typed_groups = {
        (group.source_context or "root", group.name): group
        for group in ir_config.internet_service_groups
    }
    findings: List[str] = []
    for dependency in dependencies:
        required_direction = INTERNET_SERVICE_GROUP_REFERENCE_DIRECTIONS.get(
            (dependency.source_path, dependency.source_field)
        )
        if (
            dependency.result != "RESOLVED"
            or dependency.target_path != "firewall internet-service-group"
            or required_direction is None
        ):
            continue
        group = groups.get((dependency.source_context or "root", dependency.reference))
        if group is None:
            continue
        typed_group = typed_groups.get((dependency.source_context or "root", dependency.reference))
        direction = (
            str(typed_group.direction).lower()
            if typed_group is not None
            else _direction(group)
        )
        if _is_group_direction_compatible(direction, required_direction):
            continue
        rule = _rule_for_dependency(dependency, ir_config)
        field = dependency.source_field
        note = f"incompatible-internet-service-group-direction:{dependency.reference}"
        message = (
            f"Internet Service group '{dependency.reference}' is configured with direction "
            f"'{direction}' but {dependency.source_path} object "
            f"'{dependency.source_object}' field '{field}' requires "
            f"{required_direction}-compatible usage."
        )
        if rule is not None and message not in rule.review_reasons:
            rule.review_reasons.append(message)
            rule.requires_manual_review = True
        source_item = next(
            (
                item for item in inventory
                if item.source_path == dependency.source_path
                and (item.source_context or "root") == (dependency.source_context or "root")
                and (item.name or item.source_id) == dependency.source_object
            ),
            None,
        )
        if source_item is not None and note not in source_item.notes:
            source_item.notes.append(note)
            source_item.requires_manual_review = True
        audit_id = (
            f"semantic:internet-service-group:{dependency.source_context or 'root'}:"
            f"{dependency.source_path}:{dependency.source_object}:{field}:{dependency.reference}"
        )
        if not any(entry.id == audit_id for entry in ir_config.audit_entries):
            ir_config.audit_entries.append(IRAuditEntry(
                id=audit_id,
                category="FortiGate Semantic Validation",
                message=message,
                confidence=MigrationConfidence.MANUAL,
            ))
        findings.append(message)
    def add_structural(message: str) -> None:
        audit_id = f"semantic:internet-service-structure:{message}"
        if not any(entry.id == audit_id for entry in ir_config.audit_entries):
            ir_config.audit_entries.append(IRAuditEntry(
                id=audit_id,
                category="FortiGate Semantic Validation",
                message=message,
                confidence=MigrationConfidence.MANUAL,
            ))
        findings.append(message)

    def check_ports(parent: str, entry_id: object, ports: Iterable[object]) -> None:
        for port in ports:
            if port.start_port is not None and port.end_port is not None and port.start_port > port.end_port:
                add_structural(f"Internet Service {parent} entry '{entry_id}' has start-port greater than end-port")

    for service in ir_config.custom_internet_services:
        for entry in service.entries:
            if entry.addr_mode == "ipv4" and entry.destination_ipv6:
                add_structural(f"Internet Service custom '{service.name}' entry '{entry.source_id}' has IPv6 data in an IPv4-only entry")
            if entry.addr_mode == "ipv6" and entry.destination_ipv4:
                add_structural(f"Internet Service custom '{service.name}' entry '{entry.source_id}' has IPv4 data in an IPv6-only entry")
            check_ports("custom", entry.source_id, entry.port_ranges)
    for service in ir_config.internet_service_additions:
        for entry in service.entries:
            check_ports("addition", entry.source_id, entry.port_ranges)
    for service in ir_config.internet_service_extensions:
        disable_ids = [entry.source_id for entry in service.disable_entries if entry.source_id is not None]
        if len(disable_ids) != len(set(disable_ids)):
            add_structural(f"Internet Service extension '{service.source_id}' has duplicate disable-entry identifiers")
        entry_ids = [entry.source_id for entry in service.entries if entry.source_id is not None]
        if len(entry_ids) != len(set(entry_ids)):
            add_structural(f"Internet Service extension '{service.source_id}' has duplicate entry identifiers")
        for entry in service.disable_entries:
            if entry.addr_mode == "ipv4" and entry.ipv6_ranges:
                add_structural(f"Internet Service extension '{service.source_id}' disable-entry '{entry.source_id}' has IPv6 data in an IPv4-only entry")
            if entry.addr_mode == "ipv6" and entry.ipv4_ranges:
                add_structural(f"Internet Service extension '{service.source_id}' disable-entry '{entry.source_id}' has IPv4 data in an IPv6-only entry")
            check_ports("extension disable-entry", entry.source_id, entry.port_ranges)
        for entry in service.entries:
            if entry.addr_mode == "ipv4" and entry.destination_ipv6:
                add_structural(f"Internet Service extension '{service.source_id}' entry '{entry.source_id}' has IPv6 data in an IPv4-only entry")
            if entry.addr_mode == "ipv6" and entry.destination_ipv4:
                add_structural(f"Internet Service extension '{service.source_id}' entry '{entry.source_id}' has IPv4 data in an IPv6-only entry")
            check_ports("extension entry", entry.source_id, entry.port_ranges)
    return list(dict.fromkeys(findings))
