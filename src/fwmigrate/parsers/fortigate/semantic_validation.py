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
    local_rules = {
        (rule.source_context or "root", rule.source_id or rule.name): rule
        for rule in ir_config.local_in_policies
    }
    findings: List[str] = []
    for dependency in dependencies:
        if (
            dependency.result != "RESOLVED"
            or dependency.target_path != "firewall internet-service-group"
            or dependency.source_path not in {"firewall local-in-policy", "firewall local-in-policy6"}
            or dependency.source_field not in {"internet-service-src-group", "internet-service6-src-group"}
        ):
            continue
        group = groups.get((dependency.source_context or "root", dependency.reference))
        if group is None:
            continue
        direction = _direction(group)
        if direction in {"source", "both"}:
            continue
        rule = local_rules.get((dependency.source_context or "root", dependency.source_object))
        field = dependency.source_field
        note = f"incompatible-internet-service-group-direction:{dependency.reference}"
        message = (
            f"Internet Service group '{dependency.reference}' is configured with direction "
            f"'{direction}' but is referenced by Local-In source Internet Service field "
            f"'{field}'. The object exists, but its configured direction is incompatible "
            "with source-group usage."
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
    return list(dict.fromkeys(findings))
