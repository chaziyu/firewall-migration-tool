"""Explicit PAN-OS extraction stages."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fwmigrate.extraction import ExtractionStatus, finalize_extraction

from .dependencies import build_pan_nat_dependencies
from .policy_nat_coverage import PANOSSourceParser as _CoveragePANOSSourceParser
from .policy_order import sync_effective_order_to_ir


def managed_nat_chain(parser, device_group: Optional[str]) -> tuple[List[str], bool]:
    if not device_group:
        return [], True
    parents = dict(parser.resolver._dg_parents)
    chain = [device_group]
    visited = {device_group}
    current = device_group
    complete = True
    while current in parents:
        parent = parents[current]
        if parent in visited:
            complete = False
            break
        visited.add(parent)
        chain.append(parent)
        current = parent
    chain.reverse()
    return chain, complete


def nat_rules_for_scope(
    extraction,
    kind: str,
    name: str,
    position: str,
    device_serial: Optional[str] = None,
) -> List[Any]:
    items = [
        item for item in extraction.inventory_items
        if item.domain == "nat"
        and item.source_attributes.get("scope_kind") == kind
        and item.source_attributes.get("scope_name") == name
        and item.source_attributes.get("pan_rulebase_position") == position
        and (
            (device_serial is None and not item.source_attributes.get("scope_device_serial"))
            or (
                device_serial is not None
                and item.source_attributes.get("scope_device_serial") == device_serial
            )
        )
    ]
    return sorted(
        items,
        key=lambda item: item.source_attributes.get("pan_source_rule_index", 2**31),
    )


def materialize_managed_nat_contexts(parser, extraction) -> None:
    """Build effective NAT order for every managed firewall/VSYS.

    The base order builder discovers concrete NAT contexts from local VSYS
    NAT inventory.  A managed firewall may legitimately inherit all NAT
    rules from Panorama and therefore have no local NAT items.  Use the
    Panorama managed-VSYS topology instead so inherited-only NAT still has
    a device-qualified effective order and can be target-filtered safely.
    """
    hierarchy_error = any(
        item.domain == "panorama_hierarchy"
        and item.status == ExtractionStatus.PARSE_ERROR
        for item in extraction.inventory_items
    )

    for identity in parser.resolver.managed_vsys_identities():
        serial = identity.device_serial
        vsys = identity.vsys_name
        device_group = parser.resolver.device_group_for_vsys(vsys, serial)
        chain, chain_complete = managed_nat_chain(parser, device_group)
        sequence: List[tuple[str, Any]] = []

        sequence.extend(
            ("shared-pre-nat-rules", item)
            for item in nat_rules_for_scope(
                extraction, "shared", "shared", "pre"
            )
        )

        if device_group:
            for ancestor in chain[:-1]:
                sequence.extend(
                    ("ancestor-device-group-pre-nat-rules", item)
                    for item in nat_rules_for_scope(
                        extraction, "device-group", ancestor, "pre"
                    )
                )
            sequence.extend(
                ("current-device-group-pre-nat-rules", item)
                for item in nat_rules_for_scope(
                    extraction, "device-group", device_group, "pre"
                )
            )

        for position, layer in (
            ("pre", "local-pre-nat-rules"),
            ("local", "local-nat-rules"),
            ("post", "local-post-nat-rules"),
        ):
            sequence.extend(
                (layer, item)
                for item in nat_rules_for_scope(
                    extraction, "vsys", vsys, position, serial
                )
            )

        if device_group:
            sequence.extend(
                ("current-device-group-post-nat-rules", item)
                for item in nat_rules_for_scope(
                    extraction, "device-group", device_group, "post"
                )
            )
            for ancestor in reversed(chain[:-1]):
                sequence.extend(
                    ("ancestor-device-group-post-nat-rules", item)
                    for item in nat_rules_for_scope(
                        extraction, "device-group", ancestor, "post"
                    )
                )

        sequence.extend(
            ("shared-post-nat-rules", item)
            for item in nat_rules_for_scope(
                extraction, "shared", "shared", "post"
            )
        )

        context = f"device:{serial}:vsys:{vsys}"
        scope_chain = ["shared", *chain, context]
        complete = chain_complete and not hierarchy_error
        for rank, (layer, item) in enumerate(sequence):
            position = {
                "effective_policy_layer": layer,
                "effective_policy_rank": rank,
                "effective_scope_chain": scope_chain,
                "effective_rule_index": rank,
                "effective_order_complete": complete,
            }
            item.source_attributes.setdefault(
                "pan_effective_order_by_context", {}
            )[context] = position


def apply_pan_target_applicability(parser, extraction, base_apply) -> None:
    # The coverage layer may run target filtering more than once as new
    # concrete managed-device contexts are materialized.  Preserve earlier
    # not-applicable/unknown audit results even after their order entries
    # have correctly been removed from the effective context map.
    previous = {
        item.source_record_id: dict(
            item.source_attributes.get("pan_target_applicability_by_context", {})
        )
        for item in extraction.inventory_items
        if item.domain in {"policies", "nat"}
    }
    base_apply(extraction)
    for item in extraction.inventory_items:
        if item.domain not in {"policies", "nat"}:
            continue
        old = previous.get(item.source_record_id, {})
        current = item.source_attributes.get(
            "pan_target_applicability_by_context", {}
        )
        if old or current:
            item.source_attributes["pan_target_applicability_by_context"] = {
                **old,
                **current,
            }


def finalize_pan_extraction(parser, extraction):
    """Run post-source accounting and finalize one PAN extraction result."""
    extraction.dependencies = build_pan_nat_dependencies(extraction, parser.resolver)
    materialize_managed_nat_contexts(parser, extraction)
    apply_pan_target_applicability(
        parser, extraction, parser._apply_target_applicability_base
    )
    _CoveragePANOSSourceParser._mark_nat_hierarchy_completeness(extraction)
    sync_effective_order_to_ir(extraction)
    _CoveragePANOSSourceParser._refresh_extraction_accounting(extraction)
    return finalize_extraction(extraction)
