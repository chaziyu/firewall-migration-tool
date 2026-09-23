"""Explicit, secret-safe Check Point presentation projection."""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from enum import Enum
from typing import Any

from fwmigrate.extraction.sanitize import sanitize_source_attributes
from .export.excel_schema import SOURCE_SHEETS
from .source_report import CheckPointSourceResult


def _project(value: Any) -> Any:
    if isinstance(value, Enum): return value.value
    if hasattr(value, "model_dump"): value = value.model_dump(mode="python", by_alias=False)
    elif is_dataclass(value): value = asdict(value)
    if isinstance(value, dict): return sanitize_source_attributes({str(k): _project(v) for k, v in value.items()})
    if isinstance(value, (list, tuple, set)): return [_project(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None: return value
    return str(value)


def _refs(values):
    return [_project(v) for v in values or ()]


def build_checkpoint_preview(result: CheckPointSourceResult) -> dict[str, Any]:
    config, derived = result.config, result.derived
    source = {field: [_project(item) for item in getattr(config, field)] for field in SOURCE_SHEETS.values()}
    nat = [{"source_kind": v.source_kind, "source_owner": v.owner_name or v.source_name,
            "translation_classification": v.translation_method, "original_source": _refs(v.original_source),
            "original_destination": _refs(v.original_destination), "translated_source": _refs(v.translated_source),
            "translated_destination": _refs(v.translated_destination), "issues": [_project(i) for i in v.issues]}
           for v in derived.nat.views]
    traversal = [{"package": e.package_name, "layer": e.layer_name, "section": e.section_name,
                  "rule": e.rule_name, "source_rule_order": e.rule_order,
                  "derived_traversal_position": e.traversal_position, "parent_rule": e.parent_rule_uid,
                  "inline_depth": e.inline_depth, "issues": [_project(i) for i in e.issues]}
                 for e in derived.policy_traversal.entries]
    interfaces = [{"device": v.device_name, "device_kind": v.device_kind, "interface": v.interface_name,
                  "resolved_zone": v.resolved_zone_name, "zone_assignment_source": v.zone_assignment_source,
                  "management_source_present": v.management_source_present, "gaia_source_present": v.gaia_source_present,
                  "issues": [_project(i) for i in v.issues]} for v in derived.interface_views.views]
    vpn = [{"community": v.community_name, "community_type": v.community_type,
            "gateways": _refs(v.member_gateways), "clusters": _refs(v.member_clusters),
            "interoperable_devices": _refs(v.member_interoperable_devices), "centers": _refs(v.center_members),
            "satellites": _refs(v.satellite_members), "vpn_domains": _refs(v.vpn_domains),
            "vtis": _refs(v.vtis), "route_based": v.route_based, "issues": [_project(i) for i in v.issues]}
           for v in derived.vpn_views.views]
    return _project({
        "vendor": "checkpoint",
        "summary": {"source_objects": sum(len(getattr(config, field)) for field in SOURCE_SHEETS.values()),
                    "derived_views": len(nat) + len(traversal) + len(interfaces) + len(vpn),
                    "validation_findings": len(result.validation.issues),
                    "incomplete_collections": len(derived.collection_incomplete),
                    "unsupported_source_inventory": len(result.source_inventory),
                    "scope_ambiguous": bool(getattr(result.scope, "ambiguous", False)),
                    "capabilities": {"SD-WAN": "No direct R81.00 equivalent"}},
        "collection": [_project(item) for item in result.collection],
        "scope": _project(result.scope), "source": source,
        "derived": {"nat": nat, "policy_traversal": traversal, "interfaces": interfaces, "vpn": vpn,
                    "unresolved_references": [_project(i) for i in derived.broken_references]},
        "validation": [_project(i) for i in result.validation.issues],
        "source_inventory": [_project(i) for i in result.source_inventory],
        "unsupported": {"inventory": [_project(i) for i in result.source_inventory],
                        "collections": [_project(i) for i in result.collection if not i.complete]},
        "source_metadata": _project(result.source_metadata),
    })


__all__ = ["build_checkpoint_preview"]
