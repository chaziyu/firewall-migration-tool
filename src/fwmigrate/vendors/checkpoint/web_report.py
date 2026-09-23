"""Secret-safe Check Point source preview serialization."""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from typing import Any

from .source_report import CheckPointSourceResult


def build_checkpoint_preview(result: CheckPointSourceResult) -> dict[str, Any]:
    config = result.config
    fields = tuple(type(config).model_fields)
    return {
        "vendor": "checkpoint",
        "summary": {name: len(getattr(config, name)) for name in fields},
        "sections": {
            name: [item.model_dump() for item in getattr(config, name)]
            for name in fields
        },
        "collection": [item.model_dump() for item in result.collection],
        "source_inventory": [item.model_dump() for item in result.source_inventory],
        "source_metadata": asdict(result.source_metadata),
        "relationships": {
            "references": _jsonable(result.derived.references),
            "policy_structure": _jsonable(result.derived.policy_structure),
            "interface_topology": _jsonable(result.derived.interface_topology),
            "vpn_topology": _jsonable(result.derived.vpn_topology),
            "identity": _jsonable(result.derived.identity),
            "broken_references": _jsonable(result.derived.broken_references),
            "groups": result.derived.group_memberships,
            "package_layers": result.derived.package_layers,
            "inline_layers": result.derived.inline_layers,
            "unresolved_references": list(result.derived.unresolved_references),
        },
        "validation": [issue.__dict__ for issue in result.validation.issues],
    }


def _jsonable(value: Any):
    if is_dataclass(value): return {key: _jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, dict): return {str(_jsonable(key)): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)): return [_jsonable(item) for item in value]
    if hasattr(value, "model_dump"): return _jsonable(value.model_dump())
    if isinstance(value, (str, int, float, bool)) or value is None: return value
    return str(value)


__all__ = ["build_checkpoint_preview"]
