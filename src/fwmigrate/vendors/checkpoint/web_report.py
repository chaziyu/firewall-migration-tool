"""Secret-safe Check Point source preview serialization."""

from __future__ import annotations

from dataclasses import asdict
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
            "groups": result.derived.group_memberships,
            "package_layers": result.derived.package_layers,
            "inline_layers": result.derived.inline_layers,
            "unresolved_references": list(result.derived.unresolved_references),
        },
        "validation": [issue.__dict__ for issue in result.validation.issues],
    }


__all__ = ["build_checkpoint_preview"]
