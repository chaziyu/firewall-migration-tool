"""Check Point relationships and read-only derived views."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .source_model import CheckPointConfig, CheckPointSourceRecord


@dataclass(frozen=True)
class CheckPointDerivedViews:
    by_uid: dict[str, CheckPointSourceRecord] = field(default_factory=dict)
    by_name: dict[tuple[str | None, str], tuple[CheckPointSourceRecord, ...]] = field(default_factory=dict)
    group_memberships: dict[str, tuple[str, ...]] = field(default_factory=dict)
    package_layers: dict[str, tuple[str, ...]] = field(default_factory=dict)
    inline_layers: dict[str, str] = field(default_factory=dict)
    unresolved_references: tuple[dict[str, Any], ...] = ()
    collection_incomplete: tuple[Any, ...] = ()


def _scope(item: CheckPointSourceRecord) -> str | None:
    return item.domain_uid or item.domain or "global"


def build_checkpoint_derived_views(config: CheckPointConfig) -> CheckPointDerivedViews:
    records = [
        item
        for field in type(config).model_fields
        if field != "collection"
        for item in (getattr(config, field) or [])
        if isinstance(item, CheckPointSourceRecord)
    ]
    by_uid = {item.uid: item for item in records if item.uid}
    names: dict[tuple[str | None, str], list[CheckPointSourceRecord]] = {}
    for item in records:
        if item.name:
            names.setdefault((_scope(item), item.name), []).append(item)
    group_memberships = {
        item.uid or f"{_scope(item)}:{item.name}": tuple(
            str(member.get("uid") or member.get("name") or member)
            if isinstance(member, dict) else str(member)
            for member in item.members
        )
        for item in config.groups
    }
    package_layers: dict[str, list[str]] = {}
    for layer in config.access_layers:
        if layer.package_uid or layer.package:
            package_layers.setdefault(layer.package_uid or layer.package or "", []).append(layer.uid or layer.name or "")
    inline_layers = {
        layer.uid or layer.name or "": layer.parent_layer_uid
        for layer in config.access_layers
        if layer.parent_layer_uid
    }
    unresolved: list[dict[str, Any]] = []
    for item in config.access_rules + config.nat_rules:
        for reference in item.references:
            values = reference if isinstance(reference, list) else [reference]
            for value in values:
                key = value.get("uid") or value.get("name") if isinstance(value, dict) else value
                if key in (None, "", "any", "Any", "Original"):
                    continue
                if str(key) not in by_uid and (_scope(item), str(key)) not in names:
                    unresolved.append({"command": item.command, "uid": item.uid, "reference": str(key)})
    return CheckPointDerivedViews(
        by_uid=by_uid,
        by_name={key: tuple(value) for key, value in names.items()},
        group_memberships=group_memberships,
        package_layers={key: tuple(value) for key, value in package_layers.items()},
        inline_layers=inline_layers,
        unresolved_references=tuple(unresolved),
        collection_incomplete=tuple(item for item in config.collection if not item.complete),
    )


__all__ = ["CheckPointDerivedViews", "build_checkpoint_derived_views"]
