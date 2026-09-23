"""Check Point relationships and read-only derived views."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .relationships.policy_structure import build_policy_structure
from .relationships.references import build_reference_views
from .model.source import CheckPointConfig


@dataclass(frozen=True)
class CheckPointDerivedViews:
    by_uid: dict[str, Any] = field(default_factory=dict)
    by_name: dict[tuple[str | None, str], tuple[Any, ...]] = field(default_factory=dict)
    group_memberships: dict[str, tuple[str, ...]] = field(default_factory=dict)
    package_layers: dict[str, tuple[str, ...]] = field(default_factory=dict)
    inline_layers: dict[str, str] = field(default_factory=dict)
    unresolved_references: tuple[dict[str, Any], ...] = ()
    collection_incomplete: tuple[Any, ...] = ()


def build_checkpoint_derived_views(config: CheckPointConfig) -> CheckPointDerivedViews:
    by_uid, by_name, memberships, unresolved = build_reference_views(config)
    package_layers, inline_layers = build_policy_structure(config)
    return CheckPointDerivedViews(
        by_uid=by_uid, by_name=by_name, group_memberships=memberships,
        package_layers=package_layers, inline_layers=inline_layers,
        unresolved_references=unresolved,
        collection_incomplete=tuple(item for item in config.collection if not item.complete),
    )


__all__ = ["CheckPointDerivedViews", "build_checkpoint_derived_views"]
