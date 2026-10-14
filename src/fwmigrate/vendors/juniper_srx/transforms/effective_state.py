"""Read-only effective-state classification for explicit Junos source paths."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from .effective_lookup import context_local_path


def effective_path_state(view: dict[str, Any], context: str, path: Sequence[str]) -> str | None:
    """Return derived EFFECTIVE/INACTIVE state without changing source objects."""
    target = context_local_path(context, path)
    if not target:
        return None
    inactive = tuple(
        context_local_path(context, item.get("path") or ())
        for item in view.get("inactive_hierarchies", ())
        if item.get("context", "root").lower() == context.lower()
    )
    if any(parent is not None and len(target) >= len(parent) and target[:len(parent)] == parent for parent in inactive):
        return "INACTIVE"

    for item in view.get("effective_statements", ()):
        if item.get("context", "root").lower() != context.lower() or item.get("status") != "EFFECTIVE":
            continue
        statement = context_local_path(context, item.get("target_path") or ())
        if statement and len(statement) >= len(target) and statement[:len(target)] == target:
            return "EFFECTIVE"
    return None
