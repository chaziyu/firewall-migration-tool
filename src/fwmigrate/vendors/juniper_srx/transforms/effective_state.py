"""Read-only effective-state classification for explicit Junos source paths."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any


def effective_path_state(view: dict[str, Any], context: str, path: Sequence[str]) -> str | None:
    """Return derived EFFECTIVE/INACTIVE state without changing source objects."""
    target = tuple(str(part).casefold() for part in path)
    inactive = tuple(
        tuple(str(part).casefold() for part in item.get("path") or ())
        for item in view.get("inactive_hierarchies", ())
        if item.get("context", "root") == context
    )
    if any(len(target) >= len(parent) and target[:len(parent)] == parent for parent in inactive):
        return "INACTIVE"

    for item in view.get("effective_statements", ()):
        if item.get("context", "root") != context or item.get("status") != "EFFECTIVE":
            continue
        statement = tuple(str(part).casefold() for part in item.get("target_path") or ())
        if len(statement) >= len(target) and statement[:len(target)] == target:
            return "EFFECTIVE"
    return None
