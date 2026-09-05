"""Hierarchy-aware, source-preserving Junos configuration-group resolution."""

from __future__ import annotations

from collections import defaultdict
from typing import List

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.juniper_srx.tokenizer import (
    JunosCommand, JunosOperation, extract_value_list,
)


def _inactive_paths(commands: List[JunosCommand]) -> list[tuple[str, ...]]:
    return [tuple(t.lower() for t in c.tokens[1:]) for c in commands
            if c.operation == JunosOperation.DEACTIVATE]


def _inactive(path: tuple[str, ...], paths: list[tuple[str, ...]]) -> bool:
    return any(path[:len(parent)] == parent for parent in paths)


def _context_prefix(path: tuple[str, ...]) -> tuple[str, ...]:
    return path[:2] if len(path) >= 2 and path[0].lower() in {"logical-systems", "tenants"} else ()


def _expand(path: list[str], target_commands: List[JunosCommand], target: tuple[str, ...]) -> list[list[str]]:
    """Expand <*> only from concrete target configuration paths."""
    if "<*>" not in path:
        return [path]
    index = path.index("<*>")
    prefix = tuple(target) + tuple(path[:index])
    value_index = 1 + len(prefix)
    values = {c.tokens[value_index] for c in target_commands
              if len(c.tokens) > value_index and tuple(c.tokens[1:value_index]) == prefix}
    return [path[:index] + [value] + path[index + 1:] for value in sorted(values)]


def resolve_group_commands(commands: List[JunosCommand]) -> List[JunosCommand]:
    groups: dict[tuple[tuple[str, ...], str], list[tuple[list[str], JunosCommand]]] = defaultdict(list)
    applications: list[tuple[tuple[str, ...], list[str], JunosCommand]] = []
    exclusions: dict[tuple[str, ...], set[str]] = defaultdict(set)
    inactive_paths = _inactive_paths(commands)

    for command in commands:
        if command.operation != JunosOperation.SET:
            continue
        tokens = command.tokens[1:]
        group_index = next((i for i, t in enumerate(tokens) if t.lower() == "groups"), None)
        if group_index is not None and len(tokens) > group_index + 2:
            scope = tuple(tokens[:group_index])
            path = tokens[group_index + 2:]
            if not _inactive(tuple(t.lower() for t in tokens), inactive_paths):
                groups[(scope, tokens[group_index + 1].lower())].append((path, command))
            command.consumed = True
            command.handler = "groups"
            command.extraction_status = ExtractionStatus.EXTRACT_ONLY

        for marker_name in ("apply-groups", "apply-groups-except"):
            marker = next((i for i, t in enumerate(tokens) if t.lower() == marker_name), None)
            if marker is None:
                continue
            target = tuple(tokens[:marker])
            names = extract_value_list(tokens[marker + 1:])
            if marker_name == "apply-groups":
                applications.append((target, names, command))
            else:
                exclusions[target].update(n.lower() for n in names)
            command.consumed = True
            command.handler = "groups"
            command.extraction_status = ExtractionStatus.EXTRACT_ONLY

    inherited: list[JunosCommand] = []
    emitted: set[tuple[str, ...]] = set()
    for target, names, application in applications:
        if any(_inactive(tuple(t.lower() for t in target + ("apply-groups", name)), inactive_paths) for name in names):
            continue
        context = _context_prefix(target)
        # Emit low priority values first; later handlers then overwrite them.
        for depth in range(0, len(target) + 1):
            apply_at = target[:depth]
            for name in reversed(names):  # first Junos group wins conflicts.
                if name.lower() in exclusions.get(apply_at, set()) or name.lower() in exclusions.get(target, set()):
                    continue
                candidates = [(apply_at, path, source) for path, source in groups.get((apply_at, name.lower()), [])]
                if (not apply_at) or context:
                    candidates += [((), path, source) for path, source in groups.get(((), name.lower()), [])]
                for scope, path, source in candidates:
                    group_context = _context_prefix(scope or tuple(path))
                    if group_context != context and (group_context or context):
                        continue
                    if scope and tuple(path[:len(scope)]) == scope:
                        path = path[len(scope):]
                    elif not scope and group_context:
                        path = path[2:]
                    base = target if apply_at == target else apply_at
                    for expanded in _expand(path, commands, base):
                        rendered = base + tuple(expanded)
                        if any(name.lower() in blocked for excluded, blocked in exclusions.items()
                               if rendered[:len(excluded)] == excluded):
                            continue
                        if rendered in emitted:
                            continue
                        emitted.add(rendered)
                        inherited.append(JunosCommand(
                            operation=JunosOperation.SET,
                            tokens=["set", *rendered],
                            raw_sanitized="set " + " ".join(rendered),
                            line_number=source.line_number,
                            source_group=name,
                            source_group_path=tuple(path),
                            synthetic=True,
                        ))
    return inherited + commands
