"""Hierarchy-aware, source-preserving Junos configuration-group resolution."""

from __future__ import annotations

from collections import defaultdict
from typing import List

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.juniper_srx.tokenizer import (
    JunosCommand, JunosOperation, extract_value_list,
)

MAX_GROUP_RECURSION_DEPTH = 64


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
    nested: dict[tuple[tuple[str, ...], str], list[tuple[str, bool, JunosCommand]]] = defaultdict(list)
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
            group_name = tokens[group_index + 1]
            path = tokens[group_index + 2:]
            owner = (scope, group_name.lower())
            if not _inactive(tuple(t.lower() for t in tokens), inactive_paths):
                if path and path[0].lower() in {"apply-groups", "apply-groups-except"}:
                    for name in extract_value_list(path[1:]):
                        nested[owner].append((name, path[0].lower() == "apply-groups-except", command))
                else:
                    groups[owner].append((path, command))
            command.consumed = True
            command.handler = "groups"
            command.extraction_status = ExtractionStatus.EXTRACT_ONLY
            # This marker belongs to the group definition, not to a target.
            if group_index is not None:
                continue

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

    def emit_group(name: str, apply_at: tuple[str, ...], target: tuple[str, ...],
                   chain: tuple[str, ...], priority: int, stack: tuple[str, ...],
                   blocked: set[str], application: JunosCommand) -> None:
        lower_name = name.lower()
        if lower_name in stack:
            application.group_resolution = "GROUP_CYCLE"
            application.requires_manual_review = True
            return
        if len(stack) >= MAX_GROUP_RECURSION_DEPTH:
            application.group_resolution = "GROUP_RECURSION_PARTIAL"
            application.requires_manual_review = True
            return
        owner_candidates = [(apply_at, lower_name)]
        if not apply_at or _context_prefix(target):
            owner_candidates.append(((), lower_name))
        definitions = []
        nested_refs = []
        for owner in owner_candidates:
            definitions.extend(groups.get(owner, []))
            nested_refs.extend(nested.get(owner, []))
        # Deeper groups are emitted first; local statements of this group win.
        for nested_name, excluded, source in reversed(nested_refs):
            if excluded:
                blocked = blocked | {nested_name.lower()}
                continue
            emit_group(nested_name, apply_at, target, chain + (name,), priority + 1,
                       stack + (lower_name,), blocked, source)
        for path, source in definitions:
            # A group may be declared with an explicit logical-system prefix;
            # retain it as a compatibility check, then render relative to the target.
            source_scope = tuple(path[:2]) if _context_prefix(tuple(path)) else ()
            if source_scope and source_scope != _context_prefix(target):
                continue
            if not source_scope and _context_prefix(target):
                continue
            if source_scope:
                path = path[2:]
            for expanded in _expand(path, commands, apply_at):
                rendered = apply_at + tuple(expanded)
                if any(rendered[:len(prefix)] == prefix and lower_name in names
                       for prefix, names in exclusions.items()) or lower_name in blocked:
                    application.group_resolution = "GROUP_EXCLUDED"
                    application.requires_manual_review = True
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
                    source_group_chain=[*chain, name],
                    target_path=rendered,
                    group_recursion_depth=len(chain),
                    synthetic=True,
                ))
        if not definitions and not nested_refs:
            application.group_resolution = "GROUP_NOT_FOUND"
            application.requires_manual_review = True

    for target, names, application in applications:
        context = _context_prefix(target)
        if any(_inactive(tuple(t.lower() for t in target + ("apply-groups", name)), inactive_paths)
               for name in names):
            continue
        for depth in range(0, len(target) + 1):
            apply_at = target[:depth]
            for priority, name in reversed(list(enumerate(names))):
                if name.lower() in exclusions.get(apply_at, set()) or name.lower() in exclusions.get(target, set()):
                    continue
                emit_group(name, apply_at, target, (), priority, (), set(), application)

    return inherited + commands
