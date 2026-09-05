"""Hierarchy-aware, source-preserving Junos configuration-group resolution."""

from __future__ import annotations

from collections import defaultdict
from typing import List

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.juniper_srx.tokenizer import (
    JunosCommand, JunosOperation, extract_value_list,
)

MAX_GROUP_RECURSION_DEPTH = 64
_APPLY = {"apply-groups", "apply-groups-except"}


def _inactive_paths(commands: List[JunosCommand]) -> list[tuple[str, ...]]:
    return [tuple(t.lower() for t in c.tokens[1:]) for c in commands
            if c.operation == JunosOperation.DEACTIVATE]


def _inactive(path: tuple[str, ...], paths: list[tuple[str, ...]]) -> bool:
    return any(path[:len(parent)] == parent for parent in paths)


def _context_prefix(path: tuple[str, ...]) -> tuple[str, ...]:
    return path[:2] if len(path) >= 2 and path[0].lower() in {"logical-systems", "tenants"} else ()


def _render(path: tuple[str, ...], base: tuple[str, ...], target: tuple[str, ...],
            commands: List[JunosCommand]) -> list[tuple[str, ...]]:
    """Render one relative path, expanding wildcards only to real targets."""
    values = [list(base)]
    for offset, component in enumerate(path):
        absolute = len(base) + offset
        if component == "<*>" and absolute >= len(target):
            prefix = tuple(base) + tuple(path[:offset])
            candidates = sorted({c.tokens[absolute + 1] for c in commands
                                 if len(c.tokens) > absolute + 1
                                 and tuple(c.tokens[1:absolute + 1]) == prefix})
            if not candidates:
                return []
        elif component == "<*>":
            if absolute >= len(target):
                return []
            candidates = [target[absolute]]
        else:
            candidates = [component]
        values = [current + [value] for current in values for value in candidates]
    return [tuple(value) for value in values]


def _group_key(scope: tuple[str, ...], name: str) -> tuple[tuple[str, ...], str]:
    return scope, name.lower()


def resolve_group_commands(commands: List[JunosCommand]) -> List[JunosCommand]:
    groups: dict[tuple[tuple[str, ...], str], list[tuple[tuple[str, ...], JunosCommand]]] = defaultdict(list)
    nested: dict[tuple[tuple[str, ...], str], list[tuple[tuple[str, ...], str, bool, JunosCommand]]] = defaultdict(list)
    applications: list[tuple[tuple[str, ...], list[str], list[str], JunosCommand]] = []
    inactive_paths = _inactive_paths(commands)

    for command in commands:
        if command.operation != JunosOperation.SET:
            continue
        tokens = command.tokens[1:]
        group_index = next((i for i, t in enumerate(tokens) if t.lower() == "groups"), None)
        if group_index is not None and len(tokens) > group_index + 2:
            scope = tuple(tokens[:group_index])
            group_name = tokens[group_index + 1]
            path = tuple(tokens[group_index + 2:])
            owner = _group_key(scope, group_name)
            if not _inactive(tuple(t.lower() for t in tokens), inactive_paths):
                marker = next((i for i, t in enumerate(path) if t.lower() in _APPLY), None)
                if marker is None:
                    groups[owner].append((path, command))
                else:
                    excluded = path[marker].lower() == "apply-groups-except"
                    for ref in extract_value_list(path[marker + 1:]):
                        nested[owner].append((path[:marker], ref, excluded, command))
            command.consumed = True
            command.handler = "groups"
            command.extraction_status = ExtractionStatus.EXTRACT_ONLY
            continue

        marker = next((i for i, t in enumerate(tokens) if t.lower() in _APPLY), None)
        if marker is None:
            continue
        target = tuple(tokens[:marker])
        refs = extract_value_list(tokens[marker + 1:])
        if tokens[marker].lower() == "apply-groups":
            applications.append((target, refs, [], command))
        else:
            applications.append((target, [], refs, command))
        command.consumed = True
        command.handler = "groups"
        command.extraction_status = ExtractionStatus.EXTRACT_ONLY

    inherited: list[JunosCommand] = []
    emitted: set[tuple[str, ...]] = set()

    def emit_group(name: str, apply_at: tuple[str, ...], target: tuple[str, ...],
                   chain: tuple[str, ...], stack: tuple[str, ...],
                   application: JunosCommand) -> None:
        lower_name = name.lower()
        if lower_name in stack:
            application.group_resolution = "GROUP_CYCLE"
            application.requires_manual_review = True
            return
        if len(stack) >= MAX_GROUP_RECURSION_DEPTH:
            application.group_resolution = "GROUP_RECURSION_DEPTH_EXCEEDED"
            application.requires_manual_review = True
            return

        target_scope = _context_prefix(target)
        owner_candidates = [_group_key(target_scope, lower_name), _group_key((), lower_name)]
        definitions = [item for owner in owner_candidates for item in groups.get(owner, [])]
        nested_refs = [item for owner in owner_candidates for item in nested.get(owner, [])]
        if not definitions and not nested_refs:
            application.group_resolution = "GROUP_NOT_FOUND"
            application.requires_manual_review = True
            return

        # Actual nested applications create a new point; no fabricated prefixes.
        for node_path, nested_name, excluded, source in sorted(nested_refs, key=lambda item: item[3].line_number):
            nested_points = _render(node_path, apply_at, target, commands)
            for nested_at in nested_points:
                if target and tuple(target[:len(nested_at)]) != nested_at:
                    continue
                if excluded:
                    application.group_resolution = "GROUP_EXCLUDED"
                    application.requires_manual_review = True
                    continue
                emit_group(nested_name, nested_at, target, chain + (name,), stack + (lower_name,), application)

        for path, source in sorted(definitions, key=lambda item: item[1].line_number):
            source_scope = _context_prefix(path)
            if source_scope:
                if source_scope != target_scope:
                    application.group_resolution = "GROUP_HIERARCHY_INCOMPATIBLE"
                    continue
                path = path[2:]
            elif target_scope:
                application.group_resolution = "GROUP_HIERARCHY_INCOMPATIBLE"
                continue
            relative_path = path
            if apply_at and tuple(path[:len(apply_at)]) == apply_at:
                relative_path = path[len(apply_at):]
            for rendered in _render(relative_path, apply_at, target, commands):
                if target and tuple(target[:len(rendered)]) != rendered[:len(target)]:
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
                source_group_path=path,
                    source_group_chain=[*chain, name],
                    target_path=rendered,
                    group_recursion_depth=len(chain),
                    synthetic=True,
                ))

    for target, names, excluded_names, application in sorted(applications, key=lambda item: item[3].line_number):
        blocked = {name.lower() for name in excluded_names}
        # Stronger application points are emitted first; list order is stable and first wins.
        # Handlers apply later commands over earlier ones: emit weaker list
        # entries first so Junos' first apply-groups entry wins.
        for name in reversed(names):
            if _inactive(tuple(t.lower() for t in target + ("apply-groups", name)), inactive_paths):
                application.group_resolution = "GROUP_INACTIVE"
                continue
            if name.lower() in blocked:
                application.group_resolution = "GROUP_EXCLUDED"
                continue
            emit_group(name, target, target, (), (), application)

    return inherited + commands
