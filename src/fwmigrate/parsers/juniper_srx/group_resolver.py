"""Hierarchy-aware, source-preserving Junos configuration-group resolution."""

from __future__ import annotations

from collections import defaultdict
from typing import List

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.juniper_srx.extraction import sanitize_tokens
from fwmigrate.parsers.juniper_srx.tokenizer import (
    JunosCommand, JunosOperation, extract_value_list,
)
from fwmigrate.parsers.juniper_srx.model import JuniperResolutionStatus
from fwmigrate.parsers.juniper_srx.provenance import build_candidate

MAX_GROUP_RECURSION_DEPTH = 64
_APPLY = {"apply-groups", "apply-groups-except"}
_DAYS_OF_WEEK = {"monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"}


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


def _build_precedence_key(command: JunosCommand) -> tuple[int, int, int, int, int, int]:
    """Return a weak-to-strong key for competing effective statements."""
    return (
        int(command.source_group is None),
        command.group_application_depth,
        -command.group_list_priority,
        int(command.source_group is not None and command.group_recursion_depth <= 1),
        -command.group_recursion_depth,
        command.source_order or command.line_number,
    )


def _candidate_field_value(path: tuple[str, ...]) -> tuple[str, object]:
    low = [part.lower() for part in path]
    if "security-zone" in low:
        if "interfaces" in low:
            i = low.index("interfaces")
            if i + 1 < len(path) and "host-inbound-traffic" not in low[i + 1:]:
                return "interfaces", path[i + 1]
            if "host-inbound-traffic" in low[i + 1:]:
                h = low.index("host-inbound-traffic", i + 1)
                interface = path[i + 1] if i + 1 < h and low[i + 1] != "host-inbound-traffic" else None
                kind = low[h + 1] if h + 1 < len(path) else ""
                field = f"interface:{interface}:{'system_services' if kind == 'system-services' else 'protocols'}" if interface else (
                    "host_inbound_system_services" if kind == "system-services" else "host_inbound_protocols"
                )
                return field, path[h + 2] if h + 2 < len(path) else None
        if "description" in low:
            i = low.index("description")
            return "description", " ".join(path[i + 1:])
        if "screen" in low:
            return "screen", path[low.index("screen") + 1]
        if "tcp-rst" in low:
            return "tcp_rst", True
    if low[:2] == ["schedulers", "scheduler"]:
        key = low[2] if len(low) > 2 else ""
        value = path[3] if len(path) > 3 else None
        if key in {"description", "start-date", "stop-date"}:
            return key.replace("-", "_"), value
        if key == "daily":
            return "daily", " ".join(path[3:])
        if key in _DAYS_OF_WEEK:
            return f"weekday:{key}", " ".join(path[3:])
    if low[:2] == ["security", "policies"]:
        if "scheduler-name" in low:
            i = low.index("scheduler-name")
            return "scheduler_name", path[i + 1]
        if "match" in low:
            i = low.index("match")
            key = low[i + 1] if i + 1 < len(low) else ""
            names = {"source-address": "source_addresses", "destination-address": "destination_addresses",
                     "application": "applications", "dynamic-application": "dynamic_applications",
                     "source-identity": "source_identities"}
            return names.get(key, key), path[i + 2] if i + 2 < len(path) else None
        if "then" in low:
            i = low.index("then")
            return "action", path[i + 1] if i + 1 < len(path) else None
    if low[:3] == ["security", "address-book", low[2] if len(low) > 2 else ""] and "address-set" in low:
        i = low.index("address-set")
        if i + 2 < len(path) and low[i + 2] in {"address", "address-set"}:
            return low[i + 2], path[i + 3] if i + 3 < len(path) else None
    if "routing-options" in low and "route" in low:
        key = low[-2] if len(low) > 1 else ""
        return {"next-hop": "next_hops", "qualified-next-hop": "next_hops"}.get(key, key.replace("-", "_")), path[-1] if path else None
    return (low[-2] if len(low) > 1 else low[-1] if low else "unknown"), path[-1] if path else None


def _record_non_effective_definition(application, name, path, source, status, reason, target,
                                     group_list_priority=0, group_application_depth=0):
    field, value = _candidate_field_value(path)
    candidate = build_candidate(value, field, source, status=status, effective=False, reason=reason)
    safe_path = tuple(sanitize_tokens(target))
    candidate.target_path = safe_path
    if candidate.provenance:
        candidate.provenance = candidate.provenance.__class__(
            **{**candidate.provenance.__dict__, "source_group_name": name,
               "source_group_chain": (name,), "source_path": tuple(sanitize_tokens(path)),
               "target_path": safe_path, "group_priority": group_list_priority,
               "group_list_priority": group_list_priority,
               "group_application_depth": group_application_depth,
               "hierarchy_depth": group_application_depth,
               "recursion_depth": 1, "group_recursion_depth": 1}
        )
        candidate.group_list_priority = group_list_priority
        candidate.group_application_depth = group_application_depth
        candidate.group_recursion_depth = 1
        candidate.hierarchy_depth = group_application_depth
    application.candidate_records.append(candidate.model_dump())


def resolve_group_commands(commands: List[JunosCommand]) -> List[JunosCommand]:
    groups: dict[tuple[tuple[str, ...], str], list[tuple[tuple[str, ...], JunosCommand]]] = defaultdict(list)
    inactive_groups: dict[tuple[tuple[str, ...], str], list[tuple[tuple[str, ...], JunosCommand]]] = defaultdict(list)
    nested: dict[tuple[tuple[str, ...], str], list[tuple[tuple[str, ...], str, bool, JunosCommand, int]]] = defaultdict(list)
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
            marker = next((i for i, t in enumerate(path) if t.lower() in _APPLY), None)
            if marker is None and _inactive(tuple(t.lower() for t in tokens), inactive_paths):
                inactive_groups[owner].append((path, command))
            elif marker is None:
                groups[owner].append((path, command))
            else:
                excluded = path[marker].lower() == "apply-groups-except"
                for list_priority, ref in enumerate(extract_value_list(path[marker + 1:])):
                    nested[owner].append((path[:marker], ref, excluded, command, list_priority))
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

    def emit_group(name: str, apply_at: tuple[str, ...], target: tuple[str, ...],
                   chain: tuple[str, ...], stack: tuple[str, ...],
                   application: JunosCommand, group_list_priority: int) -> None:
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
        owner_candidates = list(dict.fromkeys(
            (_group_key(target_scope, lower_name), _group_key((), lower_name))
        ))
        definitions = [item for owner in owner_candidates for item in groups.get(owner, [])]
        nested_refs = [item for owner in owner_candidates for item in nested.get(owner, [])]
        if not definitions and not nested_refs:
            application.group_resolution = "GROUP_NOT_FOUND"
            application.requires_manual_review = True
            return

        # Actual nested applications create a new point; no fabricated prefixes.
        for node_path, nested_name, excluded, source, nested_priority in sorted(
                nested_refs, key=lambda item: item[3].line_number):
            nested_points = _render(node_path, apply_at, target, commands)
            for nested_at in nested_points:
                if target and tuple(target[:len(nested_at)]) != nested_at:
                    continue
                if excluded:
                    application.group_resolution = "GROUP_EXCLUDED"
                    application.requires_manual_review = True
                    application.candidate_records.append(build_candidate(
                        nested_name, "group", source, status=JuniperResolutionStatus.EXCLUDED,
                        effective=False, reason="apply-groups-except").model_dump()
                    )
                    continue
                emit_group(nested_name, nested_at, target, chain + (name,), stack + (lower_name,),
                           application, nested_priority)

        for path, source in sorted(definitions, key=lambda item: item[1].line_number):
            source_scope = _context_prefix(path)
            if source_scope:
                if source_scope != target_scope:
                    application.group_resolution = "GROUP_HIERARCHY_INCOMPATIBLE"
                    application.candidate_records.append(build_candidate(
                        path, "group", source,
                        status=JuniperResolutionStatus.INCOMPATIBLE, effective=False,
                        reason="hierarchy incompatible").model_dump()
                    )
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
                inherited.append(JunosCommand(
                    operation=JunosOperation.SET,
                    tokens=["set", *rendered],
                    raw_sanitized="set " + " ".join(rendered),
                    line_number=source.line_number,
                    source_group=name,
                    source_group_path=path,
                    source_group_chain=[*chain, name],
                    target_path=rendered,
                    group_recursion_depth=len(chain) + 1,
                    group_priority=group_list_priority,
                    group_list_priority=group_list_priority,
                    group_application_depth=len(apply_at),
                    hierarchy_depth=len(apply_at),
                    source_order=source.line_number,
                    synthetic=True,
                ))

    for target, names, excluded_names, application in sorted(
            applications, key=lambda item: (len(item[0]), item[3].line_number)):
        application.target_path = target
        application.group_application_depth = len(target)
        application.hierarchy_depth = len(target)
        blocked = {name.lower() for name in excluded_names}
        for list_priority, name in enumerate(names):
            if _inactive(tuple(t.lower() for t in target + ("apply-groups", name)), inactive_paths):
                application.group_resolution = "GROUP_INACTIVE"
                application.candidate_records.append(build_candidate(
                    name, "group", application, status=JuniperResolutionStatus.INACTIVE,
                    effective=False, reason="inactive").model_dump()
                )
                continue
            if name.lower() in blocked:
                application.group_resolution = "GROUP_EXCLUDED"
                application.candidate_records.append(build_candidate(
                    name, "group", application, status=JuniperResolutionStatus.EXCLUDED,
                    effective=False, reason="apply-groups-except").model_dump()
                )
                continue
            emit_group(name, target, target, (), (), application, list_priority)

            owners = list(dict.fromkeys((_group_key(_context_prefix(target), name), _group_key((), name))))
            for owner in owners:
                for path, source in sorted(inactive_groups.get(owner, []), key=lambda item: item[1].line_number):
                    for rendered in _render(path, (), target, commands):
                        _record_non_effective_definition(
                            application, name, rendered, source,
                            JuniperResolutionStatus.INACTIVE, "inactive", rendered,
                            list_priority, len(target),
                        )

        for list_priority, name in enumerate(excluded_names):
            owners = list(dict.fromkeys((_group_key(_context_prefix(target), name), _group_key((), name))))
            for owner in owners:
                for path, source in sorted(groups.get(owner, []), key=lambda item: item[1].line_number):
                    rendered_paths = _render(path, (), target, commands)
                    for rendered in rendered_paths:
                        _record_non_effective_definition(
                            application, name, rendered, source,
                            JuniperResolutionStatus.EXCLUDED, "apply-groups-except", rendered,
                            list_priority, len(target),
                        )

    # Only competing paths need reordering; preserve the existing emission order
    # for unrelated paths while making each winner selection semantic.
    by_target: dict[tuple[str, ...], list[int]] = defaultdict(list)
    for index, command in enumerate(inherited):
        target_path = command.target_path or tuple(command.tokens[1:])
        by_target[target_path[:-1]].append(index)
    for indexes in by_target.values():
        ordered = sorted((inherited[index] for index in indexes), key=_build_precedence_key)
        for index, command in zip(indexes, ordered):
            inherited[index] = command

    return inherited + commands
