"""Final FortiGate dependency-resolution safety corrections.

This extension composes with the existing dependency wrappers. It fixes two
fail-closed issues without bypassing prior FortiGate relationship extensions:

- values previously treated as global built-ins are resolved against an exact
  same-context allowed target first;
- multiple distinct same-type targets in the same context are reported as
  unresolved ambiguity instead of selecting the first source object.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Tuple

from fwmigrate.extraction.models import DependencyRecord, SourceInventoryItem


# FortiOS selector keywords are field-specific. Keep this list intentionally
# narrow and only cover source relationships where the keyword is a documented
# selector/default in the supported FortiGate configuration model.
BUILTIN_REFERENCE_RULES: Dict[Tuple[str, str], set[str]] = {
    ("firewall policy", "srcintf"): {"any"},
    ("firewall policy", "dstintf"): {"any"},
    ("firewall policy", "srcaddr"): {"all"},
    ("firewall policy", "dstaddr"): {"all"},
    ("firewall policy", "srcaddr6"): {"all"},
    ("firewall policy", "dstaddr6"): {"all"},
    ("firewall policy", "service"): {"all", "none"},
    ("firewall policy", "schedule"): {"always"},
    ("firewall security-policy", "srcintf"): {"any"},
    ("firewall security-policy", "dstintf"): {"any"},
    ("firewall security-policy", "srcaddr"): {"all"},
    ("firewall security-policy", "dstaddr"): {"all"},
    ("firewall security-policy", "srcaddr6"): {"all"},
    ("firewall security-policy", "dstaddr6"): {"all"},
    ("firewall security-policy", "service"): {"all", "none"},
    ("firewall security-policy", "schedule"): {"always"},
    ("firewall local-in-policy", "intf"): {"any"},
    ("firewall local-in-policy", "srcaddr"): {"all"},
    ("firewall local-in-policy", "dstaddr"): {"all"},
    ("firewall local-in-policy", "service"): {"all", "none"},
    ("firewall local-in-policy", "schedule"): {"always"},
    ("firewall local-in-policy6", "intf"): {"any"},
    ("firewall local-in-policy6", "srcaddr"): {"all"},
    ("firewall local-in-policy6", "dstaddr"): {"all"},
    ("firewall local-in-policy6", "service"): {"all", "none"},
    ("firewall local-in-policy6", "schedule"): {"always"},
    ("firewall dos-policy", "interface"): {"any"},
    ("firewall dos-policy", "srcaddr"): {"all"},
    ("firewall dos-policy", "dstaddr"): {"all"},
    ("firewall dos-policy", "service"): {"all", "none"},
    ("firewall dos-policy6", "interface"): {"any"},
    ("firewall dos-policy6", "srcaddr"): {"all"},
    ("firewall dos-policy6", "dstaddr"): {"all"},
    ("firewall dos-policy6", "service"): {"all", "none"},
    ("firewall multicast-policy", "srcintf"): {"any"},
    ("firewall multicast-policy", "dstintf"): {"any"},
    ("firewall multicast-policy", "srcaddr"): {"all"},
    ("firewall multicast-policy6", "srcintf"): {"any"},
    ("firewall multicast-policy6", "dstintf"): {"any"},
    ("firewall multicast-policy6", "srcaddr"): {"all"},
    ("router policy", "srcaddr"): {"all"},
    ("router policy", "dstaddr"): {"all"},
    ("router policy6", "srcaddr"): {"all"},
    ("router policy6", "dstaddr"): {"all"},
    ("firewall vip", "extintf"): {"any"},
    ("firewall vip", "service"): {"all", "none"},
    ("vpn ssl settings", "source-interface"): {"any"},
    ("vpn ssl settings", "source-address"): {"all"},
    ("vpn ssl settings", "source-address6"): {"all"},
}

_REDACTED_REFERENCES = {"[REDACTED]", "<redacted>"}


def _source_key(item: SourceInventoryItem, dependencies_module: Any) -> tuple[str, str, str]:
    return (
        item.source_context or "root",
        dependencies_module._norm(item.source_path),
        str(item.name or item.source_id or ""),
    )


def _record_key(record: DependencyRecord, dependencies_module: Any) -> tuple[str, str, str, str, str]:
    return (
        record.source_context or "root",
        dependencies_module._norm(record.source_path),
        str(record.source_object or ""),
        dependencies_module._norm(record.source_field),
        record.reference,
    )


def _is_rule_specific_builtin(
    source_path: str,
    field: str,
    reference: str,
    dependencies_module: Any,
) -> bool:
    allowed = BUILTIN_REFERENCE_RULES.get(
        (
            dependencies_module._norm(source_path),
            dependencies_module._norm(field),
        ),
        set(),
    )
    return dependencies_module._norm(reference) in allowed


def _build_index(
    items: Iterable[SourceInventoryItem],
) -> Dict[Tuple[str, str], List[SourceInventoryItem]]:
    index: Dict[Tuple[str, str], List[SourceInventoryItem]] = {}
    for item in items:
        source_context = item.source_context or "root"
        names = dict.fromkeys(
            str(name)
            for name in (item.name, item.source_id)
            if name is not None and str(name)
        )
        for name in names:
            index.setdefault((source_context, name), []).append(item)
    return index


def _matching_candidates(
    index: Dict[Tuple[str, str], List[SourceInventoryItem]],
    *,
    source_context: str,
    reference: str,
    allowed_sections: set[str],
    dependencies_module: Any,
) -> List[SourceInventoryItem]:
    matches: List[SourceInventoryItem] = []
    for candidate in index.get((source_context, reference), []):
        if not dependencies_module._allowed_section_matches(
            candidate.source_path,
            allowed_sections,
        ):
            continue
        # Existing FortiGate extension composition can surface the same logical
        # inventory object more than once. Equivalent records are one target.
        if any(candidate == existing for existing in matches):
            continue
        matches.append(candidate)
    return matches


def _ambiguous_candidates(
    candidates: List[SourceInventoryItem],
    dependencies_module: Any,
) -> List[SourceInventoryItem]:
    """Return candidates only when one source family has multiple targets."""
    by_section: Dict[str, List[SourceInventoryItem]] = {}
    for candidate in candidates:
        section = dependencies_module._norm(candidate.source_path)
        by_section.setdefault(section, []).append(candidate)
    ambiguous: List[SourceInventoryItem] = []
    for section_candidates in by_section.values():
        if len(section_candidates) > 1:
            ambiguous.extend(section_candidates)
    return ambiguous


def _ambiguity_note(
    candidates: List[SourceInventoryItem],
    dependencies_module: Any,
) -> str:
    sections = sorted(
        {dependencies_module._norm(candidate.source_path) for candidate in candidates}
    )
    return (
        "Reference is ambiguous in the same VDOM/context; "
        f"{len(candidates)} valid targets match: {', '.join(sections)}."
    )


def _replace_ambiguous_records(
    records: List[DependencyRecord],
    *,
    index: Dict[Tuple[str, str], List[SourceInventoryItem]],
    dependencies_module: Any,
) -> List[DependencyRecord]:
    result: List[DependencyRecord] = []
    for record in records:
        source_path = dependencies_module._norm(record.source_path)
        field = dependencies_module._norm(record.source_field)
        expected = dependencies_module.REFERENCE_RULES.get((source_path, field))
        if expected is None:
            result.append(record)
            continue

        allowed_sections = dependencies_module._allowed_target_sections(
            source_path,
            field,
            expected,
        )
        candidates = _matching_candidates(
            index,
            source_context=record.source_context or "root",
            reference=record.reference,
            allowed_sections=allowed_sections,
            dependencies_module=dependencies_module,
        )
        ambiguous = _ambiguous_candidates(candidates, dependencies_module)
        if not ambiguous:
            result.append(record)
            continue

        result.append(
            record.model_copy(
                update={
                    "result": "UNRESOLVED",
                    "target_path": None,
                    "target_uid": None,
                    "target_name": None,
                    "notes": _ambiguity_note(ambiguous, dependencies_module),
                    "reason": "ambiguous-reference",
                }
            )
        )
    return result


def _missing_filtered_reference_records(
    items: List[SourceInventoryItem],
    existing_records: List[DependencyRecord],
    *,
    index: Dict[Tuple[str, str], List[SourceInventoryItem]],
    dependencies_module: Any,
) -> List[DependencyRecord]:
    existing_keys = {
        _record_key(record, dependencies_module)
        for record in existing_records
    }
    additions: List[DependencyRecord] = []

    for item in items:
        source_context, source_path, source_object = _source_key(
            item,
            dependencies_module,
        )
        for command in item.commands:
            field = dependencies_module._norm(command.key)
            expected = dependencies_module.REFERENCE_RULES.get((source_path, field))
            if expected is None or not dependencies_module._reference_is_active(item, field):
                continue

            allowed_sections = dependencies_module._allowed_target_sections(
                source_path,
                field,
                expected,
            )
            for reference in command.values:
                if not reference or reference in _REDACTED_REFERENCES:
                    continue
                if reference.lower() not in dependencies_module.BUILTIN_REFERENCES:
                    continue

                key = (
                    source_context,
                    source_path,
                    source_object,
                    field,
                    reference,
                )
                if key in existing_keys:
                    continue

                self_reference = (
                    source_path == "system interface"
                    and field == "member"
                    and item.name == reference
                )
                candidates = _matching_candidates(
                    index,
                    source_context=source_context,
                    reference=reference,
                    allowed_sections=allowed_sections,
                    dependencies_module=dependencies_module,
                )
                ambiguous = _ambiguous_candidates(candidates, dependencies_module)

                if self_reference:
                    record = DependencyRecord(
                        source_context=source_context,
                        source_path=source_path,
                        source_object=item.name or item.source_id,
                        source_field=command.key,
                        reference=reference,
                        expected_type=expected,
                        result="UNRESOLVED",
                        target_path=None,
                        notes="Interface member cannot reference its own interface.",
                    )
                elif ambiguous:
                    record = DependencyRecord(
                        source_context=source_context,
                        source_path=source_path,
                        source_object=item.name or item.source_id,
                        source_field=command.key,
                        reference=reference,
                        expected_type=expected,
                        result="UNRESOLVED",
                        target_path=None,
                        notes=_ambiguity_note(ambiguous, dependencies_module),
                        reason="ambiguous-reference",
                    )
                elif candidates:
                    record = DependencyRecord(
                        source_context=source_context,
                        source_path=source_path,
                        source_object=item.name or item.source_id,
                        source_field=command.key,
                        reference=reference,
                        expected_type=expected,
                        result="RESOLVED",
                        target_path=dependencies_module._norm(
                            candidates[0].source_path
                        ),
                        notes=None,
                    )
                elif _is_rule_specific_builtin(
                    source_path,
                    field,
                    reference,
                    dependencies_module,
                ):
                    continue
                else:
                    resolution_mode = dependencies_module._reference_resolution_mode(
                        source_path,
                        field,
                    )
                    result = (
                        "EXTERNAL"
                        if resolution_mode in {"external", "local-or-external"}
                        else "UNRESOLVED"
                    )
                    record = DependencyRecord(
                        source_context=source_context,
                        source_path=source_path,
                        source_object=item.name or item.source_id,
                        source_field=command.key,
                        reference=reference,
                        expected_type=expected,
                        result=result,
                        target_path=None,
                        notes=(
                            dependencies_module.EXTERNAL_REFERENCE_NOTE
                            if result == "EXTERNAL"
                            else "Reference was not found in the same VDOM/context."
                        ),
                    )

                additions.append(record)
                existing_keys.add(key)

    return additions


def install_dependency_resolution_safety_fix(
    dependencies_module: Any,
    extractor_module: Any,
) -> None:
    """Install the final local-first and ambiguity-safe dependency resolver."""

    current = dependencies_module.build_dependency_registry
    if getattr(current, "_dependency_resolution_safety_fixed", False):
        return

    original_build_dependency_registry = current

    def build_dependency_registry(
        items: Iterable[SourceInventoryItem],
    ) -> List[DependencyRecord]:
        materialized = list(items)
        records = list(original_build_dependency_registry(materialized))
        all_items = dependencies_module._flatten(materialized)
        index = _build_index(all_items)

        records = _replace_ambiguous_records(
            records,
            index=index,
            dependencies_module=dependencies_module,
        )
        records.extend(
            _missing_filtered_reference_records(
                all_items,
                records,
                index=index,
                dependencies_module=dependencies_module,
            )
        )
        return records

    build_dependency_registry._dependency_resolution_safety_fixed = True
    dependencies_module.build_dependency_registry = build_dependency_registry
    extractor_module.build_dependency_registry = build_dependency_registry
