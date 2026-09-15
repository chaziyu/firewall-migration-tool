"""Post-extraction fidelity repair for Check Point exclusion groups."""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, Iterable, List, Optional, Tuple

from fwmigrate.extraction.models import ExtractionResult, ExtractionStatus, SourceInventoryItem


_UNRESOLVED_INCLUDE_KEY = "checkpoint-unresolved-include-references"
_UNRESOLVED_EXCLUDE_KEY = "checkpoint-unresolved-exclude-references"
_PRESERVED_NOTE = "group-with-exclusion-semantics-preserved-in-ir"
_LEGACY_NOTE = "Exclusion groups (include/except) cannot be expressed directly in canonical IR"


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    return list(value) if isinstance(value, list) else [value]


def _ref_key(value: Any) -> Optional[str]:
    if isinstance(value, dict):
        value = value.get("uid") or value.get("name")
    if value in (None, ""):
        return None
    return str(value)


def _dedupe(values: Iterable[str]) -> List[str]:
    return list(dict.fromkeys(value for value in values if value))


def _canonical_names_by_source_uid(result: ExtractionResult) -> Dict[str, List[str]]:
    names: Dict[str, List[str]] = defaultdict(list)
    for address in result.canonical_ir.addresses:
        if address.source_uuid:
            names[str(address.source_uuid)].append(address.name)
    for group in result.canonical_ir.address_groups:
        if group.source_uuid:
            names[str(group.source_uuid)].append(group.name)
    return {key: _dedupe(value) for key, value in names.items()}


def _inventory_indexes(
    result: ExtractionResult,
) -> Tuple[Dict[Tuple[str, str], SourceInventoryItem], Dict[Tuple[str, str], SourceInventoryItem]]:
    by_uid: Dict[Tuple[str, str], SourceInventoryItem] = {}
    by_name: Dict[Tuple[str, str], SourceInventoryItem] = {}
    for item in result.inventory_items:
        domain = item.domain or "global"
        if item.source_id:
            by_uid[(domain, str(item.source_id))] = item
        if item.name:
            by_name[(domain, str(item.name))] = item
    return by_uid, by_name


def _resolve_ref(
    ref: Any,
    domain: str,
    by_uid: Dict[Tuple[str, str], SourceInventoryItem],
    by_name: Dict[Tuple[str, str], SourceInventoryItem],
    canonical_by_uid: Dict[str, List[str]],
) -> Tuple[List[str], Optional[str]]:
    key = _ref_key(ref)
    if not key:
        return [], None
    item = by_uid.get((domain, key)) or by_name.get((domain, key))
    if item is None:
        return [], key
    if item.source_id:
        canonical = canonical_by_uid.get(str(item.source_id), [])
        if canonical:
            return list(canonical), None
    if item.name and item.status in {
        ExtractionStatus.NORMALIZED,
        ExtractionStatus.PARTIALLY_NORMALIZED,
    }:
        return [str(item.name)], None
    return [], key


def _resolved_refs(
    refs: Iterable[Any],
    domain: str,
    by_uid: Dict[Tuple[str, str], SourceInventoryItem],
    by_name: Dict[Tuple[str, str], SourceInventoryItem],
    canonical_by_uid: Dict[str, List[str]],
) -> Tuple[List[str], List[str]]:
    resolved: List[str] = []
    unresolved: List[str] = []
    for ref in refs:
        names, missing = _resolve_ref(ref, domain, by_uid, by_name, canonical_by_uid)
        resolved.extend(names)
        if missing:
            unresolved.append(missing)
    return _dedupe(resolved), _dedupe(unresolved)


def apply_checkpoint_group_fidelity(result: ExtractionResult) -> ExtractionResult:
    """Keep exclusion groups non-lossy without treating unresolved refs as canonical names."""
    canonical_by_uid = _canonical_names_by_source_uid(result)
    by_uid, by_name = _inventory_indexes(result)
    groups_by_uid = {
        str(group.source_uuid): group
        for group in result.canonical_ir.address_groups
        if group.source_uuid
    }
    groups_by_name = {group.name: group for group in result.canonical_ir.address_groups}

    for item in result.inventory_items:
        if item.source_type != "group-with-exclusion":
            continue
        group = (
            groups_by_uid.get(str(item.source_id)) if item.source_id else None
        ) or (groups_by_name.get(item.name or "") if item.name else None)
        if group is None:
            continue

        attributes = item.source_attributes
        include_value = attributes.get("include")
        if include_value is None:
            include_value = attributes.get("members", [])
        exclude_value = attributes.get("except")
        if exclude_value is None:
            exclude_value = attributes.get("exclude")
        if exclude_value is None:
            exclude_value = attributes.get("except-members", [])

        include_names, unresolved_include = _resolved_refs(
            _as_list(include_value), item.domain or "global",
            by_uid, by_name, canonical_by_uid,
        )
        exclude_names, unresolved_exclude = _resolved_refs(
            _as_list(exclude_value), item.domain or "global",
            by_uid, by_name, canonical_by_uid,
        )

        group.members = include_names
        group.exclusion_enabled = True
        group.exclude_members = exclude_names
        group.migration_status = ExtractionStatus.PARTIALLY_NORMALIZED.value
        group.requires_manual_review = True
        group.audit_note = "Check Point include/exclude semantics preserved; target portability requires review."
        group.source_attributes[_UNRESOLVED_INCLUDE_KEY] = unresolved_include
        group.source_attributes[_UNRESOLVED_EXCLUDE_KEY] = unresolved_exclude

        item.status = ExtractionStatus.PARTIALLY_NORMALIZED
        item.requires_manual_review = True
        item.source_attributes[_UNRESOLVED_INCLUDE_KEY] = unresolved_include
        item.source_attributes[_UNRESOLVED_EXCLUDE_KEY] = unresolved_exclude
        item.notes = [note for note in item.notes if note != _LEGACY_NOTE]
        if _PRESERVED_NOTE not in item.notes:
            item.notes.append(_PRESERVED_NOTE)
        for ref in unresolved_include:
            note = f"unresolved-group-with-exclusion-include:{ref}"
            if note not in item.notes:
                item.notes.append(note)
        for ref in unresolved_exclude:
            note = f"unresolved-group-with-exclusion-exclude:{ref}"
            if note not in item.notes:
                item.notes.append(note)

        if unresolved_include or unresolved_exclude:
            result.requires_manual_review = True
            result.generation_safe = False
            reason = "checkpoint-group-with-exclusion-unresolved-reference"
            if reason not in result.blocking_reasons:
                result.blocking_reasons.append(reason)

        for unsupported in result.unsupported_items:
            if unsupported.source_name == item.name and "group-with-exclusion" in unsupported.reason:
                unsupported.reason = (
                    "Check Point group-with-exclusion semantics are preserved in canonical IR; "
                    "target portability requires review"
                )

    return result


__all__ = ["apply_checkpoint_group_fidelity"]
