from __future__ import annotations

from typing import Any

from ..model.common import CheckPointSourceObject
from ..model.source import CheckPointConfig


def _scope(item: CheckPointSourceObject) -> str | None:
    return item.domain_uid or item.domain or "global"


def _reference_key(value: Any) -> str | None:
    if isinstance(value, dict):
        return value.get("uid") or value.get("name")
    return getattr(value, "uid", None) or getattr(value, "name", None) or (str(value) if value else None)


def build_reference_views(config: CheckPointConfig) -> tuple[dict[str, CheckPointSourceObject], dict[tuple[str | None, str], tuple[CheckPointSourceObject, ...]], dict[str, tuple[str, ...]], tuple[dict[str, Any], ...]]:
    records = [item for field in type(config).model_fields if field != "collection" for item in (getattr(config, field) or []) if isinstance(item, CheckPointSourceObject)]
    by_uid = {item.uid: item for item in records if item.uid}
    names: dict[tuple[str | None, str], list[CheckPointSourceObject]] = {}
    for item in records:
        if item.name:
            names.setdefault((_scope(item), item.name), []).append(item)
    memberships = {
        item.uid or f"{_scope(item)}:{item.name}": tuple(
            str(_reference_key(member))
            for member in getattr(item, "members", ())
        )
        for item in config.groups
        if hasattr(item, "members")
    }
    unresolved = []
    for item in config.access_rules + config.nat_rules:
        for reference in _rule_references(item):
            for value in (reference if isinstance(reference, list) else [reference]):
                key = _reference_key(value)
                if key in (None, "", "any", "Any", "Original"):
                    continue
                if str(key) not in by_uid and (_scope(item), str(key)) not in names:
                    unresolved.append({"command": item.command, "uid": item.uid, "reference": str(key)})
    return by_uid, {key: tuple(value) for key, value in names.items()}, memberships, tuple(unresolved)


def _rule_references(item: CheckPointSourceObject) -> tuple[Any, ...]:
    fields = ("source", "destination", "service", "install_on", "time", "original_source", "original_destination", "original_service")
    return tuple(value for field in fields for value in (getattr(item, field, None) or ()))
