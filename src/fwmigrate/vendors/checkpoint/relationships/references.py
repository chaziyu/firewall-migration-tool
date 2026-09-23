from __future__ import annotations

from typing import Any

from ..source_model import CheckPointConfig, CheckPointSourceRecord


def _scope(item: CheckPointSourceRecord) -> str | None:
    return item.domain_uid or item.domain or "global"


def build_reference_views(config: CheckPointConfig) -> tuple[dict[str, CheckPointSourceRecord], dict[tuple[str | None, str], tuple[CheckPointSourceRecord, ...]], dict[str, tuple[str, ...]], tuple[dict[str, Any], ...]]:
    records = [item for field in type(config).model_fields if field != "collection" for item in (getattr(config, field) or []) if isinstance(item, CheckPointSourceRecord)]
    by_uid = {item.uid: item for item in records if item.uid}
    names: dict[tuple[str | None, str], list[CheckPointSourceRecord]] = {}
    for item in records:
        if item.name:
            names.setdefault((_scope(item), item.name), []).append(item)
    memberships = {item.uid or f"{_scope(item)}:{item.name}": tuple(str(member.get("uid") or member.get("name") or member) if isinstance(member, dict) else str(member) for member in item.members) for item in config.groups}
    unresolved = []
    for item in config.access_rules + config.nat_rules:
        for reference in item.references:
            for value in (reference if isinstance(reference, list) else [reference]):
                key = value.get("uid") or value.get("name") if isinstance(value, dict) else value
                if key in (None, "", "any", "Any", "Original"):
                    continue
                if str(key) not in by_uid and (_scope(item), str(key)) not in names:
                    unresolved.append({"command": item.command, "uid": item.uid, "reference": str(key)})
    return by_uid, {key: tuple(value) for key, value in names.items()}, memberships, tuple(unresolved)
