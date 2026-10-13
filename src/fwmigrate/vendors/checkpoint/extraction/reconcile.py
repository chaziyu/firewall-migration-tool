from __future__ import annotations

from typing import Any

from ..model.common import CheckPointSourceObject


_CONTEXT_FIELDS = {"source_plane", "command", "order", "explicit_fields", "raw_extra"}


def _domain(item: CheckPointSourceObject) -> str | None:
    return item.domain_uid or item.domain


def _preferred_rank(item: CheckPointSourceObject) -> int:
    command = (item.command or "").lower()
    if type(item).__name__ == "CPAccessLayer" and command == "show-access-layers":
        return 2
    if type(item).__name__ == "CPGateway" and command == "show-simple-gateways":
        return 2
    if type(item).__name__ == "CPCluster" and command == "show-simple-clusters":
        return 2
    return 1


def _explicit_field_names(item: CheckPointSourceObject) -> dict[str, str]:
    fields = type(item).model_fields
    names = {name.replace("-", "_"): name for name in fields}
    names.update({field.alias.replace("-", "_"): name for name, field in fields.items() if field.alias})
    return {raw.replace("-", "_"): names[raw.replace("-", "_")] for raw in item.explicit_fields
            if raw.replace("-", "_") in names}


def _merge(existing: CheckPointSourceObject, incoming: CheckPointSourceObject) -> CheckPointSourceObject | None:
    left_fields = _explicit_field_names(existing)
    right_fields = _explicit_field_names(incoming)
    left_extra, right_extra = existing.raw_extra, incoming.raw_extra

    for key in left_fields.keys() & right_fields.keys():
        name = left_fields[key]
        if name not in _CONTEXT_FIELDS and getattr(existing, name) != getattr(incoming, name):
            return None
    if any(left_extra[key] != right_extra[key] for key in left_extra.keys() & right_extra.keys()):
        return None

    data = existing.model_dump()
    for key, name in right_fields.items():
        if key not in left_fields and name not in _CONTEXT_FIELDS:
            data[name] = getattr(incoming, name)
    data["raw_extra"] = {**left_extra, **right_extra}
    data["explicit_fields"] = tuple(sorted(set(existing.explicit_fields) | set(incoming.explicit_fields)))

    primary = max((existing, incoming), key=_preferred_rank)
    explicit_names = {name.replace("-", "_") for name in data["explicit_fields"]}
    for name in ("source_plane", "command", "package", "package_uid", "layer", "layer_uid",
                 "parent_layer_uid", "parent_rule_uid", "gateway", "order"):
        if name not in {"source_plane", "command", "order"} and name in explicit_names:
            continue
        data[name] = getattr(primary, name)
    return type(existing).model_validate(data)


def reconcile_append(destination: list[Any], item: Any) -> None:
    if not isinstance(item, CheckPointSourceObject) or not item.uid:
        destination.append(item)
        return
    for index, existing in enumerate(destination):
        if (type(existing) is type(item) and existing.uid == item.uid
                and _domain(existing) == _domain(item)):
            merged = _merge(existing, item)
            if merged is not None:
                destination[index] = merged
                return
    destination.append(item)


__all__ = ["reconcile_append"]
