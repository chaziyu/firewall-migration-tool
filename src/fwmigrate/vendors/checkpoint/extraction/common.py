from __future__ import annotations

from typing import Any, Dict, Iterable, Type, get_args, get_origin

from fwmigrate.extraction.sanitize import sanitize_source_attributes

from ..model.common import CheckPointSourceObject
from ..models import CheckPointResponse
from .source_inventory import CheckPointSourceRecord


def iter_dictionary_objects(objects: Any) -> Iterable[Dict[str, Any]]:
    if isinstance(objects, dict):
        for key, item in objects.items():
            if isinstance(item, dict):
                value = dict(item)
                if not value.get("uid") and key:
                    value["uid"] = str(key)
                yield value
    elif isinstance(objects, list):
        yield from (dict(item) for item in objects if isinstance(item, dict))


def source_plane(response: CheckPointResponse) -> str:
    return "gaia" if response.command.startswith("gaia/") else "management"


def values(response: CheckPointResponse) -> Iterable[dict[str, Any]]:
    for key in ("objects", "rulebase", "rules", "items", "interfaces", "routes"):
        value = response.data.get(key)
        if isinstance(value, dict):
            yield from iter_dictionary_objects(value)
        elif isinstance(value, list):
            yield from (item for item in value if isinstance(item, dict))
            return


def build_typed_object(
    response: CheckPointResponse,
    value: dict[str, Any],
    model: Type[CheckPointSourceObject],
    order: int | None = None,
) -> CheckPointSourceObject:
    context = dict(value)
    section_path = context.pop("_checkpoint_section_path", None)
    inline_layer_context = context.pop("_checkpoint_inline_layer_context", None)
    source_values, raw_extra, explicit_fields = build_source_fields(model, context)
    if section_path is not None and "section_path" in model.model_fields:
        source_values["section_path"] = list(section_path)
    if inline_layer_context is not None and "inline_layer" in model.model_fields:
        source_values["inline_layer"] = inline_layer_context
    return model(
        **source_values,
        source_plane=source_plane(response), command=response.command,
        domain=response.domain, domain_uid=response.domain_uid,
        package=response.package, package_uid=response.package_uid,
        layer=response.layer, layer_uid=response.layer_uid,
        parent_layer_uid=response.parent_layer_uid, parent_rule_uid=response.parent_rule_uid,
        gateway=response.gateway,
        order=order, raw_extra=raw_extra, explicit_fields=explicit_fields,
    )


def build_source_fields(
    model: Type[CheckPointSourceObject], value: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any], tuple[str, ...]]:
    """Map explicit safe source keys to one typed model without resolving references."""
    safe = sanitize_source_attributes(dict(value))
    fields = model.model_fields
    aliases = {field.alias for field in fields.values() if field.alias}
    source_values: dict[str, Any] = {}
    for key, item in safe.items():
        field_name = key.replace("-", "_")
        if field_name in fields:
            source_values[field_name] = _model_value(fields[field_name].annotation, item)
        elif key in aliases:
            field_name = next(name for name, field in fields.items() if field.alias == key)
            source_values[field_name] = _model_value(fields[field_name].annotation, item)
    raw_extra = {
        key: item for key, item in safe.items()
        if key not in aliases and key.replace("-", "_") not in fields
    }
    return source_values, raw_extra, tuple(sorted(key.replace("-", "_") for key in safe))


def _model_value(annotation: Any, value: Any) -> Any:
    if value is None or isinstance(value, list) or not _contains_list(annotation):
        return value
    return [value]


def _contains_list(annotation: Any) -> bool:
    if get_origin(annotation) is list:
        return True
    return any(_contains_list(item) for item in get_args(annotation))


def build_source_inventory(
    response: CheckPointResponse,
    value: dict[str, Any],
    order: int | None = None,
) -> CheckPointSourceRecord:
    safe = sanitize_source_attributes(dict(value))
    return CheckPointSourceRecord(
        uid=safe.get("uid"), name=safe.get("name"), type=safe.get("type"),
        source_plane=source_plane(response), command=response.command,
        domain=response.domain, domain_uid=response.domain_uid,
        package=response.package, package_uid=response.package_uid,
        layer=response.layer, layer_uid=response.layer_uid,
        gateway=response.gateway, order=order, values=safe,
        explicit_fields=tuple(sorted(str(key) for key in safe)),
    )
