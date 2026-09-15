"""Declarative FortiGate source-parser section metadata."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any, Callable, Iterable, Mapping


@dataclass(frozen=True)
class SectionSpec:
    source_path: str
    model: type[Any] | None = None
    list_fields: frozenset[str] = field(default_factory=frozenset)
    integer_fields: frozenset[str] = field(default_factory=frozenset)
    integer_list_fields: frozenset[str] = field(default_factory=frozenset)
    scalar_fields: frozenset[str] = field(default_factory=frozenset)
    explicit_fields: frozenset[str] = field(default_factory=frozenset)
    secret_fields: frozenset[str] = field(default_factory=frozenset)
    custom_builder: Callable[..., Any] | None = None


SECTION_REGISTRY: dict[str, SectionSpec] = {}


def register_section(spec: SectionSpec) -> None:
    SECTION_REGISTRY[spec.source_path] = spec


def register_sections(
    paths: Iterable[str],
    *,
    models: Mapping[str, type[Any]] | None = None,
    list_fields: Mapping[str, Iterable[str]] | None = None,
    integer_fields: Mapping[str, Iterable[str]] | None = None,
    integer_list_fields: Mapping[str, Iterable[str]] | None = None,
    scalar_fields: Mapping[str, Iterable[str]] | None = None,
    explicit_fields: Mapping[str, Iterable[str]] | None = None,
    secret_fields: Mapping[str, Iterable[str]] | None = None,
) -> None:
    """Replace registry entries from the parser's final active metadata."""

    models = models or {}
    mappings = [
        list_fields or {}, integer_fields or {}, integer_list_fields or {},
        scalar_fields or {}, explicit_fields or {}, secret_fields or {},
    ]
    for path in paths:
        register_section(SectionSpec(
            source_path=path,
            model=models.get(path),
            list_fields=frozenset(mappings[0].get(path, ())),
            integer_fields=frozenset(mappings[1].get(path, ())),
            integer_list_fields=frozenset(mappings[2].get(path, ())),
            scalar_fields=frozenset(mappings[3].get(path, ())),
            explicit_fields=frozenset(mappings[4].get(path, ())),
            secret_fields=frozenset(mappings[5].get(path, ())),
        ))


def update_section(path: str, **changes: Any) -> SectionSpec:
    spec = replace(get_section_spec(path) or SectionSpec(path), **changes)
    register_section(spec)
    return spec


def get_section_spec(section_path: str) -> SectionSpec | None:
    return SECTION_REGISTRY.get(section_path)


def get_section_parser_capability(
    section_path: str,
    encountered_fields: Iterable[str] = (),
) -> dict[str, Any]:
    spec = get_section_spec(section_path)
    if spec is None:
        return {
            "source_path": section_path,
            "known_section": False,
            "classification": "unknown",
            "unknown_fields": sorted(set(encountered_fields)),
        }
    typed = spec.list_fields | spec.integer_fields | spec.integer_list_fields | spec.scalar_fields
    known = typed | spec.explicit_fields
    return {
        "source_path": section_path,
        "known_section": True,
        "model": spec.model.__name__ if spec.model else None,
        "known_fields": sorted(known),
        "list_fields": sorted(spec.list_fields),
        "integer_fields": sorted(spec.integer_fields),
        "integer_list_fields": sorted(spec.integer_list_fields),
        "scalar_fields": sorted(spec.scalar_fields),
        "custom_handler": bool(spec.custom_builder),
        "classification": "custom handled" if spec.custom_builder else "typed",
        "unknown_fields": sorted(set(encountered_fields) - known),
    }
