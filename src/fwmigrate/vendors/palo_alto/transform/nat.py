from __future__ import annotations

from dataclasses import dataclass

from ..model.nat import PANNATRule


@dataclass(frozen=True, slots=True)
class PANDerivedNAT:
    name: str | None
    source_path: str
    source_translation_mode: str | None
    destination_translation_mode: str | None
    dynamic_destination_mode: str | None
    translated_references: tuple[str, ...]
    source_order: int | None


def transform_nat(rules: list[PANNATRule]) -> tuple[PANDerivedNAT, ...]:
    result = []
    for rule in rules:
        source = rule.source_translation
        destination = rule.destination_translation
        dynamic = rule.dynamic_destination_translation
        refs = tuple((source.translated_address,) if hasattr(source, "translated_address") and source.translated_address else ()) + tuple(source.translated_addresses if hasattr(source, "translated_addresses") and source and source.translated_addresses else ()) + tuple(destination.translated_address for _ in [0] if destination and destination.translated_address) + tuple(dynamic.translated_addresses if dynamic and dynamic.translated_addresses else ())
        result.append(PANDerivedNAT(rule.name, rule.source_path, source.translation_type if source else None, "destination-translation" if destination else "dynamic-destination-translation" if dynamic else None, dynamic.distribution if dynamic else None, refs, rule.source_order))
    return tuple(result)
