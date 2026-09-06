"""FortiGate Phase 22 typed source models and parser integration.

These models remain source-oriented. They improve extraction fidelity for
FortiOS traffic shaping families without implying portable target-generation
support.
"""

from __future__ import annotations

from typing import Any, Dict, Iterator, List, Optional, Set

from pydantic import BaseModel, Field

from fwmigrate.parsers.fortigate.extraction import sanitize_source_attributes
from fwmigrate.parsers.fortigate.model import FGConfig, FGSourceOnlyRule
from fwmigrate.parsers.fortigate.source_tree import FGSourceNode


class FGPerIPShaper(FGSourceOnlyRule):
    """Typed FortiOS ``firewall shaper per-ip-shaper`` source semantics."""

    max_bandwidth: Optional[int] = None
    bandwidth_unit: Optional[str] = None
    max_concurrent_session: Optional[int] = None
    max_concurrent_tcp_session: Optional[int] = None
    max_concurrent_udp_session: Optional[int] = None
    diffserv_forward: Optional[str] = None
    diffserv_reverse: Optional[str] = None
    diffservcode_forward: Optional[str] = None
    diffservcode_rev: Optional[str] = None
    source_explicit_fields: Set[str] = Field(default_factory=set)


class FGShapingProfileEntry(BaseModel):
    """One FortiOS shaping-profile ``shaping-entries`` child."""

    source_id: str
    id: Optional[int] = None
    class_id: Optional[int] = None
    priority: Optional[str] = None
    guaranteed_bandwidth_percentage: Optional[int] = None
    maximum_bandwidth_percentage: Optional[int] = None
    limit: Optional[int] = None
    burst_in_msec: Optional[int] = None
    cburst_in_msec: Optional[int] = None
    red_probability: Optional[int] = None
    min: Optional[int] = None
    max: Optional[int] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGShapingProfile(FGSourceOnlyRule):
    """Typed FortiOS ``firewall shaping-profile`` source semantics."""

    type: Optional[str] = None
    default_class_id: Optional[int] = None
    comment: Optional[str] = None
    shaping_entries: List[FGShapingProfileEntry] = Field(default_factory=list)
    source_explicit_fields: Set[str] = Field(default_factory=set)


_PER_IP_INT_FIELDS = {
    "max_bandwidth",
    "max_concurrent_session",
    "max_concurrent_tcp_session",
    "max_concurrent_udp_session",
}

_PROFILE_INT_FIELDS = {"default_class_id"}

_PROFILE_ENTRY_INT_FIELDS = {
    "class_id",
    "guaranteed_bandwidth_percentage",
    "maximum_bandwidth_percentage",
    "limit",
    "burst_in_msec",
    "cburst_in_msec",
    "red_probability",
    "min",
    "max",
}

_INHERITED_RULE_FIELDS = {
    "family",
    "id",
    "name",
    "source_order",
    "status",
    "source_context",
    "settings",
    "nested_configs",
    "extra_settings",
    "source_explicit_fields",
}

_ORIGINAL_BUILD_MODEL = None
_INSTALLED = False


def _scalar(values: List[str]) -> Any:
    if not values:
        return None
    return values[0] if len(values) == 1 else list(values)


def _apply_source_command(
    attributes: Dict[str, Any],
    operation: str,
    key: str,
    values: List[str],
) -> None:
    """Replay a retained source command without losing append/unset semantics."""

    normalized_key = key.replace("-", "_")
    if operation == "unset":
        attributes.pop(normalized_key, None)
        return

    value = _scalar(values)
    if operation != "append":
        attributes[normalized_key] = value
        return

    if normalized_key not in attributes:
        attributes[normalized_key] = list(values)
        return

    current = attributes[normalized_key]
    if not isinstance(current, list):
        current = [current]
    current.extend(values)
    attributes[normalized_key] = current


def _source_node_attributes(node: FGSourceNode) -> Dict[str, Any]:
    attributes: Dict[str, Any] = {}
    for command in node.commands:
        _apply_source_command(
            attributes,
            command.operation,
            command.key,
            list(command.values),
        )
    return attributes


def _normalize_optional_int(
    attributes: Dict[str, Any],
    key: str,
    extra_settings: Dict[str, Any],
) -> Optional[int]:
    raw = attributes.get(key)
    if raw is None:
        return None
    if isinstance(raw, list):
        if len(raw) != 1:
            extra_settings[f"unparsed_{key}"] = raw
            return None
        raw = raw[0]
    if isinstance(raw, bool):
        extra_settings[f"unparsed_{key}"] = raw
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        extra_settings[f"unparsed_{key}"] = raw
        return None


def _typed_extra_settings(
    settings: Dict[str, Any],
    known_fields: Set[str],
) -> Dict[str, Any]:
    return sanitize_source_attributes(
        {
            key: value
            for key, value in settings.items()
            if key not in known_fields and key not in _INHERITED_RULE_FIELDS
        }
    )


def _iter_profile_entry_nodes(nodes: List[FGSourceNode]) -> Iterator[FGSourceNode]:
    for node in nodes:
        normalized_name = node.name.replace("_", "-").lower()
        if normalized_name in {"shaping-entries", "classes"}:
            for child in node.children:
                if child.node_type == "edit":
                    yield child
        yield from _iter_profile_entry_nodes(node.children)


def _build_profile_entries(
    nodes: List[FGSourceNode],
) -> List[FGShapingProfileEntry]:
    entries: List[FGShapingProfileEntry] = []
    known_fields = set(FGShapingProfileEntry.model_fields) - {"extra_settings"}

    for node in _iter_profile_entry_nodes(nodes):
        attributes = _source_node_attributes(node)
        extra_settings = _typed_extra_settings(attributes, known_fields)
        payload: Dict[str, Any] = {
            "source_id": node.name,
            "extra_settings": extra_settings,
        }
        try:
            payload["id"] = int(node.name)
        except (TypeError, ValueError):
            payload["id"] = None

        for key in known_fields - {"source_id", "id"}:
            if key not in attributes:
                continue
            if key in _PROFILE_ENTRY_INT_FIELDS:
                payload[key] = _normalize_optional_int(
                    attributes,
                    key,
                    extra_settings,
                )
            else:
                payload[key] = attributes[key]

        entries.append(FGShapingProfileEntry(**payload))

    return entries


def _build_per_ip_shaper(
    parser: Any,
    attributes: Dict[str, Any],
) -> FGPerIPShaper:
    attrs = dict(attributes)
    rule_id = attrs.pop("id", None)
    name = attrs.pop("name", None)
    context = attrs.pop("source_context", parser.current_context)
    nested_configs = list(attrs.pop("nested_configs", []))
    source_explicit_fields = set(attrs.pop("source_explicit_fields", set()))
    status = attrs.get("status")
    settings = sanitize_source_attributes(dict(attrs))

    known_fields = set(FGPerIPShaper.model_fields) - _INHERITED_RULE_FIELDS
    extra_settings = _typed_extra_settings(settings, known_fields)
    payload: Dict[str, Any] = {}
    for key in known_fields:
        if key not in settings:
            continue
        if key in _PER_IP_INT_FIELDS:
            payload[key] = _normalize_optional_int(settings, key, extra_settings)
        else:
            payload[key] = settings[key]

    return FGPerIPShaper(
        family="per-ip-shaper",
        id=rule_id,
        name=name,
        source_order=parser._source_order,
        status=status,
        source_context=context,
        settings=settings,
        nested_configs=nested_configs,
        extra_settings=extra_settings,
        source_explicit_fields=source_explicit_fields,
        **payload,
    )


def _build_shaping_profile(
    parser: Any,
    attributes: Dict[str, Any],
) -> FGShapingProfile:
    attrs = dict(attributes)
    rule_id = attrs.pop("id", None)
    name = attrs.pop("name", None)
    context = attrs.pop("source_context", parser.current_context)
    nested_configs = list(attrs.pop("nested_configs", []))
    source_explicit_fields = set(attrs.pop("source_explicit_fields", set()))
    status = attrs.get("status")
    settings = sanitize_source_attributes(dict(attrs))

    known_fields = (
        set(FGShapingProfile.model_fields)
        - _INHERITED_RULE_FIELDS
        - {"shaping_entries"}
    )
    extra_settings = _typed_extra_settings(settings, known_fields)
    payload: Dict[str, Any] = {}
    for key in known_fields:
        if key not in settings:
            continue
        if key in _PROFILE_INT_FIELDS:
            payload[key] = _normalize_optional_int(settings, key, extra_settings)
        else:
            payload[key] = settings[key]

    return FGShapingProfile(
        family="shaping-profile",
        id=rule_id,
        name=name,
        source_order=parser._source_order,
        status=status,
        source_context=context,
        settings=settings,
        nested_configs=nested_configs,
        extra_settings=extra_settings,
        source_explicit_fields=source_explicit_fields,
        shaping_entries=_build_profile_entries(nested_configs),
        **payload,
    )


def install_phase22_parser_support() -> None:
    """Install typed handling for Phase 22 source-only shaping families.

    The existing parser deliberately routes several non-portable families
    through ``FGSourceOnlyRule``. This focused integration intercepts only the
    two Phase 22 sections and delegates every other section unchanged.
    """

    global _ORIGINAL_BUILD_MODEL, _INSTALLED
    if _INSTALLED:
        return

    from fwmigrate.parsers.fortigate import model as model_module
    from fwmigrate.parsers.fortigate.parser import FortiGateParser

    _ORIGINAL_BUILD_MODEL = FortiGateParser.build_model

    def phase22_build_model(
        self: Any,
        section_path: str,
        attributes: Dict[str, Any],
    ) -> None:
        if section_path == "firewall shaper per-ip-shaper":
            self._source_order += 1
            self.config.source_only_rules.append(
                _build_per_ip_shaper(self, attributes)
            )
            return

        if section_path == "firewall shaping-profile":
            self._source_order += 1
            self.config.source_only_rules.append(
                _build_shaping_profile(self, attributes)
            )
            return

        _ORIGINAL_BUILD_MODEL(self, section_path, attributes)

    phase22_build_model.__name__ = "build_model"
    phase22_build_model.__qualname__ = "FortiGateParser.build_model"
    FortiGateParser.build_model = phase22_build_model

    # Keep these source models accessible through the established model module
    # import surface while the typed data remains in the source-only collection.
    model_module.FGPerIPShaper = FGPerIPShaper
    model_module.FGShapingProfileEntry = FGShapingProfileEntry
    model_module.FGShapingProfile = FGShapingProfile

    def _per_ip_shapers(config: FGConfig) -> List[FGPerIPShaper]:
        return [
            item
            for item in config.source_only_rules
            if isinstance(item, FGPerIPShaper)
        ]

    def _shaping_profiles(config: FGConfig) -> List[FGShapingProfile]:
        return [
            item
            for item in config.source_only_rules
            if isinstance(item, FGShapingProfile)
        ]

    if not hasattr(FGConfig, "per_ip_shapers"):
        FGConfig.per_ip_shapers = property(_per_ip_shapers)
    if not hasattr(FGConfig, "shaping_profiles"):
        FGConfig.shaping_profiles = property(_shaping_profiles)

    _INSTALLED = True
