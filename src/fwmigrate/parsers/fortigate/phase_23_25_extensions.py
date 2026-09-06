"""FortiGate Phase 23-25 source-parser extensions.

These extensions tighten FortiOS 7.4.6 source typing without broadening target
semantics:
- shaping-policy application/application-category IDs are typed as integers
  while malformed tokens remain in ``extra_settings``;
- shaping-policy ``comment`` is retained as a typed source field;
- address and address-group color fields use the parser's lossless integer
  normalization path;
- address-group dynamic filter input is retained as typed source evidence while
  remaining non-portable/manual-review data.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import ConfigDict, Field, model_validator

from fwmigrate.parsers.fortigate.model import (
    FGAddressGroup as _FGAddressGroup,
    FGShapingPolicy as _FGShapingPolicy,
)


_SHAPING_POLICY_LIST_FIELDS = {
    "srcintf",
    "dstintf",
    "srcaddr",
    "dstaddr",
    "srcaddr6",
    "dstaddr6",
    "application",
    "app_category",
    "app_group",
    "url_category",
    "service",
}

_ADDRESS_SECTIONS = {
    "firewall address",
    "firewall address6",
    "firewall multicast-address",
    "firewall multicast-address6",
}

_ADDRESS_GROUP_SECTIONS = {"firewall addrgrp", "firewall addrgrp6"}


def _normalize_int_lists(value: Any, fields: set[str]) -> Any:
    """Type integer-ID lists without silently discarding malformed tokens."""
    if not isinstance(value, dict):
        return value

    normalized = dict(value)
    extra_settings = dict(normalized.get("extra_settings") or {})

    for field in fields:
        raw = normalized.get(field)
        if raw is None:
            continue

        values = list(raw) if isinstance(raw, list) else [raw]
        parsed: List[int] = []
        unparsed: List[Any] = []
        for item in values:
            if isinstance(item, bool):
                unparsed.append(item)
                continue
            try:
                parsed.append(int(item))
            except (TypeError, ValueError):
                unparsed.append(item)

        normalized[field] = parsed
        if unparsed:
            extra_settings[f"unparsed_{field}"] = unparsed

    normalized["extra_settings"] = extra_settings
    return normalized


class FGShapingPolicy746(_FGShapingPolicy):
    """Phase 23 shaping-policy source model with typed application IDs."""

    application: List[int] = Field(default_factory=list)
    app_category: List[int] = Field(default_factory=list)
    comment: Optional[str] = None

    @model_validator(mode="before")
    @classmethod
    def _normalize_application_ids(cls, value: Any) -> Any:
        return _normalize_int_lists(value, {"application", "app_category"})


class FGAddressGroup746(_FGAddressGroup):
    """Phase 25 address-group source model with retained dynamic criteria.

    FortiOS 7.4.6's normal ``addrgrp`` schema is static/folder based. When a
    source configuration contains a ``filter`` setting, keep it explicitly as
    source evidence instead of interpreting it as static membership. The raw
    ``filter`` key intentionally remains in ``extra_settings`` so existing
    migration-safety logic continues to require manual review.
    """

    model_config = ConfigDict(populate_by_name=True)
    dynamic_filter: Optional[str] = Field(default=None, alias="filter")


def install_phase_23_25_extensions(parser_module: Any) -> None:
    """Install scoped Phase 23-25 parsing behavior on ``FortiGateParser``."""

    # Reinforce the list/reference contract for shaping policies. Shaper
    # references deliberately remain scalar names and are not resolved here.
    parser_module.SECTION_LIST_FIELDS.setdefault(
        "firewall shaping-policy", set()
    ).update(_SHAPING_POLICY_LIST_FIELDS)

    # Address-group member/exclusion ordering must survive set/append/unset.
    for path in _ADDRESS_GROUP_SECTIONS:
        parser_module.SECTION_LIST_FIELDS.setdefault(path, set()).update(
            {"member", "exclude_member"}
        )

    # The existing build_model function resolves these globals at runtime.
    parser_module.FGShapingPolicy = FGShapingPolicy746
    parser_module.FGAddressGroup = FGAddressGroup746

    parser_cls = parser_module.FortiGateParser
    if getattr(parser_cls.build_model, "_phase_23_25_wrapped", False):
        return

    original_build_model = parser_cls.build_model

    def build_model(
        self: Any,
        section_path: str,
        attributes: Dict[str, Any],
    ) -> Any:
        if section_path in _ADDRESS_SECTIONS or section_path in _ADDRESS_GROUP_SECTIONS:
            # Use the parser's existing zero-silent-loss conversion: malformed
            # numeric input becomes ``unparsed_color`` source evidence rather
            # than causing object validation to fail or being repaired.
            self._normalize_optional_int(attributes, "color")
        return original_build_model(self, section_path, attributes)

    build_model._phase_23_25_wrapped = True
    parser_cls.build_model = build_model
