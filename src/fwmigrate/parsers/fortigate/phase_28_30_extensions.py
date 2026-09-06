"""FortiOS 7.4.6 source-model extensions for phases 28-30.

The canonical IR remains unchanged. These models preserve FortiGate source
semantics while the existing transformer continues to decide what is portable.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import Field, model_validator

from fwmigrate.parsers.fortigate.model import (
    FGPhase1Interface as _FGPhase1Interface,
    FGPhase1Policy as _FGPhase1Policy,
    FGPhase2Interface as _FGPhase2Interface,
    FGPhase2Policy as _FGPhase2Policy,
    FGSchedule as _FGSchedule,
    FGScheduleGroup as _FGScheduleGroup,
)


def _preserve_ints(value: Any, fields: set[str]) -> Any:
    """Coerce documented integer fields without repairing malformed source."""
    if not isinstance(value, dict):
        return value
    normalized = dict(value)
    extra = dict(normalized.get("extra_settings") or {})
    for field in fields:
        raw = normalized.get(field)
        if raw is None:
            continue
        try:
            normalized[field] = int(raw)
        except (TypeError, ValueError):
            extra[f"unparsed_{field}"] = raw
            normalized[field] = None
    normalized["extra_settings"] = extra
    return normalized


class FGRecurringSchedule746(_FGSchedule):
    """FortiOS recurring schedule; source time strings are not converted."""

    type: str = "recurring"
    day: List[str] = Field(default_factory=list)
    start: Optional[str] = None
    end: Optional[str] = None
    color: Optional[int] = None
    fabric_object: Optional[str] = None

    @model_validator(mode="before")
    @classmethod
    def _normalize_ints(cls, value: Any) -> Any:
        return _preserve_ints(value, {"color"})


class FGOnetimeSchedule746(_FGSchedule):
    """FortiOS one-time schedule with exact local and UTC source strings."""

    type: str = "onetime"
    start: Optional[str] = None
    end: Optional[str] = None
    start_utc: Optional[str] = None
    end_utc: Optional[str] = None
    expiration_days: Optional[int] = None
    color: Optional[int] = None
    fabric_object: Optional[str] = None

    @model_validator(mode="before")
    @classmethod
    def _normalize_ints(cls, value: Any) -> Any:
        return _preserve_ints(value, {"color", "expiration_days"})


class FGScheduleGroup746(_FGScheduleGroup):
    """Typed FortiOS schedule-group source object."""

    color: Optional[int] = None
    fabric_object: Optional[str] = None

    @model_validator(mode="before")
    @classmethod
    def _normalize_ints(cls, value: Any) -> Any:
        return _preserve_ints(value, {"color"})


class _Phase1Fields746:
    """Documented Phase-1 fields that were previously retained only as extras."""

    ip_version: Optional[str] = None
    remote_gw_match: Optional[str] = None
    remote_gw_start_ip: Optional[str] = None
    remote_gw_subnet: Optional[str] = None
    remote_gw_country: Optional[str] = None
    remote_gw_ztna_tags: List[str] = Field(default_factory=list)
    cert_trust_store: Optional[str] = None
    cert_peer_username_strip: Optional[str] = None
    cert_peer_username_validation: Optional[str] = None
    acct_verify: Optional[str] = None
    default_gw: Optional[str] = None
    default_gw_priority: Optional[int] = None
    distance: Optional[int] = None
    priority: Optional[int] = None
    dns_suffix_search: List[str] = Field(default_factory=list)


class FGPhase1Interface746(_FGPhase1Interface):
    ip_version: Optional[str] = None
    remote_gw_match: Optional[str] = None
    remote_gw_start_ip: Optional[str] = None
    remote_gw_subnet: Optional[str] = None
    remote_gw_country: Optional[str] = None
    remote_gw_ztna_tags: List[str] = Field(default_factory=list)
    cert_trust_store: Optional[str] = None
    cert_peer_username_strip: Optional[str] = None
    cert_peer_username_validation: Optional[str] = None
    acct_verify: Optional[str] = None
    default_gw: Optional[str] = None
    default_gw_priority: Optional[int] = None
    distance: Optional[int] = None
    priority: Optional[int] = None
    dns_suffix_search: List[str] = Field(default_factory=list)
    aggregate_member: Optional[str] = None
    aggregate_weight: Optional[int] = None

    @model_validator(mode="before")
    @classmethod
    def _normalize_phase1_746_ints(cls, value: Any) -> Any:
        return _preserve_ints(
            value,
            {"default_gw_priority", "distance", "priority", "aggregate_weight"},
        )


class FGPhase1Policy746(_FGPhase1Policy):
    ip_version: Optional[str] = None
    remote_gw_match: Optional[str] = None
    remote_gw_start_ip: Optional[str] = None
    remote_gw_subnet: Optional[str] = None
    remote_gw_country: Optional[str] = None
    remote_gw_ztna_tags: List[str] = Field(default_factory=list)
    cert_trust_store: Optional[str] = None
    cert_peer_username_strip: Optional[str] = None
    cert_peer_username_validation: Optional[str] = None
    acct_verify: Optional[str] = None
    default_gw: Optional[str] = None
    default_gw_priority: Optional[int] = None
    distance: Optional[int] = None
    priority: Optional[int] = None
    dns_suffix_search: List[str] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _normalize_phase1_746_ints(cls, value: Any) -> Any:
        return _preserve_ints(value, {"default_gw_priority", "distance", "priority"})


class FGPhase2Interface746(_FGPhase2Interface):
    """Phase-2 interface model with typed ports/protocol and exact selectors."""

    protocol: Optional[int] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None

    @model_validator(mode="before")
    @classmethod
    def _normalize_phase2_746_ints(cls, value: Any) -> Any:
        return _preserve_ints(value, {"protocol", "src_port", "dst_port"})


class FGPhase2Policy746(_FGPhase2Policy):
    """Policy-mode Phase-2 remains a distinct source family."""

    protocol: Optional[int] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None

    @model_validator(mode="before")
    @classmethod
    def _normalize_phase2_746_ints(cls, value: Any) -> Any:
        return _preserve_ints(value, {"protocol", "src_port", "dst_port"})


def install_phase_28_30_extensions(parser_module) -> None:
    """Install scoped Phase 28-30 models into the existing parser."""

    # List-valued FortiOS fields. Order is source-significant and duplicates
    # must not be removed by the raw parser.
    parser_module.SECTION_LIST_FIELDS.setdefault(
        "firewall schedule recurring", set()
    ).add("day")
    parser_module.SECTION_LIST_FIELDS.setdefault(
        "firewall schedule group", set()
    ).add("member")
    for path in ("vpn ipsec phase1-interface", "vpn ipsec phase1"):
        parser_module.SECTION_LIST_FIELDS.setdefault(path, set()).update(
            {"dns_suffix_search", "remote_gw_ztna_tags"}
        )

    phase1_fields = {
        "ip_version", "remote_gw_match", "remote_gw_start_ip",
        "remote_gw_subnet", "remote_gw_country", "remote_gw_ztna_tags",
        "cert_trust_store", "cert_peer_username_strip",
        "cert_peer_username_validation", "acct_verify", "default_gw",
        "default_gw_priority", "distance", "priority", "dns_suffix_search",
    }
    for path in ("vpn ipsec phase1-interface", "vpn ipsec phase1"):
        parser_module.SECTION_EXPLICIT_FIELDS.setdefault(path, set()).update(
            phase1_fields
        )

    # The original build_model resolves these globals at runtime.
    parser_module.FGScheduleGroup = FGScheduleGroup746
    parser_module.FGPhase1Interface = FGPhase1Interface746
    parser_module.FGPhase1Policy = FGPhase1Policy746
    parser_module.FGPhase2Interface = FGPhase2Interface746
    parser_module.FGPhase2Policy = FGPhase2Policy746

    parser_cls = parser_module.FortiGateParser
    if getattr(parser_cls.build_model, "_phase_28_30_wrapped", False):
        return
    original_build_model = parser_cls.build_model

    def build_model(self, section_path: str, attributes: Dict[str, Any]):
        if section_path in {
            "firewall schedule recurring", "firewall schedule onetime"
        }:
            model_cls = (
                FGOnetimeSchedule746
                if section_path.endswith("onetime")
                else FGRecurringSchedule746
            )
            values = dict(attributes)
            values["extra_settings"] = parser_module._extract_extra_settings(
                values, set(model_cls.model_fields)
            )
            self.config.schedules.append(model_cls(**values))
            return

        if section_path == "firewall schedule group":
            # Let the existing branch retain generic unset evidence while using
            # the extended typed group model through the patched global.
            return original_build_model(self, section_path, attributes)

        return original_build_model(self, section_path, attributes)

    build_model._phase_28_30_wrapped = True
    parser_cls.build_model = build_model
