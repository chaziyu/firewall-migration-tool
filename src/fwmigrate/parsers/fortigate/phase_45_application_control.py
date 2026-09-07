"""Phase 45 FortiGate application-control list typing.

Uses the Phase 41 operation-aware evaluator and models the FortiOS 7.4.6
``config application list`` hierarchy explicitly. Source nodes/commands remain
lossless and authoritative.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from fwmigrate.parsers.fortigate import phase_41_security_profiles as phase41
from fwmigrate.parsers.fortigate.phase_44_dnsfilter import FGConfigDNS746 as _FGConfigDNS746
from fwmigrate.parsers.fortigate.model import (
    FGApplicationEntry as _FGApplicationEntry,
    FGApplicationFilter,
    FGApplicationList as _FGApplicationList,
    FGApplicationOverride,
)
from fwmigrate.parsers.fortigate.source_tree import FGSourceNode


class FGApplicationParameterMember746(BaseModel):
    """One ordered tuple member under ``entries -> parameters -> members``."""

    name: str
    parameter_name: Optional[str] = None
    value: Optional[str] = None
    source_order: int = 0
    settings: Dict[str, Any] = Field(default_factory=dict)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGApplicationParameter746(BaseModel):
    """Application parameter edit with ordered member tuples."""

    name: str
    source_order: int = 0
    members: List[FGApplicationParameterMember746] = Field(default_factory=list)
    settings: Dict[str, Any] = Field(default_factory=dict)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGApplicationDefaultNetworkService746(BaseModel):
    """Default network service entry under ``config default-network-services``."""

    name: str
    port: Optional[int] = None
    services: List[str] = Field(default_factory=list)
    violation_action: Optional[str] = None
    source_order: int = 0
    settings: Dict[str, Any] = Field(default_factory=dict)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGApplicationEntry746(_FGApplicationEntry):
    """FortiOS 7.4.6 application-list entry."""

    application: List[int] = Field(default_factory=list)
    application_id: Optional[int] = None
    category: List[int] = Field(default_factory=list)
    exclusion: List[int] = Field(default_factory=list)
    risk: List[int] = Field(default_factory=list)
    popularity: List[int] = Field(default_factory=list)
    behavior: Optional[str] = None
    log: Optional[str] = None
    log_packet: Optional[str] = None
    per_ip_shaper: Optional[str] = None
    protocols: Optional[str] = None
    quarantine: Optional[str] = None
    quarantine_expiry: Optional[str] = None
    quarantine_log: Optional[str] = None
    rate_count: Optional[int] = None
    rate_duration: Optional[int] = None
    rate_mode: Optional[str] = None
    rate_track: Optional[str] = None
    session_ttl: Optional[int] = None
    shaper: Optional[str] = None
    shaper_reverse: Optional[str] = None
    technology: Optional[str] = None
    vendor: Optional[str] = None
    source_order: int = 0
    parameters: List[FGApplicationParameter746] = Field(default_factory=list)
    settings: Dict[str, Any] = Field(default_factory=dict)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGApplicationList746(_FGApplicationList):
    """FortiOS 7.4.6 application-control list typed projection."""

    app_replacemsg: Optional[str] = None
    control_default_network_services: Optional[str] = None
    deep_app_inspection: Optional[str] = None
    enforce_default_app_port: Optional[str] = None
    extended_log: Optional[str] = None
    force_inclusion_ssl_di_sigs: Optional[str] = None
    options: List[str] = Field(default_factory=list)
    other_application_action: Optional[str] = None
    other_application_log: Optional[str] = None
    p2p_block_list: List[str] = Field(default_factory=list)
    replacemsg_group: Optional[str] = None
    unknown_application_action: Optional[str] = None
    unknown_application_log: Optional[str] = None
    default_network_services: List[FGApplicationDefaultNetworkService746] = Field(default_factory=list)
    entries: List[FGApplicationEntry746] = Field(default_factory=list)


class FGConfigApplication746(_FGConfigDNS746):
    """Root config retaining Phases 42-44 plus Phase 45 application fields."""

    application_lists: List[FGApplicationList746] = Field(default_factory=list)


_PROFILE_SPEC: Dict[str, set[str]] = {
    "scalar_fields": {
        "comment", "app_replacemsg", "control_default_network_services",
        "deep_app_inspection", "enforce_default_app_port", "extended_log",
        "force_inclusion_ssl_di_sigs", "other_application_action",
        "other_application_log", "replacemsg_group",
        "unknown_application_action", "unknown_application_log",
    },
    "list_fields": {"options", "p2p_block_list"},
}

_DEFAULT_NETWORK_SERVICE_SPEC: Dict[str, set[str]] = {
    "scalar_fields": {"violation_action"},
    "list_fields": {"services"},
    "integer_fields": {"port"},
}

_ENTRY_SPEC: Dict[str, set[str]] = {
    "scalar_fields": {
        "action", "behavior", "log", "log_packet", "per_ip_shaper",
        "protocols", "quarantine", "quarantine_expiry", "quarantine_log",
        "rate_mode", "rate_track", "shaper", "shaper_reverse", "technology",
        "vendor",
    },
    "integer_fields": {"rate_count", "rate_duration", "session_ttl"},
    "integer_list_fields": {"application", "category", "exclusion", "risk", "popularity"},
}

_MEMBER_SPEC: Dict[str, set[str]] = {
    "scalar_fields": {"name", "value"},
}


def _settings(source: FGSourceNode, model: Any) -> tuple[Dict[str, Any], Dict[str, Any]]:
    return phase41._effective_profile_settings(source, model)


def _build_parameters(entry_node: FGSourceNode) -> List[FGApplicationParameter746]:
    parameters: List[FGApplicationParameter746] = []
    for child in entry_node.children:
        if child.node_type != "config" or child.name.lower().replace("-", "_") != "parameters":
            continue
        for order, parameter_node in enumerate(
            (node for node in child.children if node.node_type == "edit"), start=1
        ):
            parameter = FGApplicationParameter746(name=parameter_node.name, source_order=order)
            direct, direct_extra = phase41._effective_node_attributes(parameter_node)
            parameter.settings = direct
            parameter.extra_settings = direct_extra
            for nested in parameter_node.children:
                if nested.node_type != "config" or nested.name.lower().replace("-", "_") != "members":
                    continue
                for member_order, member_node in enumerate(
                    (node for node in nested.children if node.node_type == "edit"), start=1
                ):
                    settings, extra = phase41._effective_node_attributes(
                        member_node, field_spec=_MEMBER_SPEC
                    )
                    parameter.members.append(
                        FGApplicationParameterMember746(
                            name=member_node.name,
                            parameter_name=settings.get("name"),
                            value=settings.get("value"),
                            source_order=member_order,
                            settings=settings,
                            extra_settings=extra,
                        )
                    )
            parameters.append(parameter)
    return parameters


def _append_compat_entries(
    parser: Any,
    profile: FGApplicationList746,
    profile_name: str,
    child: FGSourceNode,
    target_model: Any,
    target_bucket: List[Any],
    integer_fields: tuple[str, ...],
) -> None:
    section_name = child.name.lower().replace("-", "_")
    for projection in phase41._effective_nested_profile_edits(child, target_model):
        phase41._application_diagnostics(
            parser,
            source_path="application list",
            section_name=section_name,
            profile_name=profile_name,
            projection=projection,
            fields=integer_fields,
        )
        target_bucket.append(
            target_model(
                name=projection["name"],
                settings=projection["settings"] if "settings" in target_model.model_fields else {},
                extra_settings=projection["extra_settings"],
                **projection["values"],
            )
        )


def _build_application_lists(
    parser: Any,
    collection_name: str,
    top_edits: List[FGSourceNode],
) -> None:
    for node in top_edits:
        profile_settings, profile_extra = _settings(node, FGApplicationList746)
        profile = FGApplicationList746(
            name=node.name,
            **phase41._typed_values(profile_settings, FGApplicationList746),
        )
        profile.extra_settings = profile_extra

        for child in node.children:
            if child.node_type != "config":
                continue
            child_name = child.name.lower().replace("-", "_")

            if child_name == "default_network_services":
                for projection in phase41._effective_nested_profile_edits(
                    child, FGApplicationDefaultNetworkService746
                ):
                    profile.default_network_services.append(
                        FGApplicationDefaultNetworkService746(
                            name=projection["name"],
                            source_order=projection["source_order"],
                            settings=projection["settings"],
                            extra_settings=projection["extra_settings"],
                            **projection["values"],
                        )
                    )
                continue

            if child_name == "entries":
                edit_nodes = [item for item in child.children if item.node_type == "edit"]
                projections = phase41._effective_nested_profile_edits(child, FGApplicationEntry746)
                for projection, entry_node in zip(projections, edit_nodes):
                    phase41._application_diagnostics(
                        parser,
                        source_path="application list",
                        section_name="entries",
                        profile_name=node.name,
                        projection=projection,
                        fields=("application", "category", "exclusion", "risk", "popularity"),
                    )
                    values = projection["values"]
                    applications = values.get("application", [])
                    values["application_id"] = applications[0] if applications else None
                    profile.entries.append(
                        FGApplicationEntry746(
                            name=projection["name"],
                            source_order=projection["source_order"],
                            settings=projection["settings"],
                            extra_settings=projection["extra_settings"],
                            parameters=_build_parameters(entry_node),
                            **values,
                        )
                    )
                continue

            # Exact compatibility blocks used by older repository fixtures. They
            # are never inferred by substring and do not affect documented 7.4.6
            # ``entries`` semantics.
            if child_name == "filters":
                _append_compat_entries(
                    parser, profile, node.name, child, FGApplicationFilter,
                    profile.filters, ("category", "risk"),
                )
                continue
            if child_name == "overrides":
                _append_compat_entries(
                    parser, profile, node.name, child, FGApplicationOverride,
                    profile.overrides, ("application", "category"),
                )
                continue

            profile.extra_settings.setdefault("source_only_sections", []).append(child.name)

        getattr(parser.config, collection_name).append(profile)


def install_phase_45_application_control_support(parser_module: Any) -> None:
    """Install Phase 45 Application Control typing on top of Phases 41-44."""

    phase41.PROFILE_FIELD_SPECS[FGApplicationList746] = _PROFILE_SPEC
    phase41.PROFILE_FIELD_SPECS[FGApplicationDefaultNetworkService746] = _DEFAULT_NETWORK_SERVICE_SPEC
    phase41.PROFILE_FIELD_SPECS[FGApplicationEntry746] = _ENTRY_SPEC
    phase41.PROFILE_FIELD_SPECS[FGApplicationParameterMember746] = _MEMBER_SPEC

    # Only ``application list`` belongs to this phase. Keep ``application custom``
    # on its existing path/model because it has a different FortiOS schema.
    phase41._PROFILE_PATHS["application list"] = (
        "application_lists",
        FGApplicationList746,
    )

    original_builder = phase41._build_dns_app_ssl
    if not getattr(original_builder, "_phase_45_wrapped", False):
        def build_dns_app_ssl(
            parser: Any,
            source_path: str,
            collection_name: str,
            model: Any,
            top_edits: List[FGSourceNode],
        ) -> None:
            if model is FGApplicationList746:
                _build_application_lists(parser, collection_name, top_edits)
                return
            original_builder(parser, source_path, collection_name, model, top_edits)

        build_dns_app_ssl._phase_45_wrapped = True
        phase41._build_dns_app_ssl = build_dns_app_ssl

    parser_module.FGConfig = FGConfigApplication746
    parser_module.FGApplicationList = FGApplicationList746
    parser_module.FGApplicationEntry = FGApplicationEntry746
    parser_module.PROFILE_FIELD_SPECS = phase41.PROFILE_FIELD_SPECS
