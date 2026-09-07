"""Phase 44 FortiGate DNS-filter profile typing.

Extends the Phase 41 shared operation-aware evaluator with explicit FortiOS
7.4.6 DNS-filter hierarchy and field declarations. Structured source nodes
remain authoritative and unchanged.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from fwmigrate.parsers.fortigate import phase_41_security_profiles as phase41
from fwmigrate.parsers.fortigate.phase_43_webfilter import FGConfigWeb746 as _FGConfigWeb746
from fwmigrate.parsers.fortigate.model import (
    FGDNSFilterCategory as _FGDNSFilterCategory,
    FGDNSFilterProfile as _FGDNSFilterProfile,
)
from fwmigrate.parsers.fortigate.source_tree import FGSourceNode


class FGDNSFilterCategory746(_FGDNSFilterCategory):
    """FortiGuard DNS category filter entry under ``ftgd-dns filters``."""

    category: Optional[int] = None
    action: Optional[str] = None
    log: Optional[str] = None
    source_order: int = 0
    settings: Dict[str, Any] = Field(default_factory=dict)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGDNSFilterDomainReference746(BaseModel):
    """Reference to a separate ``config dnsfilter domain-filter`` table."""

    name: str = "domain-filter"
    domain_filter_table: Optional[int] = None
    settings: Dict[str, Any] = Field(default_factory=dict)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGDNSFilterFortiGuard746(BaseModel):
    """Direct ``config ftgd-dns`` settings and ordered category filters."""

    options: List[str] = Field(default_factory=list)
    categories: List[FGDNSFilterCategory746] = Field(default_factory=list)
    settings: Dict[str, Any] = Field(default_factory=dict)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGDNSFilterBotnet746(BaseModel):
    """Explicit botnet-related root settings kept distinct from categories."""

    name: str = "botnet"
    block_botnet: Optional[str] = None
    block_action: Optional[str] = None
    settings: Dict[str, Any] = Field(default_factory=dict)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGDNSFilterProfile746(_FGDNSFilterProfile):
    """FortiOS 7.4.6 DNS-filter profile typed projection."""

    block_action: Optional[str] = None
    block_botnet: Optional[str] = None
    external_ip_blocklist: List[str] = Field(default_factory=list)
    log_all_domain: Optional[str] = None
    redirect_portal: Optional[str] = None
    redirect_portal6: Optional[str] = None
    safe_search: Optional[str] = None
    sdns_domain_log: Optional[str] = None
    sdns_ftgd_err_log: Optional[str] = None
    strip_ech: Optional[str] = None
    transparent_dns_database: List[str] = Field(default_factory=list)
    youtube_restrict: Optional[str] = None
    ftgd_dns: Optional[FGDNSFilterFortiGuard746] = None
    domain_filters: List[FGDNSFilterDomainReference746] = Field(default_factory=list)
    categories: List[FGDNSFilterCategory746] = Field(default_factory=list)
    botnet: List[FGDNSFilterBotnet746] = Field(default_factory=list)


class FGConfigDNS746(_FGConfigWeb746):
    """Root config retaining Phase 42 AV, Phase 43 Web, and Phase 44 DNS fields."""

    dnsfilter_profiles: List[FGDNSFilterProfile746] = Field(default_factory=list)


_DNS_PROFILE_SPEC: Dict[str, set[str]] = {
    "scalar_fields": {
        "comment",
        "block_action",
        "block_botnet",
        "log_all_domain",
        "redirect_portal",
        "redirect_portal6",
        "safe_search",
        "sdns_domain_log",
        "sdns_ftgd_err_log",
        "strip_ech",
        "youtube_restrict",
    },
    "list_fields": {"external_ip_blocklist", "transparent_dns_database"},
}

_DOMAIN_REFERENCE_SPEC: Dict[str, set[str]] = {
    "integer_fields": {"domain_filter_table"},
}

_FTGD_DNS_SPEC: Dict[str, set[str]] = {
    "list_fields": {"options"},
}

_CATEGORY_SPEC: Dict[str, set[str]] = {
    "scalar_fields": {"action", "log"},
    "integer_fields": {"category"},
}

_BOTNET_SPEC: Dict[str, set[str]] = {
    "scalar_fields": {"block_botnet"},
}


def _declared_typed_values(settings: Dict[str, Any], model: Any) -> Dict[str, Any]:
    """Project only fields explicitly declared by this FortiOS schema."""

    values = phase41._typed_values(settings, model)
    spec = phase41.PROFILE_FIELD_SPECS.get(model)
    if not spec:
        return values
    declared: set[str] = set()
    for category in (
        "scalar_fields",
        "list_fields",
        "integer_fields",
        "integer_list_fields",
    ):
        declared.update(spec.get(category, set()))
    return {key: value for key, value in values.items() if key in declared}


def _settings(source: FGSourceNode, model: Any) -> tuple[Dict[str, Any], Dict[str, Any]]:
    return phase41._effective_profile_settings(source, model)


def _build_dnsfilter_profiles(
    parser: Any,
    collection_name: str,
    top_edits: List[FGSourceNode],
) -> None:
    for node in top_edits:
        profile_settings, profile_extra = _settings(node, FGDNSFilterProfile746)
        profile = FGDNSFilterProfile746(
            name=node.name,
            **_declared_typed_values(profile_settings, FGDNSFilterProfile746),
        )
        profile.extra_settings = profile_extra

        botnet_values = {
            key: profile_settings[key]
            for key in ("block_botnet",)
            if key in profile_settings
        }
        if botnet_values:
            profile.botnet.append(
                FGDNSFilterBotnet746(
                    settings=dict(botnet_values),
                    **botnet_values,
                )
            )

        for child in node.children:
            if child.node_type != "config":
                continue
            child_name = child.name.lower().replace("-", "_")

            if child_name == "domain_filter":
                settings, extra = _settings(child, FGDNSFilterDomainReference746)
                profile.domain_filters.append(
                    FGDNSFilterDomainReference746(
                        name=child.name,
                        settings=settings,
                        extra_settings=extra,
                        **_declared_typed_values(settings, FGDNSFilterDomainReference746),
                    )
                )
                continue

            if child_name == "ftgd_dns":
                settings, extra = _settings(child, FGDNSFilterFortiGuard746)
                ftgd = FGDNSFilterFortiGuard746(
                    settings=settings,
                    extra_settings=extra,
                    **_declared_typed_values(settings, FGDNSFilterFortiGuard746),
                )
                for nested in child.children:
                    if nested.node_type != "config":
                        continue
                    nested_name = nested.name.lower().replace("-", "_")
                    if nested_name != "filters":
                        profile.entries.append(phase41._typed_profile_node(nested))
                        continue
                    for projection in phase41._effective_nested_profile_edits(
                        nested,
                        FGDNSFilterCategory746,
                    ):
                        category = FGDNSFilterCategory746(
                            name=projection["name"],
                            source_order=projection["source_order"],
                            settings=projection["settings"],
                            extra_settings=projection["extra_settings"],
                            **_declared_typed_values(
                                projection["settings"], FGDNSFilterCategory746
                            ),
                        )
                        ftgd.categories.append(category)
                        profile.categories.append(category)
                profile.ftgd_dns = ftgd
                continue

            # DNS translation and future child sections remain source-preserved
            # until explicitly typed; they are never guessed into category/domain
            # or botnet buckets.
            profile.entries.append(phase41._typed_profile_node(child))

        getattr(parser.config, collection_name).append(profile)


def install_phase_44_dnsfilter_support(parser_module: Any) -> None:
    """Install Phase 44 DNS Filter typing on top of Phases 41-43."""

    phase41.PROFILE_FIELD_SPECS[FGDNSFilterProfile746] = _DNS_PROFILE_SPEC
    phase41.PROFILE_FIELD_SPECS[FGDNSFilterDomainReference746] = _DOMAIN_REFERENCE_SPEC
    phase41.PROFILE_FIELD_SPECS[FGDNSFilterFortiGuard746] = _FTGD_DNS_SPEC
    phase41.PROFILE_FIELD_SPECS[FGDNSFilterCategory746] = _CATEGORY_SPEC
    phase41.PROFILE_FIELD_SPECS[FGDNSFilterBotnet746] = _BOTNET_SPEC

    phase41.FGDNSFilterProfile = FGDNSFilterProfile746
    phase41.FGDNSFilterCategory = FGDNSFilterCategory746
    phase41._PROFILE_PATHS["dnsfilter profile"] = (
        "dnsfilter_profiles",
        FGDNSFilterProfile746,
    )

    original_builder = phase41._build_dns_app_ssl
    if not getattr(original_builder, "_phase_44_wrapped", False):
        def build_dns_app_ssl(
            parser: Any,
            source_path: str,
            collection_name: str,
            model: Any,
            top_edits: List[FGSourceNode],
        ) -> None:
            if model is FGDNSFilterProfile746:
                _build_dnsfilter_profiles(parser, collection_name, top_edits)
                return
            original_builder(parser, source_path, collection_name, model, top_edits)

        build_dns_app_ssl._phase_44_wrapped = True
        phase41._build_dns_app_ssl = build_dns_app_ssl

    parser_module.FGConfig = FGConfigDNS746
    parser_module.FGDNSFilterProfile = FGDNSFilterProfile746
    parser_module.FGDNSFilterCategory = FGDNSFilterCategory746
    parser_module.PROFILE_FIELD_SPECS = phase41.PROFILE_FIELD_SPECS
