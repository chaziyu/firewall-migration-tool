"""FortiGate DNS-filter profile typing.

Extends the Phase 41 shared operation-aware evaluator with explicit FortiOS
7.4.6 DNS-filter hierarchy and field declarations. Structured source nodes
remain authoritative and unchanged.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from fwmigrate.parsers.fortigate.builders import security_profiles as phase41
from fwmigrate.parsers.fortigate.builders.webfilter import FGConfigWeb746 as _FGConfigWeb746
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


def _declared_typed_values(
    settings: Dict[str, Any],
    model: Any,
    field_spec: Dict[str, set[str]],
) -> Dict[str, Any]:
    """Project only fields explicitly declared by this FortiOS schema."""

    return phase41._typed_values(settings, model, field_spec=field_spec)


def _settings(
    source: FGSourceNode,
    model: Any,
    field_spec: Dict[str, set[str]],
) -> tuple[Dict[str, Any], Dict[str, Any]]:
    return phase41._effective_profile_settings(source, model, field_spec=field_spec)


def _build_dnsfilter_profiles(
    parser: Any,
    collection_name: str,
    top_edits: List[FGSourceNode],
) -> None:
    for node in top_edits:
        profile_settings, profile_extra = _settings(
            node,
            FGDNSFilterProfile746,
            _DNS_PROFILE_SPEC,
        )
        profile = FGDNSFilterProfile746(
            name=node.name,
            source_context=parser.current_context or "root",
            **_declared_typed_values(
                profile_settings,
                FGDNSFilterProfile746,
                _DNS_PROFILE_SPEC,
            ),
        )
        profile.extra_settings = profile_extra

        botnet_values = phase41._typed_values(
            profile_settings,
            FGDNSFilterBotnet746,
            field_spec=_BOTNET_SPEC,
        )
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
                settings, extra = _settings(
                    child,
                    FGDNSFilterDomainReference746,
                    _DOMAIN_REFERENCE_SPEC,
                )
                profile.domain_filters.append(
                    FGDNSFilterDomainReference746(
                        name=child.name,
                        settings=settings,
                        extra_settings=extra,
                        **_declared_typed_values(
                            settings,
                            FGDNSFilterDomainReference746,
                            _DOMAIN_REFERENCE_SPEC,
                        ),
                    )
                )
                continue

            if child_name == "ftgd_dns":
                settings, extra = _settings(
                    child,
                    FGDNSFilterFortiGuard746,
                    _FTGD_DNS_SPEC,
                )
                ftgd = FGDNSFilterFortiGuard746(
                    settings=settings,
                    extra_settings=extra,
                    **_declared_typed_values(
                        settings,
                        FGDNSFilterFortiGuard746,
                        _FTGD_DNS_SPEC,
                    ),
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
                        field_spec=_CATEGORY_SPEC,
                    ):
                        category = FGDNSFilterCategory746(
                            name=projection["name"],
                            source_order=projection["source_order"],
                            settings=projection["settings"],
                            extra_settings=projection["extra_settings"],
                            **_declared_typed_values(
                                projection["settings"],
                                FGDNSFilterCategory746,
                                _CATEGORY_SPEC,
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


