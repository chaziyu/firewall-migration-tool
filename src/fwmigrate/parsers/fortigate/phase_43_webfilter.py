"""Phase 43 FortiGate web-filter profile typing.

Extends the Phase 41 shared operation-aware evaluator with explicit FortiOS
7.4.6 web-filter profile hierarchy and field declarations. Structured source
nodes remain authoritative and unchanged.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from fwmigrate.parsers.fortigate import phase_41_security_profiles as phase41
from fwmigrate.parsers.fortigate.phase_42_antivirus import FGConfig746 as _FGConfig746
from fwmigrate.parsers.fortigate.model import (
    FGWebFilterCategory as _FGWebFilterCategory,
    FGWebFilterOverride as _FGWebFilterOverride,
    FGWebFilterProfile as _FGWebFilterProfile,
)
from fwmigrate.parsers.fortigate.source_tree import FGSourceNode


class FGWebFilterCategory746(_FGWebFilterCategory):
    """FortiGuard category filter entry under ``config ftgd-wf filters``."""

    category: Optional[int] = None
    auth_usr_grp: List[str] = Field(default_factory=list)
    override_replacemsg: Optional[str] = None
    warn_duration: Optional[str] = None
    warning_duration_type: Optional[str] = None
    warning_prompt: Optional[str] = None
    source_order: int = 0


class FGWebFilterQuota746(BaseModel):
    """FortiGuard quota entry retained distinctly and in source order."""

    name: str
    category: Optional[str] = None
    duration: Optional[str] = None
    override_replacemsg: Optional[str] = None
    type: Optional[str] = None
    unit: Optional[str] = None
    value: Optional[int] = None
    source_order: int = 0
    settings: Dict[str, Any] = Field(default_factory=dict)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGWebFilterFortiGuard746(BaseModel):
    """Direct ``config ftgd-wf`` settings plus ordered filters/quotas."""

    exempt_quota: Optional[str] = None
    max_quota_timeout: Optional[int] = None
    options: List[str] = Field(default_factory=list)
    ovrd: Optional[str] = None
    rate_crl_urls: Optional[str] = None
    rate_css_urls: Optional[str] = None
    rate_javascript_urls: Optional[str] = None
    filters: List[FGWebFilterCategory746] = Field(default_factory=list)
    quotas: List[FGWebFilterQuota746] = Field(default_factory=list)
    settings: Dict[str, Any] = Field(default_factory=dict)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGWebFilterOverride746(_FGWebFilterOverride):
    """Direct ``config override`` settings; referenced profiles stay names."""

    ovrd_cookie: Optional[str] = None
    ovrd_dur: Optional[str] = None
    ovrd_dur_mode: Optional[str] = None
    ovrd_scope: Optional[str] = None
    ovrd_user_group: List[str] = Field(default_factory=list)
    profile: List[str] = Field(default_factory=list)
    profile_attribute: Optional[str] = None
    profile_type: Optional[str] = None
    source_order: int = 0


class FGWebFilterWeb746(BaseModel):
    """Direct ``config web`` settings; URL filter is retained as an ID reference."""

    name: str = "web"
    allowlist: List[str] = Field(default_factory=list)
    blocklist: Optional[str] = None
    bword_table: Optional[int] = None
    bword_threshold: Optional[int] = None
    content_header_list: Optional[int] = None
    keyword_match: List[str] = Field(default_factory=list)
    log_search: Optional[str] = None
    safe_search: List[str] = Field(default_factory=list)
    urlfilter_table: Optional[int] = None
    vimeo_restrict: Optional[str] = None
    youtube_restrict: Optional[str] = None
    settings: Dict[str, Any] = Field(default_factory=dict)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGWebFilterProfile746(_FGWebFilterProfile):
    """FortiOS 7.4.6 web-filter profile typed projection."""

    extended_log: Optional[str] = None
    feature_set: Optional[str] = None
    https_replacemsg: Optional[str] = None
    log_all_url: Optional[str] = None
    options: List[str] = Field(default_factory=list)
    ovrd_perm: List[str] = Field(default_factory=list)
    post_action: Optional[str] = None
    replacemsg_group: Optional[str] = None
    web_antiphishing_log: Optional[str] = None
    web_content_log: Optional[str] = None
    web_extended_all_action_log: Optional[str] = None
    web_filter_activex_log: Optional[str] = None
    web_filter_applet_log: Optional[str] = None
    web_filter_command_block_log: Optional[str] = None
    web_filter_cookie_log: Optional[str] = None
    web_filter_cookie_removal_log: Optional[str] = None
    web_filter_js_log: Optional[str] = None
    web_filter_jscript_log: Optional[str] = None
    web_filter_referer_log: Optional[str] = None
    web_filter_unknown_log: Optional[str] = None
    web_filter_vbs_log: Optional[str] = None
    web_flow_log_encoding: Optional[str] = None
    web_ftgd_err_log: Optional[str] = None
    web_ftgd_quota_usage: Optional[str] = None
    web_invalid_domain_log: Optional[str] = None
    web_url_log: Optional[str] = None
    wisp: Optional[str] = None
    wisp_algorithm: Optional[str] = None
    wisp_servers: List[str] = Field(default_factory=list)
    ftgd_wf: Optional[FGWebFilterFortiGuard746] = None
    overrides: List[FGWebFilterOverride746] = Field(default_factory=list)
    url_filters: List[FGWebFilterWeb746] = Field(default_factory=list)
    categories: List[FGWebFilterCategory746] = Field(default_factory=list)


class FGConfigWeb746(_FGConfig746):
    """Root config retaining Phase 42 AV and Phase 43 web-filter fields."""

    webfilter_profiles: List[FGWebFilterProfile746] = Field(default_factory=list)


_WEB_PROFILE_SPEC: Dict[str, set[str]] = {
    "scalar_fields": {
        "comment", "extended_log", "feature_set", "https_replacemsg",
        "log_all_url", "post_action", "replacemsg_group",
        "web_antiphishing_log", "web_content_log", "web_extended_all_action_log",
        "web_filter_activex_log", "web_filter_applet_log",
        "web_filter_command_block_log", "web_filter_cookie_log",
        "web_filter_cookie_removal_log", "web_filter_js_log",
        "web_filter_jscript_log", "web_filter_referer_log",
        "web_filter_unknown_log", "web_filter_vbs_log", "web_flow_log_encoding",
        "web_ftgd_err_log", "web_ftgd_quota_usage", "web_invalid_domain_log",
        "web_url_log", "wisp", "wisp_algorithm",
    },
    "list_fields": {"options", "ovrd_perm", "wisp_servers"},
}

_FTGD_SPEC: Dict[str, set[str]] = {
    "scalar_fields": {
        "exempt_quota", "ovrd", "rate_crl_urls", "rate_css_urls",
        "rate_javascript_urls",
    },
    "list_fields": {"options"},
    "integer_fields": {"max_quota_timeout"},
}

_CATEGORY_SPEC: Dict[str, set[str]] = {
    "scalar_fields": {
        "action", "log", "override_replacemsg", "warn_duration",
        "warning_duration_type", "warning_prompt",
    },
    "list_fields": {"auth_usr_grp"},
    "integer_fields": {"category"},
}

_QUOTA_SPEC: Dict[str, set[str]] = {
    "scalar_fields": {"category", "duration", "override_replacemsg", "type", "unit"},
    "integer_fields": {"value"},
}

_OVERRIDE_SPEC: Dict[str, set[str]] = {
    "scalar_fields": {
        "ovrd_cookie", "ovrd_dur", "ovrd_dur_mode", "ovrd_scope",
        "profile_attribute", "profile_type",
    },
    "list_fields": {"ovrd_user_group", "profile"},
}

_WEB_SPEC: Dict[str, set[str]] = {
    "scalar_fields": {"blocklist", "log_search", "vimeo_restrict", "youtube_restrict"},
    "list_fields": {"allowlist", "keyword_match", "safe_search"},
    "integer_fields": {"bword_table", "bword_threshold", "content_header_list", "urlfilter_table"},
}

_TYPED_FIELD_KINDS = (
    "scalar_fields",
    "list_fields",
    "integer_fields",
    "integer_list_fields",
)


def _section_settings(source: FGSourceNode, model: Any) -> tuple[Dict[str, Any], Dict[str, Any]]:
    return phase41._effective_profile_settings(source, model)


def _declared_typed_values(settings: Dict[str, Any], model: Any) -> Dict[str, Any]:
    """Project only fields explicitly declared for this FortiOS 7.4.6 model.

    Several Phase 43 models inherit legacy compatibility fields. Undocumented
    source keys must remain source-preserved instead of being promoted merely
    because an inherited Pydantic field happens to share the same name.
    """

    field_spec = phase41.PROFILE_FIELD_SPECS.get(model, {})
    declared: set[str] = set()
    for kind in _TYPED_FIELD_KINDS:
        declared.update(field_spec.get(kind, set()))
    return {
        key: value
        for key, value in settings.items()
        if key in declared
        and key in model.model_fields
        and key not in {"name", "settings", "extra_settings"}
    }


def _build_webfilter_profiles(
    parser: Any,
    collection_name: str,
    top_edits: List[FGSourceNode],
) -> None:
    for node in top_edits:
        profile_settings, profile_extra = _section_settings(node, FGWebFilterProfile746)
        profile = FGWebFilterProfile746(
            name=node.name,
            **_declared_typed_values(profile_settings, FGWebFilterProfile746),
        )
        profile.extra_settings = profile_extra

        for child in node.children:
            if child.node_type != "config":
                continue
            child_name = child.name.lower().replace("-", "_")

            if child_name == "ftgd_wf":
                settings, extra = _section_settings(child, FGWebFilterFortiGuard746)
                ftgd = FGWebFilterFortiGuard746(
                    settings=settings,
                    extra_settings=extra,
                    **_declared_typed_values(settings, FGWebFilterFortiGuard746),
                )
                for nested in child.children:
                    if nested.node_type != "config":
                        continue
                    nested_name = nested.name.lower().replace("-", "_")
                    if nested_name == "filters":
                        for projection in phase41._effective_nested_profile_edits(
                            nested, FGWebFilterCategory746
                        ):
                            category = FGWebFilterCategory746(
                                name=projection["name"],
                                source_order=projection["source_order"],
                                settings=projection["settings"],
                                extra_settings=projection["extra_settings"],
                                **_declared_typed_values(
                                    projection["settings"], FGWebFilterCategory746
                                ),
                            )
                            ftgd.filters.append(category)
                            profile.categories.append(category)
                    elif nested_name == "quota":
                        for projection in phase41._effective_nested_profile_edits(
                            nested, FGWebFilterQuota746
                        ):
                            ftgd.quotas.append(
                                FGWebFilterQuota746(
                                    name=projection["name"],
                                    source_order=projection["source_order"],
                                    settings=projection["settings"],
                                    extra_settings=projection["extra_settings"],
                                    **_declared_typed_values(
                                        projection["settings"], FGWebFilterQuota746
                                    ),
                                )
                            )
                profile.ftgd_wf = ftgd
                continue

            if child_name == "override":
                settings, extra = _section_settings(child, FGWebFilterOverride746)
                profile.overrides.append(
                    FGWebFilterOverride746(
                        name=child.name,
                        source_order=len(profile.overrides) + 1,
                        settings=settings,
                        extra_settings=extra,
                        **_declared_typed_values(settings, FGWebFilterOverride746),
                    )
                )
                continue

            if child_name == "web":
                settings, extra = _section_settings(child, FGWebFilterWeb746)
                profile.url_filters.append(
                    FGWebFilterWeb746(
                        name=child.name,
                        settings=settings,
                        extra_settings=extra,
                        **_declared_typed_values(settings, FGWebFilterWeb746),
                    )
                )
                continue

            # Other documented profile child sections (for example antiphish)
            # remain source-preserved until their dedicated typed scope is added.
            profile.entries.append(phase41._typed_profile_node(child))

        getattr(parser.config, collection_name).append(profile)


def install_phase_43_webfilter_support(parser_module: Any) -> None:
    """Install Phase 43 Web Filter typing on top of Phases 41 and 42."""

    phase41.PROFILE_FIELD_SPECS[FGWebFilterProfile746] = _WEB_PROFILE_SPEC
    phase41.PROFILE_FIELD_SPECS[FGWebFilterFortiGuard746] = _FTGD_SPEC
    phase41.PROFILE_FIELD_SPECS[FGWebFilterCategory746] = _CATEGORY_SPEC
    phase41.PROFILE_FIELD_SPECS[FGWebFilterQuota746] = _QUOTA_SPEC
    phase41.PROFILE_FIELD_SPECS[FGWebFilterOverride746] = _OVERRIDE_SPEC
    phase41.PROFILE_FIELD_SPECS[FGWebFilterWeb746] = _WEB_SPEC

    phase41.FGWebFilterProfile = FGWebFilterProfile746
    phase41.FGWebFilterCategory = FGWebFilterCategory746
    phase41.FGWebFilterOverride = FGWebFilterOverride746
    phase41._PROFILE_PATHS["webfilter profile"] = (
        "webfilter_profiles",
        FGWebFilterProfile746,
    )

    original_builder = phase41._build_antivirus_or_webfilter
    if not getattr(original_builder, "_phase_43_wrapped", False):
        def build_antivirus_or_webfilter(
            parser: Any,
            source_path: str,
            collection_name: str,
            model: Any,
            top_edits: List[FGSourceNode],
        ) -> None:
            if model is FGWebFilterProfile746:
                _build_webfilter_profiles(parser, collection_name, top_edits)
                return
            original_builder(parser, source_path, collection_name, model, top_edits)

        build_antivirus_or_webfilter._phase_43_wrapped = True
        phase41._build_antivirus_or_webfilter = build_antivirus_or_webfilter

    parser_module.FGConfig = FGConfigWeb746
    parser_module.FGWebFilterProfile = FGWebFilterProfile746
    parser_module.FGWebFilterCategory = FGWebFilterCategory746
    parser_module.FGWebFilterOverride = FGWebFilterOverride746
    parser_module.PROFILE_FIELD_SPECS = phase41.PROFILE_FIELD_SPECS
