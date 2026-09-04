"""Check Point access rule extraction with conservative semantic gates."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Mapping, Optional, Tuple

from pydantic import BaseModel, Field

from fwmigrate.extraction.models import ExtractionStatus, SourceInventoryItem, UnsupportedItem
from fwmigrate.ir.core import IRPolicy
from fwmigrate.parsers.checkpoint.loader import canonicalize_command
from fwmigrate.parsers.checkpoint.models import CheckPointResponse, RulebaseSafetyState, ScopeSelectionResult
from fwmigrate.parsers.checkpoint.resolver import CheckPointObjectResolver, SemanticKind
from fwmigrate.parsers.checkpoint.rulebase import flatten_rulebase, parse_required_bool

RulebaseKey = Tuple[str, Optional[str], Optional[str], Optional[str], Optional[str]]


class AddressDimensionResolution(BaseModel):
    zones: List[str] = Field(default_factory=list)
    addresses: List[str] = Field(default_factory=list)
    explicit_any: bool = False
    unresolved: List[str] = Field(default_factory=list)
    unsafe_refs: List[str] = Field(default_factory=list)
    mixed_zone_address: bool = False
    access_roles: List[str] = Field(default_factory=list)


class ServiceDimensionResolution(BaseModel):
    services: List[str] = Field(default_factory=list)
    applications: List[str] = Field(default_factory=list)
    explicit_any: bool = False
    unresolved: List[str] = Field(default_factory=list)
    unsafe_refs: List[str] = Field(default_factory=list)
    mixed_service_application: bool = False


class InstallOnResolution(BaseModel):
    eligible: Optional[bool] = True
    reasons: List[str] = Field(default_factory=list)


class VPNDimensionResolution(BaseModel):
    unconstrained: bool = False
    communities: List[str] = Field(default_factory=list)
    unresolved: List[str] = Field(default_factory=list)
    unsafe_refs: List[str] = Field(default_factory=list)


class TimeDimensionResolution(BaseModel):
    schedules: List[str] = Field(default_factory=list)
    explicit_any: bool = False
    unresolved: List[str] = Field(default_factory=list)
    unsafe_refs: List[str] = Field(default_factory=list)
    multiple_constraints: bool = False


class ContentDimensionResolution(BaseModel):
    explicit_any: bool = False
    content: List[str] = Field(default_factory=list)
    unresolved: List[str] = Field(default_factory=list)
    negate: bool = False
    direction: Optional[str] = None


class TrackResolution(BaseModel):
    source_type: Optional[str] = None
    log_start: Optional[bool] = None
    log_end: Optional[bool] = None
    unresolved: Optional[str] = None
    review_reasons: List[str] = Field(default_factory=list)


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _ref_label(ref: Any, resolved_name: Optional[str] = None) -> str:
    if resolved_name:
        return resolved_name
    if isinstance(ref, dict):
        return str(ref.get("uid") or ref.get("name") or ref)
    return str(ref)


def _inline_layer_reference(rule: Dict[str, Any]) -> Any:
    return (
        rule.get("inline-layer")
        or rule.get("inline_layer")
        or rule.get("inlineLayer")
    )


def _collect_inline_layer_parents(
    responses: List[CheckPointResponse],
    resolver: CheckPointObjectResolver,
) -> Dict[str, Dict[str, Any]]:
    """Index inline layer UIDs/names so separately supplied child layers remain gated."""
    parents: Dict[str, Dict[str, Any]] = {}
    for response in responses:
        if canonicalize_command(response.command) != "show-access-rulebase":
            continue
        for rule, section_title in flatten_rulebase(response.data.get("rulebase", [])):
            ref = _inline_layer_reference(rule)
            if ref is None:
                continue
            resolution = resolver.resolve(ref, domain=response.domain)
            provenance = {
                "uid": resolution.uid or (ref.get("uid") if isinstance(ref, dict) else None),
                "name": resolution.name or (ref.get("name") if isinstance(ref, dict) else None),
                "parent-rule-uid": rule.get("uid"),
                "parent-rule-number": rule.get("rule-number"),
                "section-path": section_title or None,
                "package": response.package,
                "layer": response.layer,
                "domain": response.domain,
            }
            keys = [provenance["uid"], provenance["name"]]
            if isinstance(ref, str):
                keys.append(ref)
            for key in keys:
                if key:
                    parents[str(key)] = provenance
    return parents


def classify_address_dimension(
    refs: List[Any], resolver: CheckPointObjectResolver, domain: Optional[str]
) -> AddressDimensionResolution:
    """Classify Check Point OR-list address semantics without converting them to IR AND semantics."""
    result = AddressDimensionResolution()
    for ref in refs:
        res = resolver.resolve(ref, domain=domain, allow_special_symbolic_names=True)
        label = _ref_label(ref, res.name)
        if res.semantic_kind == SemanticKind.SPECIAL_ANY:
            result.explicit_any = True
        elif res.semantic_kind == SemanticKind.SECURITY_ZONE and res.canonical_name:
            result.zones.append(res.canonical_name)
            if not resolver.is_dependency_safe(ref, domain=domain):
                result.unsafe_refs.append(label)
        elif res.semantic_kind == SemanticKind.ACCESS_ROLE and res.canonical_name:
            result.access_roles.append(res.canonical_name)
            if not resolver.is_dependency_safe(ref, domain=domain):
                result.unsafe_refs.append(label)
        elif res.semantic_kind in (SemanticKind.ADDRESS, SemanticKind.ADDRESS_GROUP) and res.canonical_names:
            result.addresses.extend(res.canonical_names)
            if any(name.strip().lower() in {"any", "original"} for name in res.canonical_names):
                result.unsafe_refs.append(f"reserved-special-name-collision:{label}")
            if not resolver.is_dependency_safe(ref, domain=domain):
                result.unsafe_refs.append(label)
        elif not res.resolved:
            result.unresolved.append(_ref_label(ref, res.uid or res.name))
        else:
            result.unsafe_refs.append(label)

    result.mixed_zone_address = bool(result.zones and result.addresses)
    if result.explicit_any and (result.zones or result.addresses):
        result.unsafe_refs.append("any-with-other-address-match")
    return result


def classify_service_dimension(
    refs: List[Any], resolver: CheckPointObjectResolver, domain: Optional[str]
) -> ServiceDimensionResolution:
    """Separate network services from application semantics in the Check Point OR-list."""
    result = ServiceDimensionResolution()
    application_kinds = {
        SemanticKind.APPLICATION,
        SemanticKind.APPLICATION_GROUP,
        SemanticKind.APPLICATION_CATEGORY,
        SemanticKind.SITE,
    }
    for ref in refs:
        res = resolver.resolve(ref, domain=domain, allow_special_symbolic_names=True)
        label = _ref_label(ref, res.name)
        if res.semantic_kind == SemanticKind.SPECIAL_ANY:
            result.explicit_any = True
        elif res.semantic_kind in (SemanticKind.SERVICE, SemanticKind.SERVICE_GROUP) and res.canonical_name:
            result.services.append(res.canonical_name)
            if res.canonical_name.strip().lower() in {"any", "original"}:
                result.unsafe_refs.append(f"reserved-special-name-collision:{label}")
            if not resolver.is_dependency_safe(ref, domain=domain):
                result.unsafe_refs.append(label)
        elif res.semantic_kind in application_kinds and res.canonical_name:
            result.applications.append(res.canonical_name)
            if not resolver.is_dependency_safe(ref, domain=domain):
                result.unsafe_refs.append(label)
        elif not res.resolved:
            result.unresolved.append(_ref_label(ref, res.uid or res.name))
        else:
            result.unsafe_refs.append(label)

    result.mixed_service_application = bool(result.services and result.applications)
    if result.explicit_any and (result.services or result.applications):
        result.unsafe_refs.append("any-with-other-service-match")
    return result


def classify_vpn_dimension(
    raw_vpn: Any,
    resolver: CheckPointObjectResolver,
    domain: Optional[str],
) -> VPNDimensionResolution:
    """Classify the Access VPN match without erasing nonportable constraints."""
    result = VPNDimensionResolution()
    if raw_vpn is None:
        result.unresolved.append("<missing>")
        return result

    refs = _as_list(raw_vpn)
    if not refs:
        result.unresolved.append("<empty>")
        return result

    for ref in refs:
        resolution = resolver.resolve(
            ref,
            domain=domain,
            allow_special_symbolic_names=True,
        )
        label = _ref_label(ref, resolution.name)
        if resolution.semantic_kind == SemanticKind.SPECIAL_ANY:
            result.unconstrained = True
        elif resolution.semantic_kind == SemanticKind.VPN_COMMUNITY:
            result.communities.append(label)
        elif not resolution.resolved:
            result.unresolved.append(_ref_label(ref, resolution.uid or resolution.name))
        else:
            result.unsafe_refs.append(label)

    if result.unconstrained and (result.communities or result.unsafe_refs):
        result.unsafe_refs.append("any-with-other-vpn-match")
    return result


def classify_time_dimension(
    raw_time: Any,
    resolver: CheckPointObjectResolver,
    domain: Optional[str],
    _visited: Optional[set[str]] = None,
) -> TimeDimensionResolution:
    """Classify the list-valued Access Time column without collapsing OR semantics."""
    result = TimeDimensionResolution()
    visited = _visited or set()
    if raw_time is None:
        result.unresolved.append("<missing>")
        return result
    refs = raw_time if isinstance(raw_time, list) else [raw_time]
    if not refs:
        result.unresolved.append("<empty>")
        return result
    for ref in refs:
        resolution = resolver.resolve(ref, domain=domain, allow_special_symbolic_names=True)
        label = _ref_label(ref, resolution.name)
        ref_id = resolution.uid or resolution.name or label
        if ref_id in visited:
            result.unsafe_refs.append(label)
            continue
        next_visited = visited | {ref_id}
        if resolution.semantic_kind == SemanticKind.SPECIAL_ANY:
            result.explicit_any = True
        elif resolution.semantic_kind == SemanticKind.TIME and resolution.canonical_name:
            result.schedules.append(resolution.canonical_name)
            if not resolver.is_dependency_safe(ref, domain=domain):
                result.unsafe_refs.append(label)
        elif resolution.semantic_kind == SemanticKind.TIME_GROUP and resolution.source_object:
            members = resolution.source_object.get("members", [])
            if not members:
                result.unsafe_refs.append(label)
                continue
            nested = classify_time_dimension(members, resolver, domain, next_visited)
            result.schedules.extend(nested.schedules)
            result.unresolved.extend(nested.unresolved)
            result.unsafe_refs.extend(nested.unsafe_refs)
        elif not resolution.resolved:
            result.unresolved.append(_ref_label(ref, resolution.uid or resolution.name))
        else:
            result.unsafe_refs.append(label)
    result.multiple_constraints = len(result.schedules) > 1
    if result.explicit_any and (result.schedules or result.unsafe_refs):
        result.unsafe_refs.append("any-with-other-time-match")
    return result


def classify_content_dimension(
    rule: Dict[str, Any],
    resolver: CheckPointObjectResolver,
    domain: Optional[str],
) -> ContentDimensionResolution:
    """Classify Content Awareness constraints that are not represented in IRPolicy."""
    result = ContentDimensionResolution(
        negate=rule.get("content-negate") is True,
        direction=str(rule.get("content-direction")).strip() if rule.get("content-direction") is not None else None,
    )
    if "content" not in rule:
        return result
    for ref in _as_list(rule.get("content")):
        resolution = resolver.resolve(ref, domain=domain, allow_special_symbolic_names=True)
        label = _ref_label(ref, resolution.name)
        if resolution.semantic_kind == SemanticKind.SPECIAL_ANY:
            result.explicit_any = True
        elif not resolution.resolved:
            result.unresolved.append(_ref_label(ref, resolution.uid or resolution.name))
        else:
            result.content.append(label)
    return result


def resolve_track(
    raw_track: Any,
    resolver: CheckPointObjectResolver,
    domain: Optional[str],
) -> TrackResolution:
    """Resolve Track.type UIDs and preserve richer Check Point logging behavior."""
    if raw_track is None:
        return TrackResolution()
    track = raw_track if isinstance(raw_track, dict) else {"type": raw_track}
    type_ref = track.get("type") if "type" in track else track.get("name")
    resolution = resolver.resolve(type_ref, domain=domain)
    source_type = resolution.name if resolution.resolved and resolution.name else (
        type_ref.get("name") if isinstance(type_ref, dict) else str(type_ref or "")
    )
    normalized = source_type.strip().lower()
    result = TrackResolution(source_type=source_type or None)
    if not resolution.resolved and normalized not in {"none", "log", "extended log", "detailed log"}:
        result.unresolved = _ref_label(type_ref)
        result.review_reasons.append(f"unresolved-track:{result.unresolved}")
    elif normalized == "none":
        result.log_start = False
        result.log_end = False
    elif normalized in {"log", "extended log", "detailed log"}:
        result.log_end = True
        result.log_start = False
    elif normalized:
        result.review_reasons.append(f"unsupported-track-type:{source_type}")
    for key in (
        "accounting", "alert", "per-connection", "per-session",
        "enable-firewall-session", "enable-firewall-session-logging",
    ):
        if key in track and track.get(key) not in (None, False, "none", "None"):
            result.review_reasons.append(f"checkpoint-track-{key}")
    return result


def resolve_install_on(
    rule: Dict[str, Any], resolver: CheckPointObjectResolver, selected_gateway: Optional[str], domain: Optional[str]
) -> InstallOnResolution:
    """Resolve Check Point Install On constraints for the selected migration gateway."""
    raw = rule.get("install-on", rule.get("install_on"))
    refs = _as_list(raw)
    if not refs:
        return InstallOnResolution()

    if not selected_gateway:
        return InstallOnResolution(eligible=None, reasons=["install-on-without-selected-gateway"])

    explicit_targets: List[str] = []
    unresolved_policy_targets = False
    for ref in refs:
        explicit_name = str(ref.get("name", "")).strip() if isinstance(ref, dict) else str(ref).strip()
        if explicit_name == selected_gateway:
            explicit_targets.append(explicit_name)
            continue
        early_resolution = resolver.resolve(ref, domain=domain)
        if early_resolution.resolved and early_resolution.name and early_resolution.semantic_kind == SemanticKind.INSTALL_TARGET:
            explicit_targets.append(early_resolution.name)
            continue
        looks_like_uid = bool(re.fullmatch(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            explicit_name,
        ))
        if (
            explicit_name
            and explicit_name.lower() != "policy targets"
            and not looks_like_uid
            and not (isinstance(ref, dict) and ref.get("uid") and not ref.get("name"))
        ):
            explicit_targets.append(explicit_name)
            continue
        res = early_resolution
        name = (res.name or (ref.get("name") if isinstance(ref, dict) else str(ref))).strip()
        if name.lower() == "policy targets":
            members = (res.source_object or {}).get("members") or (res.source_object or {}).get("targets")
            if not members:
                unresolved_policy_targets = True
                continue
            for member in _as_list(members):
                member_res = resolver.resolve(member, domain=domain)
                if member_res.resolved and member_res.name:
                    explicit_targets.append(member_res.name)
                else:
                    unresolved_policy_targets = True
        elif res.resolved and res.name:
            explicit_targets.append(res.name)
        else:
            unresolved_policy_targets = True

    if selected_gateway in explicit_targets:
        return InstallOnResolution(eligible=True)
    if unresolved_policy_targets:
        return InstallOnResolution(eligible=None, reasons=["unresolved-install-on"])
    return InstallOnResolution(eligible=False, reasons=["gateway-not-targeted"])


def extract_access_rulebase(
    responses: List[CheckPointResponse],
    resolver: CheckPointObjectResolver,
    scope: ScopeSelectionResult,
    safety_map: Optional[Mapping[RulebaseKey, RulebaseSafetyState]] = None,
) -> Tuple[List[IRPolicy], List[SourceInventoryItem], List[UnsupportedItem]]:
    """Extract only semantically faithful rules; retain every source rule in inventory."""
    policies: List[IRPolicy] = []
    inventory_items: List[SourceInventoryItem] = []
    unsupported_items: List[UnsupportedItem] = []
    inline_layer_parents = _collect_inline_layer_parents(responses, resolver)

    ordered_responses = sorted(
        responses,
        key=lambda response: (
            response.domain or "", response.package or "", response.layer or "",
            response.gateway or "", response.from_index if response.from_index is not None else 0,
        ),
    )
    for resp in ordered_responses:
        cmd = canonicalize_command(resp.command)
        if cmd != "show-access-rulebase":
            continue

        package = resp.package
        layer = resp.layer
        domain = resp.domain or "global"
        path_package = package or "<missing-package>"
        path_layer = layer or "<missing-layer>"
        src_path = f"checkpoint/{cmd}/{path_package}/{path_layer}"
        key: RulebaseKey = (cmd, resp.domain, resp.package, resp.layer, resp.gateway)
        rulebase_state = safety_map.get(key) if safety_map else None
        response_inline_context = next(
            (
                inline_layer_parents[str(candidate)]
                for candidate in (resp.layer, resp.data.get("uid"), resp.data.get("name"))
                if candidate is not None and str(candidate) in inline_layer_parents
            ),
            None,
        )

        scope_block_reasons: List[str] = []
        ignored_scope_reasons: List[str] = []
        if scope.ambiguous:
            scope_block_reasons = ["scope-selection-required", *scope.reasons]
        if package is None:
            scope_block_reasons.append("missing-package-scope")
        if layer is None:
            scope_block_reasons.append("missing-access-layer-scope")
        if scope.selected_domain and domain != scope.selected_domain:
            ignored_scope_reasons.append("out-of-scope-domain")
        if package is not None and scope.selected_package and package != scope.selected_package:
            ignored_scope_reasons.append("out-of-scope-package")
        if layer is not None and scope.selected_access_layer and layer != scope.selected_access_layer:
            ignored_scope_reasons.append("out-of-scope-layer")
        if scope.selected_gateway and resp.gateway and resp.gateway != scope.selected_gateway:
            ignored_scope_reasons.append("out-of-scope-gateway")

        for rule, section_title in flatten_rulebase(resp.data.get("rulebase", [])):
            uid = rule.get("uid")
            rule_num = rule.get("rule-number")
            name = rule.get("name") or f"Rule_{rule_num or len(inventory_items) + 1}"
            status = ExtractionStatus.NORMALIZED
            requires_review = False
            review_reasons: List[str] = []
            notes: List[str] = [f"Section: {section_title}"] if section_title else []
            withhold = False

            rule_type = str(rule.get("type", "")).strip().lower()
            if "_malformed_rule" in rule:
                withhold = requires_review = True
                status = ExtractionStatus.PARSE_ERROR
                review_reasons.append("malformed-non-dict-access-rule")
            elif rule_type and rule_type != "access-rule":
                withhold = requires_review = True
                status = ExtractionStatus.UNSUPPORTED
                review_reasons.append(f"unsupported-access-rule-type:{rule_type}")
                unsupported_items.append(UnsupportedItem(
                    source_path=src_path, source_name=name,
                    reason=f"Unsupported Check Point access rule type '{rule_type}'",
                    requires_manual_review=True, raw_capture=str(rule),
                ))

            if rulebase_state and not rulebase_state.complete:
                withhold = requires_review = True
                status = ExtractionStatus.PARTIALLY_NORMALIZED
                review_reasons.extend(rulebase_state.reasons or ["incomplete-pagination"])
            if scope_block_reasons:
                withhold = requires_review = True
                status = ExtractionStatus.PARTIALLY_NORMALIZED
                review_reasons.extend(scope_block_reasons)
            if ignored_scope_reasons:
                withhold = True
                status = ExtractionStatus.IGNORED_BY_POLICY
                notes.extend(ignored_scope_reasons)

            install_on = resolve_install_on(rule, resolver, scope.selected_gateway, domain)
            if install_on.eligible is False:
                withhold = True
                status = ExtractionStatus.IGNORED_BY_POLICY
                notes.extend(install_on.reasons)
            elif install_on.eligible is None:
                withhold = requires_review = True
                status = ExtractionStatus.PARTIALLY_NORMALIZED
                review_reasons.extend(install_on.reasons)

            enabled, enabled_error = parse_required_bool(rule.get("enabled"), "enabled")
            if enabled_error:
                withhold = requires_review = True
                status = ExtractionStatus.PARSE_ERROR
                review_reasons.append(enabled_error)

            raw_vpn = rule.get("vpn") if "vpn" in rule else None
            vpn_res = classify_vpn_dimension(raw_vpn, resolver, domain)
            if vpn_res.communities:
                withhold = requires_review = True
                if status == ExtractionStatus.NORMALIZED:
                    status = ExtractionStatus.PARTIALLY_NORMALIZED
                review_reasons.append("checkpoint-vpn-community")
            for ref in vpn_res.unresolved:
                withhold = requires_review = True
                if status == ExtractionStatus.NORMALIZED:
                    status = ExtractionStatus.PARTIALLY_NORMALIZED
                review_reasons.append(
                    "missing-vpn-dimension" if ref == "<missing>" else f"unresolved-vpn:{ref}"
                )
            for ref in vpn_res.unsafe_refs:
                withhold = requires_review = True
                if status == ExtractionStatus.NORMALIZED:
                    status = ExtractionStatus.PARTIALLY_NORMALIZED
                review_reasons.append(f"nonportable-vpn-match:{ref}")

            inline_layer_ref = _inline_layer_reference(rule)
            inline_context = rule.get("_checkpoint_inline_layer_context") or response_inline_context
            if inline_layer_ref is not None or inline_context is not None:
                withhold = requires_review = True
                if status not in (ExtractionStatus.PARSE_ERROR, ExtractionStatus.UNSUPPORTED):
                    status = ExtractionStatus.PARTIALLY_NORMALIZED
                review_reasons.append("checkpoint-inline-layer")

            source_res = classify_address_dimension(_as_list(rule.get("source")), resolver, domain)
            dest_res = classify_address_dimension(_as_list(rule.get("destination")), resolver, domain)
            service_res = classify_service_dimension(_as_list(rule.get("service")), resolver, domain)

            for dim_name, dim in (("source", source_res), ("destination", dest_res)):
                if not _as_list(rule.get(dim_name)):
                    requires_review = True
                    review_reasons.append(f"empty-{dim_name}-match-criteria")
                review_reasons.extend(f"unresolved-{dim_name}:{ref}" for ref in dim.unresolved)
                review_reasons.extend(f"unsafe-{dim_name}-object:{ref}" for ref in dim.unsafe_refs)
                if dim.unresolved or dim.unsafe_refs:
                    requires_review = True
                if dim.mixed_zone_address:
                    withhold = requires_review = True
                    review_reasons.append("mixed-zone-address-or-semantics")

            if not _as_list(rule.get("service")):
                requires_review = True
                review_reasons.append("empty-service-match-criteria")
            review_reasons.extend(f"unresolved-service:{ref}" for ref in service_res.unresolved)
            review_reasons.extend(f"nonportable-service-match:{ref}" for ref in service_res.unsafe_refs)
            if service_res.unresolved or service_res.unsafe_refs:
                requires_review = True
            if service_res.mixed_service_application:
                withhold = requires_review = True
                review_reasons.append("mixed-service-application-or-semantics")

            action_ref = rule.get("action")
            action_val, action_res = resolver.resolve_action(action_ref, domain=domain)
            action_name = action_res.name or (str(action_ref) if action_ref is not None else "")
            if action_val is None:
                withhold = requires_review = True
                recognized = action_name.strip().lower() in {
                    "ask", "inform", "user auth", "client auth", "session auth", "inline layer"
                }
                if action_ref is None or action_ref == "":
                    status = ExtractionStatus.PARSE_ERROR
                    reason = "missing-action"
                elif not action_res.resolved and not recognized:
                    status = ExtractionStatus.PARSE_ERROR
                    reason = f"unresolved-action:{action_res.uid or action_name}"
                else:
                    status = ExtractionStatus.PARTIALLY_NORMALIZED
                    reason = f"unsupported-action:{action_name}"
                    unsupported_items.append(UnsupportedItem(
                        source_path=src_path, source_name=name,
                        reason=f"Check Point access action '{action_name}' is not portable",
                        requires_manual_review=True, raw_capture=str(rule),
                    ))
                review_reasons.append(reason)

            source_negate = bool(rule.get("source-negate", False))
            dest_negate = bool(rule.get("destination-negate", False))
            service_negate = bool(rule.get("service-negate", False))
            if source_negate or dest_negate or service_negate:
                requires_review = True
                review_reasons.append("negated-match-criteria")

            schedule_name: Optional[str] = None
            raw_time = rule.get("time") if "time" in rule else None
            time_res = classify_time_dimension(raw_time, resolver, domain)
            if len(time_res.schedules) == 1 and not time_res.explicit_any:
                schedule_name = time_res.schedules[0]
            if time_res.multiple_constraints:
                requires_review = True
                review_reasons.append("multiple-time-constraints")
            for ref in time_res.unresolved:
                requires_review = True
                review_reasons.append(
                    "missing-time-dimension" if ref == "<missing>" else
                    "empty-time-dimension" if ref == "<empty>" else f"unresolved-schedule:{ref}"
                )
            for ref in time_res.unsafe_refs:
                requires_review = True
                review_reasons.append(
                    ref if ref == "any-with-other-time-match" else f"tainted-schedule:{ref}"
                )

            content_res = classify_content_dimension(rule, resolver, domain)
            if content_res.content:
                requires_review = True
                review_reasons.append("checkpoint-content-awareness")
            if content_res.negate:
                requires_review = True
                review_reasons.append("content-negate")
            if content_res.direction and content_res.direction.strip().lower() not in {
                "any", "any direction", "any-direction"
            }:
                requires_review = True
                review_reasons.append(f"content-direction:{content_res.direction}")
            for ref in content_res.unresolved:
                requires_review = True
                review_reasons.append(f"unresolved-content:{ref}")

            for key, reason in (
                ("action-settings", "checkpoint-action-settings"),
                ("user-check", "checkpoint-user-check"),
                ("identity-captive-portal", "checkpoint-identity-captive-portal"),
                ("limit", "checkpoint-rule-limit"),
                ("rule-limit", "checkpoint-rule-limit"),
            ):
                if key in rule and rule.get(key) not in (None, False, {}, []):
                    withhold = requires_review = True
                    review_reasons.append(reason)

            track_res = resolve_track(rule.get("track"), resolver, domain)
            if track_res.review_reasons:
                requires_review = True
                review_reasons.extend(track_res.review_reasons)

            if requires_review and status == ExtractionStatus.NORMALIZED:
                status = ExtractionStatus.PARTIALLY_NORMALIZED
            review_reasons = list(dict.fromkeys(review_reasons))

            source_attributes = dict(rule)
            source_attributes.pop("_checkpoint_inline_layer_context", None)
            parent_rule_uid = resp.parent_rule_uid or uid
            parent_rule_number = rule_num
            if isinstance(inline_context, dict):
                parent_rule_uid = inline_context.get("parent-rule-uid") or parent_rule_uid
                parent_rule_number = inline_context.get("parent-rule-number") or parent_rule_number
            source_attributes["checkpoint-provenance"] = {
                "domain": resp.domain,
                "package": package,
                "layer": layer,
                "layer-uid": resp.layer_uid or resp.data.get("uid"),
                "parent-layer": resp.parent_layer,
                "parent-layer-uid": resp.parent_layer_uid,
                "parent-rule-uid": parent_rule_uid,
                "parent-rule-number": parent_rule_number,
                "rule-number": rule_num,
                "rule-uid": uid,
                "section-path": section_title or None,
                "inline-layer": inline_layer_ref or inline_context,
            }
            if source_res.access_roles:
                source_attributes["checkpoint-access-role-references"] = list(source_res.access_roles)

            if not withhold and action_val is not None and enabled is not None:
                from_zones = ["any"] if source_res.explicit_any or not source_res.zones else source_res.zones
                sources = ["any"] if source_res.explicit_any or source_res.zones and not source_res.addresses else source_res.addresses
                to_zones = ["any"] if dest_res.explicit_any or not dest_res.zones else dest_res.zones
                destinations = ["any"] if dest_res.explicit_any or dest_res.zones and not dest_res.addresses else dest_res.addresses
                services = ["any"] if service_res.explicit_any or service_res.applications and not service_res.services else service_res.services
                policies.append(IRPolicy(
                    name=name, source_rule_id=str(rule_num) if rule_num is not None else None,
                    source_uuid=uid, from_zone=from_zones, to_zone=to_zones,
                    source=sources, destination=destinations, service=services,
                    applications=service_res.applications, action=action_val,
                    source_action=action_name or None, description=rule.get("comments"),
                    disabled=not enabled, schedule=schedule_name, schedules=list(time_res.schedules),
                    log_start=track_res.log_start, log_end=track_res.log_end,
                    source_log_setting=track_res.source_type,
                    source_address_negate_setting="negate" if source_negate else None,
                    destination_address_negate_setting="negate" if dest_negate else None,
                    source_service_negate_setting="negate" if service_negate else None,
                    migration_status=status.value, review_reasons=review_reasons,
                    requires_manual_review=requires_review, source_extra_settings=source_attributes,
                ))

            inventory_items.append(SourceInventoryItem(
                domain=domain, source_path=src_path, name=name, source_id=uid,
                source_type="access-rule", source_attributes=source_attributes, status=status,
                requires_manual_review=requires_review,
                notes=list(dict.fromkeys(notes + review_reasons)),
            ))

    return policies, inventory_items, unsupported_items
