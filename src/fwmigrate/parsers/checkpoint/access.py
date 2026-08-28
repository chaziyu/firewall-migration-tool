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
from fwmigrate.parsers.checkpoint.rulebase import flatten_rulebase

RulebaseKey = Tuple[str, Optional[str], Optional[str], Optional[str], Optional[str]]


class AddressDimensionResolution(BaseModel):
    zones: List[str] = Field(default_factory=list)
    addresses: List[str] = Field(default_factory=list)
    explicit_any: bool = False
    unresolved: List[str] = Field(default_factory=list)
    unsafe_refs: List[str] = Field(default_factory=list)
    mixed_zone_address: bool = False


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
        elif res.semantic_kind in (SemanticKind.ADDRESS, SemanticKind.ADDRESS_GROUP) and res.canonical_name:
            result.addresses.append(res.canonical_name)
            if res.canonical_name.strip().lower() in {"any", "original"}:
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
        res = resolver.resolve(ref, domain=domain)
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

        package = resp.package or "Standard"
        layer = resp.layer or "Network"
        domain = resp.domain or "global"
        src_path = f"checkpoint/{cmd}/{package}/{layer}"
        key: RulebaseKey = (cmd, resp.domain, resp.package, resp.layer, resp.gateway)
        rulebase_state = safety_map.get(key) if safety_map else None

        scope_block_reasons: List[str] = []
        ignored_scope_reasons: List[str] = []
        if scope.ambiguous:
            scope_block_reasons = ["scope-selection-required", *scope.reasons]
        if scope.selected_domain and domain != scope.selected_domain:
            ignored_scope_reasons.append("out-of-scope-domain")
        if scope.selected_package and package != scope.selected_package:
            ignored_scope_reasons.append("out-of-scope-package")
        if scope.selected_access_layer and layer != scope.selected_access_layer:
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

            enabled_raw = rule.get("enabled")
            if enabled_raw is None:
                withhold = requires_review = True
                status = ExtractionStatus.PARSE_ERROR
                review_reasons.append("missing-enabled")

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
            action_val, action_res = resolver.resolve_action(action_ref)
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
            time_ref = rule.get("time")
            if time_ref:
                time_res = resolver.resolve(time_ref, domain=domain)
                if time_res.resolved and time_res.name:
                    schedule_name = time_res.name
                    if not resolver.is_dependency_safe(time_ref, domain=domain):
                        requires_review = True
                        review_reasons.append(f"tainted-schedule:{time_res.name}")
                else:
                    requires_review = True
                    review_reasons.append(f"unresolved-schedule:{_ref_label(time_ref)}")

            if requires_review and status == ExtractionStatus.NORMALIZED:
                status = ExtractionStatus.PARTIALLY_NORMALIZED
            review_reasons = list(dict.fromkeys(review_reasons))

            if not withhold and action_val is not None and enabled_raw is not None:
                from_zones = ["any"] if source_res.explicit_any or not source_res.zones else source_res.zones
                sources = ["any"] if source_res.explicit_any or source_res.zones and not source_res.addresses else source_res.addresses
                to_zones = ["any"] if dest_res.explicit_any or not dest_res.zones else dest_res.zones
                destinations = ["any"] if dest_res.explicit_any or dest_res.zones and not dest_res.addresses else dest_res.addresses
                services = ["any"] if service_res.explicit_any or service_res.applications and not service_res.services else service_res.services
                track = rule.get("track")
                log_end = not (isinstance(track, dict) and str(track.get("name") or track.get("type", "")).lower() == "none")
                policies.append(IRPolicy(
                    name=name, source_rule_id=str(rule_num) if rule_num is not None else None,
                    source_uuid=uid, from_zone=from_zones, to_zone=to_zones,
                    source=sources, destination=destinations, service=services,
                    applications=service_res.applications, action=action_val,
                    source_action=action_name or None, description=rule.get("comments"),
                    disabled=not bool(enabled_raw), schedule=schedule_name, log_end=log_end,
                    source_address_negate_setting="negate" if source_negate else None,
                    destination_address_negate_setting="negate" if dest_negate else None,
                    source_service_negate_setting="negate" if service_negate else None,
                    migration_status=status.value, review_reasons=review_reasons,
                    requires_manual_review=requires_review, source_extra_settings=rule,
                ))

            inventory_items.append(SourceInventoryItem(
                domain=domain, source_path=src_path, name=name, source_id=uid,
                source_type="access-rule", source_attributes=rule, status=status,
                requires_manual_review=requires_review,
                notes=list(dict.fromkeys(notes + review_reasons)),
            ))

    return policies, inventory_items, unsupported_items
