"""Check Point NAT extraction with strict translation and rulebase safety gates."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Tuple

from pydantic import BaseModel, Field

from fwmigrate.extraction.models import ExtractionStatus, SourceInventoryItem, UnsupportedItem
from fwmigrate.ir.nat import IRNATRule
from fwmigrate.ir.enums import NATTranslationMode, NATType
from fwmigrate.parsers.checkpoint.access import resolve_install_on
from fwmigrate.parsers.checkpoint.loader import canonicalize_command
from fwmigrate.parsers.checkpoint.models import CheckPointResponse, RulebaseSafetyState, ScopeSelectionResult
from fwmigrate.parsers.checkpoint.resolver import (
    CheckPointObjectResolver, SemanticKind, is_any_object, is_original_object,
)
from fwmigrate.parsers.checkpoint.rulebase import flatten_rulebase, parse_required_bool

RulebaseKey = Tuple[str, Optional[str], Optional[str], Optional[str], Optional[str]]

_NAT_METHOD_KEYS = (
    "source-nat-method", "source_nat_method", "nat-method", "nat_method",
    "translation-method", "translation_method", "method",
)
_DESTINATION_NAT_METHOD_KEYS = (
    "destination-nat-method", "destination_nat_method",
    "destination-translation-method", "destination_translation_method",
)
_HIDE_BEHIND_KEYS = (
    "hide-behind", "hide_behind", "hide-behind-gateway",
    "hide_behind_gateway", "hide-behind-interface", "hide_behind_interface",
)


class SourceNATMethodResolution(BaseModel):
    resolved: bool = False
    mode: Optional[NATTranslationMode] = None
    method: Optional[str] = None
    evidence: List[str] = Field(default_factory=list)
    reasons: List[str] = Field(default_factory=list)


def _first_present(source: Mapping[str, Any], keys: Tuple[str, ...]) -> Any:
    for key in keys:
        if key in source and source[key] is not None:
            return source[key]
    return None


def _nat_metadata_for_ref(
    ref: Any,
    resolver: CheckPointObjectResolver,
    domain: Optional[str],
    metadata: Mapping[str, Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    resolution = resolver.resolve(ref, domain=domain)
    if domain is None:
        for key in (resolution.uid, resolution.name):
            if key and key in metadata:
                return dict(metadata[key])
    return resolver.get_automatic_nat_metadata(ref, domain=domain)


def resolve_source_nat_method(
    rule: Dict[str, Any],
    translated_source_ref: Any,
    resolver: CheckPointObjectResolver,
    object_nat_metadata: Mapping[str, Dict[str, Any]],
    domain: Optional[str] = None,
) -> SourceNATMethodResolution:
    """Resolve source NAT mode only from explicit rule or object NAT evidence."""
    result = SourceNATMethodResolution()
    method_raw = _first_present(rule, _NAT_METHOD_KEYS)
    hide_behind_raw = _first_present(rule, _HIDE_BEHIND_KEYS)
    method_evidence = (
        f"rule:method={str(method_raw).strip().lower()}"
        if method_raw is not None else None
    )
    hide_evidence = (
        f"rule:hide-behind={str(hide_behind_raw).strip().lower()}"
        if hide_behind_raw is not None else None
    )
    object_evidence: List[Tuple[Optional[str], Optional[str], str]] = []
    for ref in (rule.get("original-source"), translated_source_ref):
        metadata = _nat_metadata_for_ref(ref, resolver, domain, object_nat_metadata)
        if not metadata:
            continue
        object_method = _first_present(metadata, ("method", "nat-method", "nat_method"))
        object_hide = _first_present(metadata, _HIDE_BEHIND_KEYS)
        object_evidence.append((
            object_method,
            object_hide,
            f"object-nat-settings:{_ref_label(ref, resolver, domain)}",
        ))

    for object_method, object_hide, prefix in object_evidence:
        if object_method is not None:
            normalized = str(object_method).strip().lower()
            result.evidence.append(f"{prefix}:method={normalized}")
            if method_raw is None:
                method_raw = object_method
            elif str(method_raw).strip().lower() != normalized:
                result.reasons.append("conflicting-source-nat-method-evidence")
        if object_hide is not None:
            normalized = str(object_hide).strip().lower()
            result.evidence.append(f"{prefix}:hide-behind={normalized}")
            if hide_behind_raw is None:
                hide_behind_raw = object_hide
            elif str(hide_behind_raw).strip().lower() != normalized:
                result.reasons.append("conflicting-hide-behind-evidence")

    if method_evidence:
        result.evidence.insert(0, method_evidence)
    if hide_evidence:
        result.evidence.insert(1 if method_evidence else 0, hide_evidence)
    if result.reasons:
        return result

    method = str(method_raw).strip().lower() if method_raw is not None else None
    hide_behind = str(hide_behind_raw).strip().lower() if hide_behind_raw is not None else None
    result.method = method
    interface_markers = {"gateway", "interface", "gateway/interface", "gateway-interface"}
    translated_source_is_any = _trusted_special_reference(
        translated_source_ref, resolver, is_any_object,
    )
    if method in {"static", "static-nat"}:
        if translated_source_is_any:
            result.reasons.append("static-nat-target-unresolved")
            return result
        result.resolved = True
        result.mode = NATTranslationMode.STATIC
        return result

    if method in {"hide", "hide-nat", "dynamic", "dynamic-ip-and-port"}:
        if translated_source_is_any:
            if hide_behind in interface_markers:
                result.resolved = True
                result.mode = NATTranslationMode.INTERFACE_ADDRESS
                return result
            result.reasons.append("hide-nat-target-unresolved")
            return result
        if hide_behind in interface_markers:
            result.reasons.append("conflicting-hide-behind-and-translated-source")
            return result
        result.resolved = True
        result.mode = NATTranslationMode.DYNAMIC_IP_AND_PORT
        return result

    if method is not None:
        result.reasons.append(f"source-nat-method-unrepresentable:{method}")
        return result
    if hide_behind in interface_markers and translated_source_is_any:
        result.resolved = True
        result.method = "hide"
        result.mode = NATTranslationMode.INTERFACE_ADDRESS
        return result
    result.reasons.append("source-nat-method-evidence-missing")
    return result


def resolve_destination_nat_method(
    rule: Dict[str, Any],
    translated_destination_ref: Any = None,
    resolver: Optional[CheckPointObjectResolver] = None,
    object_nat_metadata: Optional[Mapping[str, Dict[str, Any]]] = None,
    domain: Optional[str] = None,
    *,
    use_common_method: bool = False,
) -> SourceNATMethodResolution:
    """Resolve destination method without applying source Hide NAT rules."""
    result = SourceNATMethodResolution()
    method_raw = _first_present(rule, _DESTINATION_NAT_METHOD_KEYS)
    if method_raw is None and use_common_method:
        common_method = _first_present(rule, ("method", "nat-method", "nat_method"))
        if str(common_method or "").strip().lower() in {"static", "static-nat"}:
            method_raw = common_method
    if method_raw is None and resolver is not None:
        for ref in (rule.get("original-destination"), translated_destination_ref):
            metadata = _nat_metadata_for_ref(ref, resolver, domain, object_nat_metadata or {})
            object_method = _first_present(metadata or {}, ("method", "nat-method", "nat_method"))
            if object_method is not None:
                method_raw = object_method
                result.evidence.append(
                    f"object-nat-settings:{_ref_label(ref, resolver, domain)}:destination-method="
                    f"{str(method_raw).strip().lower()}"
                )
                break
    if method_raw is None:
        return result
    method = str(method_raw).strip().lower()
    result.method = method
    result.evidence.append(f"rule:destination-method={method}")
    if method in {"static", "static-nat"}:
        result.resolved = True
        result.mode = NATTranslationMode.STATIC
    else:
        result.reasons.append(f"destination-nat-method-unrepresentable:{method}")
    return result


def _ref_label(ref: Any, resolver: CheckPointObjectResolver, domain: Optional[str]) -> str:
    resolution = resolver.resolve(ref, domain=domain)
    if resolution.uid or resolution.name:
        return str(resolution.uid or resolution.name)
    if isinstance(ref, dict):
        return str(ref.get("uid") or ref.get("name") or "<inline-object>")
    return str(ref)


def _trusted_special_reference(
    ref: Any, resolver: CheckPointObjectResolver, predicate: Any,
) -> bool:
    """Prefer registered object typing before accepting trusted legacy symbolic names."""
    if isinstance(ref, str):
        registered = resolver.by_uid.get(ref) or resolver.by_name.get(ref)
        if registered is not None:
            return bool(predicate(registered, allow_symbolic_name=False))
    return bool(predicate(ref, allow_symbolic_name=True))


def _resolve_match(
    ref: Any, resolver: CheckPointObjectResolver, domain: Optional[str], dimension: str,
) -> Tuple[List[str], List[str]]:
    reasons: List[str] = []
    res = resolver.resolve(ref, domain=domain, allow_special_symbolic_names=True)
    allowed = (
        {SemanticKind.ADDRESS, SemanticKind.ADDRESS_GROUP, SemanticKind.SPECIAL_ANY}
        if dimension != "service"
        else {SemanticKind.SERVICE, SemanticKind.SERVICE_GROUP, SemanticKind.SPECIAL_ANY}
    )
    if res.resolved and res.canonical_names and res.semantic_kind in allowed:
        if res.semantic_kind != SemanticKind.SPECIAL_ANY and any(name.strip().lower() in {"any", "original"} for name in res.canonical_names):
            return res.canonical_names, [f"reserved-special-name-collision:{dimension}:{name}" for name in res.canonical_names]
        if res.semantic_kind != SemanticKind.SPECIAL_ANY and not resolver.is_dependency_safe(ref, domain=domain):
            reasons.append(f"tainted-nat-{dimension}:{res.name or res.uid}")
        return res.canonical_names, reasons
    ident = res.uid or res.name or str(ref)
    prefix = "unresolved" if not res.resolved else "nonportable"
    reasons.append(f"{prefix}-nat-{dimension}:{ident}")
    return [], reasons


def _resolve_translation(
    ref: Any, resolver: CheckPointObjectResolver, domain: Optional[str], dimension: str,
) -> Tuple[List[str], List[str]]:
    reasons: List[str] = []
    res = resolver.resolve(ref, domain=domain)
    expected = (
        {SemanticKind.ADDRESS, SemanticKind.ADDRESS_GROUP}
        if dimension != "service"
        else {SemanticKind.SERVICE, SemanticKind.SERVICE_GROUP}
    )
    if res.resolved and res.canonical_names and res.semantic_kind in expected:
        if any(name.strip().lower() in {"any", "original"} for name in res.canonical_names):
            return res.canonical_names, [f"reserved-special-name-collision:translated-{dimension}:{name}" for name in res.canonical_names]
        if not resolver.is_dependency_safe(ref, domain=domain):
            reasons.append(f"tainted-translated-{dimension}:{res.name or res.uid}")
        return res.canonical_names, reasons
    ident = res.uid or res.name or str(ref)
    prefix = "unresolved" if not res.resolved else "nonportable"
    reasons.append(f"{prefix}-translated-{dimension}:{ident}")
    return [], reasons


def _sequence(value: Any) -> Optional[int]:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _address_family(ref: Any, resolver: CheckPointObjectResolver, domain: Optional[str]) -> Optional[str]:
    """Return family only when the referenced object exposes an unambiguous family."""
    if isinstance(ref, list):
        families = {_address_family(item, resolver, domain) for item in ref}
        families.discard(None)
        return next(iter(families)) if len(families) == 1 else None
    res = resolver.resolve(ref, domain=domain)
    obj = res.source_object or {}
    has_v4 = any(obj.get(key) is not None for key in ("ipv4-address", "ipv4_address", "subnet4", "ipv4-address-first"))
    has_v6 = any(obj.get(key) is not None for key in ("ipv6-address", "ipv6_address", "subnet6", "ipv6-address-first"))
    if has_v4 != has_v6:
        return "ipv4" if has_v4 else "ipv6"
    return None


def _nat_family(original: Dict[str, Any], translated: Dict[str, Any], resolver: CheckPointObjectResolver, domain: Optional[str]) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    original_families = {_address_family(original.get(key), resolver, domain) for key in ("source", "destination")}
    translated_families = {_address_family(translated.get(key), resolver, domain) for key in ("source", "destination")}
    original_families.discard(None)
    translated_families.discard(None)
    original_family = next(iter(original_families)) if len(original_families) == 1 else None
    translated_family = next(iter(translated_families)) if len(translated_families) == 1 else None
    if original_family and translated_family:
        family = {("ipv4", "ipv4"): "nat44", ("ipv4", "ipv6"): "nat46", ("ipv6", "ipv4"): "nat64", ("ipv6", "ipv6"): "nat66"}[(original_family, translated_family)]
        return family, original_family, translated_family
    return None, original_family, translated_family


def extract_nat_rulebase(
    responses: List[CheckPointResponse],
    resolver: CheckPointObjectResolver,
    scope: ScopeSelectionResult,
    safety_map: Optional[Mapping[RulebaseKey, RulebaseSafetyState]] = None,
    object_nat_metadata: Optional[Mapping[str, Dict[str, Any]]] = None,
) -> Tuple[List[IRNATRule], List[SourceInventoryItem], List[UnsupportedItem]]:
    """Extract NAT rules without guessing missing match or translation semantics."""
    nat_rules: List[IRNATRule] = []
    inventory_items: List[SourceInventoryItem] = []
    unsupported_items: List[UnsupportedItem] = []

    ordered_responses = sorted(
        responses,
        key=lambda response: (
            response.domain or "", response.package or "", response.gateway or "",
            response.from_index if response.from_index is not None else 0,
        ),
    )
    for resp in ordered_responses:
        cmd = canonicalize_command(resp.command)
        if cmd != "show-nat-rulebase":
            continue
        package = resp.package
        domain = resp.domain or "global"
        resolver.set_active_scope(resp.domain_uid, domain) if resp.domain_uid else resolver.set_active_scope(None, None)
        src_path = f"checkpoint/{cmd}/{package or '<missing-package>'}"
        key: RulebaseKey = (cmd, resp.domain, resp.package, resp.layer, resp.gateway)
        rulebase_state = safety_map.get(key) if safety_map else None

        scope_block_reasons: List[str] = []
        ignored_scope_reasons: List[str] = []
        if scope.ambiguous:
            scope_block_reasons = ["scope-selection-required", *scope.reasons]
        if package is None:
            scope_block_reasons.append("missing-package-scope")
        if scope.selected_domain and domain != scope.selected_domain:
            ignored_scope_reasons.append("out-of-scope-domain")
        if package is not None and scope.selected_package and package != scope.selected_package:
            ignored_scope_reasons.append("out-of-scope-package")
        if scope.selected_gateway and resp.gateway and resp.gateway != scope.selected_gateway:
            ignored_scope_reasons.append("out-of-scope-gateway")

        for rule, section_title in flatten_rulebase(resp.data.get("rulebase", [])):
            uid = rule.get("uid")
            rule_num = rule.get("rule-number")
            name = rule.get("name") or f"NAT_Rule_{rule_num or len(inventory_items) + 1}"
            status = ExtractionStatus.NORMALIZED
            requires_review = False
            withhold = False
            reasons: List[str] = []
            notes: List[str] = [f"Section: {section_title}"] if section_title else []

            rule_type = str(rule.get("type", "")).strip().lower()
            if "_malformed_rule" in rule:
                withhold = requires_review = True
                status = ExtractionStatus.PARSE_ERROR
                reasons.append("malformed-non-dict-nat-rule")
            elif rule_type and rule_type != "nat-rule":
                withhold = requires_review = True
                status = ExtractionStatus.UNSUPPORTED
                reasons.append(f"unsupported-nat-rule-type:{rule_type}")
                unsupported_items.append(UnsupportedItem(
                    source_path=src_path, source_name=name,
                    reason=f"Unsupported Check Point NAT rule type '{rule_type}'",
                    requires_manual_review=True, raw_capture=str(rule),
                ))

            if rulebase_state and not rulebase_state.complete:
                withhold = requires_review = True
                status = ExtractionStatus.PARTIALLY_NORMALIZED
                reasons.extend(rulebase_state.reasons or ["incomplete-pagination"])
            if scope_block_reasons:
                withhold = requires_review = True
                status = ExtractionStatus.PARTIALLY_NORMALIZED
                reasons.extend(scope_block_reasons)
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
                reasons.extend(install_on.reasons)

            enabled, enabled_error = parse_required_bool(rule.get("enabled"), "enabled")
            if enabled_error:
                withhold = requires_review = True
                status = ExtractionStatus.PARSE_ERROR
                reasons.append(enabled_error)

            original_values = {
                "source": rule.get("original-source"),
                "destination": rule.get("original-destination"),
                "service": rule.get("original-service"),
            }
            resolved_original: dict[str, List[str]] = {}
            for dimension, value in original_values.items():
                if value is None:
                    withhold = requires_review = True
                    status = ExtractionStatus.PARSE_ERROR
                    reasons.append(f"missing-original-{dimension}")
                    resolved_original[dimension] = []
                else:
                    values, value_reasons = _resolve_match(value, resolver, domain, dimension)
                    resolved_original[dimension] = values
                    if value_reasons:
                        requires_review = True
                        reasons.extend(value_reasons)

            translated_values = {
                "source": rule.get("translated-source"),
                "destination": rule.get("translated-destination"),
                "service": rule.get("translated-service"),
            }
            translated: dict[str, List[str]] = {"source": [], "destination": [], "service": []}
            translated_source_any = False
            for dimension, value in translated_values.items():
                if value is None:
                    withhold = requires_review = True
                    status = ExtractionStatus.PARSE_ERROR
                    reasons.append(f"missing-translated-{dimension}")
                    continue
                if _trusted_special_reference(value, resolver, is_original_object):
                    continue
                if dimension == "source" and _trusted_special_reference(value, resolver, is_any_object):
                    translated_source_any = True
                    continue
                if _trusted_special_reference(value, resolver, is_any_object):
                    requires_review = True
                    reasons.append(f"invalid-translated-{dimension}-any")
                    continue
                values, value_reasons = _resolve_translation(value, resolver, domain, dimension)
                translated[dimension] = values
                if value_reasons:
                    requires_review = True
                    reasons.extend(value_reasons)

            source_changed = bool(translated["source"] or translated_source_any)
            destination_changed = bool(translated["destination"])
            service_changed = bool(translated["service"])
            identity_nat = all(
                field in rule and _trusted_special_reference(
                    rule[field], resolver, is_original_object,
                )
                for field in (
                    "translated-source", "translated-destination", "translated-service",
                )
            )
            nat_type: Optional[NATType] = None
            if identity_nat:
                nat_type = NATType.SOURCE
            elif source_changed and destination_changed:
                nat_type = NATType.TWICE
            elif destination_changed:
                nat_type = NATType.DESTINATION
            elif source_changed:
                nat_type = NATType.SOURCE
            elif service_changed:
                # Check Point permits service translation without address NAT.
                # Keep it canonical and explicitly unsafe for generic target
                # generators instead of dropping the source rule.
                nat_type = NATType.SERVICE

            if service_changed:
                requires_review = True
                reasons.append("translated-service")
            if nat_type is None and not service_changed:
                withhold = requires_review = True
                reasons.append("no-effective-nat-translation")

            nat_family, original_family, translated_family = _nat_family(
                original_values, translated_values, resolver, domain,
            )
            explicit_family = _first_present(rule, ("nat-family", "nat_family", "address-family", "address_family"))
            if explicit_family is not None:
                candidate = str(explicit_family).strip().lower()
                nat_family = candidate if candidate in {"nat44", "nat46", "nat64", "nat66"} else nat_family

            src_method = SourceNATMethodResolution()
            if nat_type in (NATType.SOURCE, NATType.TWICE) and not identity_nat:
                src_method = resolve_source_nat_method(
                    rule,
                    translated_values["source"],
                    resolver,
                    object_nat_metadata or resolver.automatic_nat_metadata,
                    domain=domain,
                )
                if not src_method.resolved or src_method.mode is None:
                    withhold = requires_review = True
                    reasons.append("source-nat-method-unresolved")
                    reasons.extend(src_method.reasons)
            dst_method = SourceNATMethodResolution()
            if nat_type in (NATType.DESTINATION, NATType.TWICE):
                dst_method = resolve_destination_nat_method(
                    rule, rule.get("translated-destination"), resolver,
                    object_nat_metadata or resolver.automatic_nat_metadata, domain,
                    use_common_method=nat_type == NATType.DESTINATION,
                )
                if dst_method.reasons:
                    withhold = requires_review = True
                    reasons.extend(dst_method.reasons)

            if requires_review and status == ExtractionStatus.NORMALIZED:
                status = ExtractionStatus.PARTIALLY_NORMALIZED
            reasons = list(dict.fromkeys(reasons))
            nat_source_attributes = {
                **rule,
                "checkpoint-source-nat-method-resolution": src_method.model_dump(),
                "checkpoint-destination-nat-method-resolution": dst_method.model_dump(),
                "checkpoint-provenance": {
                    "domain": resp.domain,
                    "domain-uid": resp.domain_uid,
                    "domain-name": resp.domain_name or domain,
                    "package": package,
                    "package-uid": resp.package_uid,
                    "package-name": resp.package_name or package,
                    "section-path": section_title or None,
                    "rule-number": rule_num,
                    "rule-uid": uid,
                },
                "checkpoint-address-families": {
                    "original": original_family,
                    "translated": translated_family,
                },
            }

            if not withhold and nat_type is not None and enabled is not None:
                src_mode: Optional[NATTranslationMode] = None
                if nat_type in (NATType.SOURCE, NATType.TWICE) and not identity_nat:
                    src_mode = src_method.mode
                nat_rules.append(IRNATRule(
                    name=name, type=nat_type,
                    source_context=f"{domain}/{package or '<missing-package>'}",
                    checkpoint_domain_uid=resp.domain_uid,
                    checkpoint_domain_name=resp.domain_name or domain,
                    checkpoint_package_uid=resp.package_uid,
                    checkpoint_package_name=resp.package_name or package,
                    source_policy_reference=str(rule_num) if rule_num is not None else None,
                    source_policy_uuid=uid, source_policy_name=name,
                    source_rule_id=str(rule_num) if rule_num is not None else None,
                    sequence=_sequence(rule_num), enabled=enabled,
                    from_zone=["any"], to_zone=["any"],
                    source=resolved_original["source"],
                    destination=resolved_original["destination"],
                    services=resolved_original["service"],
                    translated_sources=translated["source"],
                    translated_destinations=translated["destination"],
                    translated_services=translated["service"],
                    nat_family=nat_family,
                    original_address_family=original_family,
                    translated_address_family=translated_family,
                    source_translation_mode=src_mode,
                    destination_translation_mode=dst_method.mode,
                    identity=identity_nat,
                    exemption=identity_nat,
                    source_origin="checkpoint-nat-rulebase",
                    migration_status=status.value, review_reasons=reasons,
                    requires_manual_review=requires_review,
                    source_attributes=nat_source_attributes,
                    description=rule.get("comments"),
                ))

            inventory_items.append(SourceInventoryItem(
                domain=domain, source_path=src_path, name=name, source_id=uid,
                source_type="nat-rule", source_attributes=nat_source_attributes, status=status,
                requires_manual_review=requires_review,
                notes=list(dict.fromkeys(notes + reasons)),
            ))

    return nat_rules, inventory_items, unsupported_items
