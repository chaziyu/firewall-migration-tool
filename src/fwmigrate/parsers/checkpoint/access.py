"""Check Point access control rulebase extraction, scope isolation, and taint propagation."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from fwmigrate.extraction.models import (
    ExtractionStatus,
    SourceInventoryItem,
    UnsupportedItem,
)
from fwmigrate.ir.core import IRPolicy
from fwmigrate.ir.enums import PolicyAction
from fwmigrate.parsers.checkpoint.loader import canonicalize_command
from fwmigrate.parsers.checkpoint.models import CheckPointResponse, ScopeSelectionResult
from fwmigrate.parsers.checkpoint.resolver import (
    CheckPointObjectResolver,
    ResolutionResult,
    SemanticKind,
)
from fwmigrate.parsers.checkpoint.rulebase import flatten_rulebase


def extract_access_rulebase(
    responses: List[CheckPointResponse],
    resolver: CheckPointObjectResolver,
    scope: ScopeSelectionResult,
) -> Tuple[List[IRPolicy], List[SourceInventoryItem], List[UnsupportedItem]]:
    """Extract Check Point access control rulebase into canonical IRPolicies with dependency safety."""
    policies: List[IRPolicy] = []
    inventory_items: List[SourceInventoryItem] = []
    unsupported_items: List[UnsupportedItem] = []

    for resp in responses:
        cmd = canonicalize_command(resp.command)
        if cmd != "show-access-rulebase":
            continue

        package = resp.package or "Standard"
        layer = resp.layer or "Network"
        domain = resp.domain or "global"
        src_path = f"checkpoint/{cmd}/{package}/{layer}"

        # Check scope isolation
        is_in_scope = True
        if scope.selected_package and package != scope.selected_package:
            is_in_scope = False
        if scope.selected_access_layer and layer != scope.selected_access_layer:
            is_in_scope = False

        data = resp.data
        raw_rules = data.get("rulebase", [])
        flattened = flatten_rulebase(raw_rules)

        for rule, section_title in flattened:
            uid = rule.get("uid")
            rule_num = rule.get("rule-number")
            name = rule.get("name") or f"Rule_{rule_num or len(policies) + 1}"
            comments = rule.get("comments")
            enabled = rule.get("enabled", True)

            status = ExtractionStatus.NORMALIZED
            requires_review = False
            review_reasons: List[str] = []
            notes: List[str] = []

            if section_title:
                notes.append(f"Section: {section_title}")

            if not is_in_scope:
                status = ExtractionStatus.EXTRACT_ONLY
                requires_review = True
                review_reasons.append("out-of-scope-package-or-layer")
                notes.append(f"Rule belongs to unselected package '{package}' or layer '{layer}'")

            # 1. Resolve Sources
            raw_sources = rule.get("source", [])
            if not isinstance(raw_sources, list):
                raw_sources = [raw_sources]

            from_zones: List[str] = []
            sources: List[str] = []
            for s in raw_sources:
                res = resolver.resolve(s, domain=domain)
                if res.semantic_kind == SemanticKind.SECURITY_ZONE and res.name:
                    from_zones.append(res.name)
                elif res.resolved and res.canonical_name:
                    sources.append(res.canonical_name)
                    if not resolver.is_dependency_safe(s, domain=domain):
                        requires_review = True
                        review_reasons.append(f"tainted-source-object:{res.name or res.uid}")
                else:
                    requires_review = True
                    unresolved_id = res.uid or (res.name if res.name else str(s))
                    review_reasons.append(f"unresolved-source:{unresolved_id}")

            if not sources:
                if from_zones:
                    sources = ["any"]
                else:
                    requires_review = True
                    review_reasons.append("empty-source-match-criteria")

            # 2. Resolve Destinations
            raw_dests = rule.get("destination", [])
            if not isinstance(raw_dests, list):
                raw_dests = [raw_dests]

            to_zones: List[str] = []
            destinations: List[str] = []
            for d in raw_dests:
                res = resolver.resolve(d, domain=domain)
                if res.semantic_kind == SemanticKind.SECURITY_ZONE and res.name:
                    to_zones.append(res.name)
                elif res.resolved and res.canonical_name:
                    destinations.append(res.canonical_name)
                    if not resolver.is_dependency_safe(d, domain=domain):
                        requires_review = True
                        review_reasons.append(f"tainted-destination-object:{res.name or res.uid}")
                else:
                    requires_review = True
                    unresolved_id = res.uid or (res.name if res.name else str(d))
                    review_reasons.append(f"unresolved-destination:{unresolved_id}")

            if not destinations:
                if to_zones:
                    destinations = ["any"]
                else:
                    requires_review = True
                    review_reasons.append("empty-destination-match-criteria")

            # 3. Resolve Services
            raw_services = rule.get("service", [])
            if not isinstance(raw_services, list):
                raw_services = [raw_services]

            services: List[str] = []
            for svc in raw_services:
                res = resolver.resolve(svc, domain=domain)
                if res.resolved and res.canonical_name:
                    services.append(res.canonical_name)
                    if not resolver.is_dependency_safe(svc, domain=domain):
                        requires_review = True
                        review_reasons.append(f"tainted-service-object:{res.name or res.uid}")
                else:
                    requires_review = True
                    unresolved_id = res.uid or (res.name if res.name else str(svc))
                    review_reasons.append(f"unresolved-service:{unresolved_id}")

            if not services:
                requires_review = True
                review_reasons.append("empty-service-match-criteria")

            # 4. Resolve Action
            action_ref = rule.get("action")
            action_val, act_res = resolver.resolve_action(action_ref)
            if action_val is None:
                # Unsupported action (Ask, Inform, User Auth, Client Auth, Session Auth)
                action_val = PolicyAction.DENY  # Safe fallback action for IR representation
                requires_review = True
                action_name = act_res.name or str(action_ref)
                review_reasons.append(f"unsupported-action:{action_name}")
                unsupported_items.append(UnsupportedItem(
                    source_path=src_path,
                    source_name=name,
                    reason=f"Check Point access action '{action_name}' is not portable to standard firewall policy",
                    requires_manual_review=True,
                    raw_capture=str(rule),
                ))

            # 5. Check Negations
            source_negate = rule.get("source-negate", False)
            dest_negate = rule.get("destination-negate", False)
            service_negate = rule.get("service-negate", False)

            if source_negate or dest_negate or service_negate:
                requires_review = True
                review_reasons.append("negated-match-criteria")

            # 6. Check Time / Schedule
            time_ref = rule.get("time")
            schedule_name: Optional[str] = None
            if time_ref:
                t_res = resolver.resolve(time_ref, domain=domain)
                if t_res.resolved and t_res.name:
                    schedule_name = t_res.name
                    if not resolver.is_dependency_safe(time_ref, domain=domain):
                        requires_review = True
                        review_reasons.append(f"tainted-schedule:{t_res.name}")

            # 7. Check Track / Logging
            track_obj = rule.get("track")
            log_end = True
            if isinstance(track_obj, dict):
                track_type = str(track_obj.get("type", "")).strip().lower()
                track_name = str(track_obj.get("name", "")).strip().lower()
                if track_name == "none" or track_type == "none":
                    log_end = False

            if requires_review and status == ExtractionStatus.NORMALIZED:
                status = ExtractionStatus.PARTIALLY_NORMALIZED

            # Construct canonical IRPolicy
            policy = IRPolicy(
                name=name,
                source_rule_id=str(rule_num) if rule_num is not None else None,
                source_uuid=uid,
                from_zone=from_zones or ["any"],
                to_zone=to_zones or ["any"],
                source=sources,
                destination=destinations,
                service=services,
                action=action_val,
                description=comments,
                disabled=not enabled,
                schedule=schedule_name,
                log_end=log_end,
                source_address_negate_setting="negate" if source_negate else None,
                destination_address_negate_setting="negate" if dest_negate else None,
                source_service_negate_setting="negate" if service_negate else None,
                migration_status=status.value,
                review_reasons=review_reasons,
                requires_manual_review=requires_review,
                source_extra_settings=rule,
            )
            policies.append(policy)

            # Construct Leaf Inventory Item
            inventory_items.append(SourceInventoryItem(
                domain=domain,
                source_path=src_path,
                name=name,
                source_id=uid,
                source_type="access-rule",
                source_attributes=rule,
                status=status,
                requires_manual_review=requires_review,
                notes=notes + review_reasons,
            ))

    return policies, inventory_items, unsupported_items
