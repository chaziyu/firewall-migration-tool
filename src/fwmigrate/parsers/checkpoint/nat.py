"""Check Point NAT rulebase extraction and translation mode typing."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from fwmigrate.extraction.models import (
    ExtractionStatus,
    SourceInventoryItem,
    UnsupportedItem,
)
from fwmigrate.ir.core import IRNATRule
from fwmigrate.ir.enums import NATTranslationMode, NATType
from fwmigrate.parsers.checkpoint.loader import canonicalize_command
from fwmigrate.parsers.checkpoint.models import CheckPointResponse, ScopeSelectionResult
from fwmigrate.parsers.checkpoint.resolver import (
    CheckPointObjectResolver,
    SemanticKind,
    is_any_object,
    is_original_object,
)
from fwmigrate.parsers.checkpoint.rulebase import flatten_rulebase


def extract_nat_rulebase(
    responses: List[CheckPointResponse],
    resolver: CheckPointObjectResolver,
    scope: ScopeSelectionResult,
) -> Tuple[List[IRNATRule], List[SourceInventoryItem], List[UnsupportedItem]]:
    """Extract Check Point NAT rulebase into canonical IRNATRules."""
    nat_rules: List[IRNATRule] = []
    inventory_items: List[SourceInventoryItem] = []
    unsupported_items: List[UnsupportedItem] = []

    for resp in responses:
        cmd = canonicalize_command(resp.command)
        if cmd != "show-nat-rulebase":
            continue

        package = resp.package or "Standard"
        domain = resp.domain or "global"
        src_path = f"checkpoint/{cmd}/{package}"

        # Scope isolation
        is_in_scope = True
        if scope.selected_package and package != scope.selected_package:
            is_in_scope = False

        data = resp.data
        raw_rules = data.get("rulebase", [])
        flattened = flatten_rulebase(raw_rules)

        for rule, section_title in flattened:
            uid = rule.get("uid")
            rule_num = rule.get("rule-number")
            name = rule.get("name") or f"NAT_Rule_{rule_num or len(nat_rules) + 1}"
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
                review_reasons.append("out-of-scope-package")
                notes.append(f"NAT rule belongs to unselected package '{package}'")

            # Resolve original source
            orig_src = rule.get("original-source")
            sources: List[str] = []
            if orig_src:
                res = resolver.resolve(orig_src, domain=domain)
                if res.resolved and res.canonical_name:
                    sources.append(res.canonical_name)
                    if not resolver.is_dependency_safe(orig_src, domain=domain):
                        requires_review = True
                        review_reasons.append(f"tainted-nat-source:{res.name or res.uid}")
                else:
                    requires_review = True
                    unresolved_id = res.uid or (res.name if res.name else str(orig_src))
                    review_reasons.append(f"unresolved-nat-source:{unresolved_id}")
            else:
                sources = ["any"]

            # Resolve original destination
            orig_dst = rule.get("original-destination")
            destinations: List[str] = []
            if orig_dst:
                res = resolver.resolve(orig_dst, domain=domain)
                if res.resolved and res.canonical_name:
                    destinations.append(res.canonical_name)
                    if not resolver.is_dependency_safe(orig_dst, domain=domain):
                        requires_review = True
                        review_reasons.append(f"tainted-nat-destination:{res.name or res.uid}")
                else:
                    requires_review = True
                    unresolved_id = res.uid or (res.name if res.name else str(orig_dst))
                    review_reasons.append(f"unresolved-nat-destination:{unresolved_id}")
            else:
                destinations = ["any"]

            # Resolve original service
            orig_svc = rule.get("original-service")
            services: List[str] = []
            if orig_svc:
                res = resolver.resolve(orig_svc, domain=domain)
                if res.resolved and res.canonical_name:
                    services.append(res.canonical_name)
                    if not resolver.is_dependency_safe(orig_svc, domain=domain):
                        requires_review = True
                        review_reasons.append(f"tainted-nat-service:{res.name or res.uid}")
                else:
                    requires_review = True
                    unresolved_id = res.uid or (res.name if res.name else str(orig_svc))
                    review_reasons.append(f"unresolved-nat-service:{unresolved_id}")
            else:
                services = ["any"]

            # Resolve translated source
            trans_src = rule.get("translated-source")
            translated_sources: List[str] = []
            trans_src_is_original = is_original_object(trans_src)
            trans_src_is_any = is_any_object(trans_src)

            if trans_src and not trans_src_is_original and not trans_src_is_any:
                res = resolver.resolve(trans_src, domain=domain)
                if res.resolved and res.canonical_name:
                    translated_sources.append(res.canonical_name)
                    if not resolver.is_dependency_safe(trans_src, domain=domain):
                        requires_review = True
                        review_reasons.append(f"tainted-translated-source:{res.name or res.uid}")
                else:
                    requires_review = True
                    unresolved_id = res.uid or (res.name if res.name else str(trans_src))
                    review_reasons.append(f"unresolved-translated-source:{unresolved_id}")

            # Resolve translated destination
            trans_dst = rule.get("translated-destination")
            translated_destinations: List[str] = []
            trans_dst_is_original = is_original_object(trans_dst)
            trans_dst_is_any = is_any_object(trans_dst)

            if trans_dst and not trans_dst_is_original and not trans_dst_is_any:
                res = resolver.resolve(trans_dst, domain=domain)
                if res.resolved and res.canonical_name:
                    translated_destinations.append(res.canonical_name)
                    if not resolver.is_dependency_safe(trans_dst, domain=domain):
                        requires_review = True
                        review_reasons.append(f"tainted-translated-destination:{res.name or res.uid}")
                else:
                    requires_review = True
                    unresolved_id = res.uid or (res.name if res.name else str(trans_dst))
                    review_reasons.append(f"unresolved-translated-destination:{unresolved_id}")

            # Resolve translated service
            trans_svc = rule.get("translated-service")
            translated_services: List[str] = []
            trans_svc_is_original = is_original_object(trans_svc)
            trans_svc_is_any = is_any_object(trans_svc)

            if trans_svc and not trans_svc_is_original and not trans_svc_is_any:
                res = resolver.resolve(trans_svc, domain=domain)
                if res.resolved and res.canonical_name:
                    translated_services.append(res.canonical_name)
                    if not resolver.is_dependency_safe(trans_svc, domain=domain):
                        requires_review = True
                        review_reasons.append(f"tainted-translated-service:{res.name or res.uid}")
                else:
                    requires_review = True
                    unresolved_id = res.uid or (res.name if res.name else str(trans_svc))
                    review_reasons.append(f"unresolved-translated-service:{unresolved_id}")

            # Determine NAT Type
            nat_type: NATType
            if translated_sources and translated_destinations:
                nat_type = NATType.TWICE
            elif translated_destinations:
                nat_type = NATType.DESTINATION
            elif translated_sources or trans_src_is_any:
                nat_type = NATType.SOURCE
            else:
                # Default to SOURCE if neither is explicitly defined
                nat_type = NATType.SOURCE

            # Source translation mode
            src_mode: Optional[NATTranslationMode] = None
            if nat_type in (NATType.SOURCE, NATType.TWICE):
                if translated_sources:
                    src_mode = NATTranslationMode.DYNAMIC_IP_AND_PORT
                elif trans_src_is_any:
                    src_mode = NATTranslationMode.INTERFACE_ADDRESS
                else:
                    src_mode = NATTranslationMode.NONE

            if requires_review and status == ExtractionStatus.NORMALIZED:
                status = ExtractionStatus.PARTIALLY_NORMALIZED

            # Construct canonical IRNATRule
            ir_nat = IRNATRule(
                name=name,
                type=nat_type,
                source_rule_id=str(rule_num) if rule_num is not None else None,
                enabled=enabled,
                from_zone=["any"],
                to_zone=["any"],
                source=sources or ["any"],
                destination=destinations or ["any"],
                services=services or ["any"],
                translated_sources=translated_sources,
                translated_destinations=translated_destinations,
                translated_services=translated_services,
                source_translation_mode=src_mode,
                migration_status=status.value,
                review_reasons=review_reasons,
                requires_manual_review=requires_review,
                source_attributes=rule,
                description=comments,
            )
            nat_rules.append(ir_nat)

            # Construct Leaf Inventory Item
            inventory_items.append(SourceInventoryItem(
                domain=domain,
                source_path=src_path,
                name=name,
                source_id=uid,
                source_type="nat-rule",
                source_attributes=rule,
                status=status,
                requires_manual_review=requires_review,
                notes=notes + review_reasons,
            ))

    return nat_rules, inventory_items, unsupported_items
