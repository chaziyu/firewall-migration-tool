"""High-level FortiGate source extraction orchestration."""

from __future__ import annotations

from typing import Dict, Optional

from fwmigrate.extraction.models import (
    ExtractionResult,
    ExtractionStatus,
    UnsupportedItem,
)
from fwmigrate.parsers.fortigate.coverage import (
    classify_section_coverage,
    extract_only_requires_manual_review,
)
from fwmigrate.parsers.fortigate.parser import FortiGateParser, SOURCE_ONLY_RULE_FAMILIES
from fwmigrate.parsers.fortigate.section_scanner import scan_fortigate_sections
from fwmigrate.parsers.fortigate.tokenizer import FortiGateTokenizer
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer


def extract_fortigate_config(
    text: str,
    zone_mapping: Optional[Dict[str, str]] = None,
) -> ExtractionResult:
    source_sections = scan_fortigate_sections(text)

    parser = FortiGateParser(FortiGateTokenizer(text))
    fg_config = parser.parse()
    ir_config = FGToIRTransformer(fg_config, zone_mapping=zone_mapping or {}).transform()

    classify_section_coverage(source_sections, fg_config, ir_config)
    status_by_path = {
        (section.path, section.source_context): section.status
        for section in source_sections
    }
    policy_safety = {
        (policy.source_context or "root", policy.source_rule_id): policy
        for policy in ir_config.policies
    }

    inventory_items = []
    for item in parser.source_inventory_items:
        context = item.source_context or "root"
        status = status_by_path.get(
            (item.source_path, item.source_context),
            status_by_path.get((item.source_path, None), ExtractionStatus.UNSUPPORTED),
        )
        has_source_only_operation = any(
            command.operation in {"unset", "append"}
            for command in item.commands
        )
        item.status = status
        item.requires_manual_review = (
            status in {ExtractionStatus.PARTIALLY_NORMALIZED, ExtractionStatus.UNSUPPORTED, ExtractionStatus.PARSE_ERROR}
            or "structured-security-profile" in item.notes
            or extract_only_requires_manual_review(item.source_path)
            or item.source_path in SOURCE_ONLY_RULE_FAMILIES
            or item.source_path == "firewall central-snat-map"
            or has_source_only_operation
        )
        include_item = (
            status in {
                ExtractionStatus.EXTRACT_ONLY,
                ExtractionStatus.VENDOR_EXTENSION,
                ExtractionStatus.UNSUPPORTED,
            }
            or has_source_only_operation
            or (status == ExtractionStatus.PARTIALLY_NORMALIZED and item.name is None)
            or item.source_path in {
                "firewall policy", "firewall ippool", "firewall ippool6",
                "firewall vip", "firewall vip realservers", "firewall vip6",
                "firewall vip6 realservers", "firewall vipgrp", "firewall vipgrp6",
                "firewall central-snat-map", "firewall security-policy",
                "router policy", "router policy6", "system dhcp6 server",
                "firewall local-in-policy", "firewall local-in-policy6",
                "firewall proxy-policy", "firewall shaping-policy",
            }
        )
        if not include_item:
            continue
        if item.source_path == "firewall policy" and item.source_id:
            policy = policy_safety.get((context, item.source_id))
            if policy and (
                policy.requires_manual_review
                or policy.migration_status != "NORMALIZED"
                or policy.review_reasons
            ):
                item.status = ExtractionStatus.PARTIALLY_NORMALIZED
                item.requires_manual_review = True
                item.notes.extend(
                    reason for reason in policy.review_reasons if reason not in item.notes
                )
        inventory_items.append(item)

    unsupported_items = [
        UnsupportedItem(
            source_path=section.path,
            reason=f"FortiGate section '{section.path}' is not supported for canonical migration.",
            requires_manual_review=True,
        )
        for section in source_sections
        if section.status == ExtractionStatus.UNSUPPORTED
    ]

    blocking_reasons = []
    configured_contexts = {context.vdom for context in fg_config.execution_contexts}
    configured_contexts.update(
        item.source_context
        for item in parser.source_inventory_items
        if item.source_context
    )
    if len(configured_contexts) > 1:
        blocking_reasons.append(
            "Multiple FortiGate VDOMs are present; target generation requires an explicit context-to-target-scope mapping"
        )
    for context in fg_config.execution_contexts:
        if context.central_nat == "enable":
            blocking_reasons.append(
                f"VDOM '{context.vdom}' has central NAT enabled; central-snat-map is retained for manual migration"
            )
        if context.ngfw_mode == "policy-based":
            blocking_reasons.append(
                f"VDOM '{context.vdom}' uses policy-based NGFW mode; security-policy is not portable firewall-policy intent"
            )

    traffic_prefixes = (
        "firewall", "router", "vpn", "system interface", "system dhcp",
        "system settings", "system sdwan", "authentication", "user group",
    )
    for section in source_sections:
        if section.status in {ExtractionStatus.UNSUPPORTED, ExtractionStatus.PARSE_ERROR} and section.path.startswith(traffic_prefixes):
            blocking_reasons.append(
                f"{section.status.value}: {section.path}"
                + (f" in VDOM '{section.source_context}'" if section.source_context else "")
            )

    critical_collections = (
        ir_config.policies, ir_config.nat_rules, ir_config.routes,
        ir_config.addresses, ir_config.address_groups, ir_config.services,
        ir_config.service_groups,
    )
    if any(
        getattr(obj, "requires_manual_review", False)
        or getattr(obj, "migration_status", "NORMALIZED") != "NORMALIZED"
        or bool(getattr(obj, "review_reasons", []))
        for collection in critical_collections for obj in collection
    ):
        blocking_reasons.append("One or more traffic-affecting canonical objects require manual review")

    # These rule families are intentionally retained outside portable canonical
    # policy/routing/NAT models.  Their presence is therefore a migration and
    # generation blocker, not merely an inventory annotation.  Otherwise a
    # configured PBR, local-in rule, proxy rule, DHCPv6 server, or similar
    # source-only traffic construct could coexist with generation_safe=True.
    source_only_rule_collections = (
        ir_config.central_snat_rules,
        ir_config.security_policies,
        ir_config.policy_routes,
        ir_config.local_in_policies,
        ir_config.proxy_policies,
        ir_config.shaping_policies,
        ir_config.dhcp6_servers,
        ir_config.source_only_rules,
    )
    for collection in source_only_rule_collections:
        for rule in collection:
            context = rule.source_context or "root"
            source_id = f" {rule.source_id}" if rule.source_id is not None else ""
            blocking_reasons.append(
                f"FortiGate {rule.family}{source_id} in VDOM '{context}' is retained as source-only traffic semantics"
            )

    blocking_reasons = list(dict.fromkeys(blocking_reasons))
    requires_review = bool(blocking_reasons) or any(
        item.requires_manual_review for item in inventory_items
    )

    return ExtractionResult(
        canonical_ir=ir_config,
        source_sections=source_sections,
        inventory_items=inventory_items,
        unsupported_items=unsupported_items,
        requires_manual_review=requires_review,
        migration_complete=not blocking_reasons,
        generation_safe=not blocking_reasons,
        blocking_reasons=blocking_reasons,
    )
