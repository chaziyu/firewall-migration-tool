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
from fwmigrate.parsers.fortigate.dependencies import build_dependency_registry
from fwmigrate.parsers.fortigate.semantic_validation import (
    validate_internet_service_group_directions,
)
from fwmigrate.parsers.fortigate.parser import (
    FortiGateParser,
    POLICY_ROUTE_FAMILIES,
    SOURCE_ONLY_RULE_FAMILIES,
)
from fwmigrate.parsers.fortigate.section_scanner import scan_fortigate_sections
from fwmigrate.parsers.fortigate.tokenizer import FortiGateTokenizer
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer
from fwmigrate.ir.core import IRAuditEntry, MigrationConfidence


# These sections are preserved as typed/source-only objects because their
# behavior has no portable canonical equivalent yet.  A configured instance
# must therefore prevent an apparently complete target from being generated.
SOURCE_ONLY_OPERATIONAL_SECTIONS = {
    "firewall acl", "firewall acl6",
    "firewall interface-policy", "firewall interface-policy6",
    "firewall network-service-dynamic", "system sdn-connector",
    "system link-monitor", "system switch-interface",
    "system virtual-wire-pair", "system vdom-link", "system pppoe-interface",
    "vpn certificate crl", "vpn certificate ocsp-server", "vpn certificate setting",
    "system dns-server", "system dns64", "firewall dnstranslation",
    "firewall access-proxy", "firewall access-proxy6",
    "firewall access-proxy-virtual-host", "firewall access-proxy-ssh-client-cert",
    "endpoint-control fctems-override",
    "vpn ssl web realm", "vpn ssl web user-bookmark", "vpn ssl web group-bookmark",
    "vpn ipsec manualkey-interface",
    "user radius", "user tacacs+", "user peer", "user peergrp",
    "user fsso-polling", "user domain-controller", "user krb-keytab",
    "user certificate", "user external-identity-provider",
}

SOURCE_ONLY_TRAFFIC_SECTIONS = {
    *SOURCE_ONLY_RULE_FAMILIES,
    *POLICY_ROUTE_FAMILIES,
}

INTERFACE_IPV6_TYPED_COMMANDS = frozenset({
    "ip6-address",
    "ip6-allowaccess",
    "ip6-mode",
    "ip6-send-adv",
    "ip6-manage-flag",
    "ip6-other-flag",
    "autoconf", "cli-conn6-status", "dhcp6-client-options", "dhcp6-information-request",
    "dhcp6-prefix-delegation", "dhcp6-relay-interface-id", "dhcp6-relay-ip",
    "dhcp6-relay-service", "dhcp6-relay-source-interface", "dhcp6-relay-source-ip",
    "dhcp6-relay-type", "icmp6-send-redirect", "interface-identifier",
    "ip6-default-life", "ip6-delegated-prefix-iaid", "ip6-dns-server-override",
    "ip6-hop-limit", "ip6-link-mtu", "ip6-max-interval", "ip6-min-interval",
    "ip6-prefix-mode", "ip6-reachable-time", "ip6-retrans-time", "ip6-subnet",
    "ip6-upstream-interface",
})
def _is_typed_ipv6_interface_inventory(item) -> bool:
    """Identify the simple IPv6 interface block already represented in IR."""
    if "interface-nested-config" not in item.notes:
        return False
    if not item.source_path.endswith(" interface ipv6"):
        return False
    if not all(
        command.operation == "set"
        and str(command.key).replace("_", "-").lower()
        in INTERFACE_IPV6_TYPED_COMMANDS
        for command in item.commands
    ):
        return False
    return not item.children


def extract_fortigate_config(
    text: str,
    zone_mapping: Optional[Dict[str, str]] = None,
) -> ExtractionResult:
    source_sections = scan_fortigate_sections(text)

    parser = FortiGateParser(FortiGateTokenizer(text))
    fg_config = parser.parse()
    ir_config = FGToIRTransformer(fg_config, zone_mapping=zone_mapping or {}).transform()

    classify_section_coverage(source_sections, fg_config, ir_config)
    dependencies = build_dependency_registry(parser.source_inventory_items)
    unresolved_dependencies = [
        dependency for dependency in dependencies
        if dependency.result == "UNRESOLVED"
    ]
    for dependency in unresolved_dependencies:
        context = dependency.source_context or "root"
        section = next(
            (
                item for item in source_sections
                if item.path == dependency.source_path
                and (item.source_context or "root") == context
            ),
            None,
        )
        if section is not None:
            section.unresolved_dependencies += 1
            if section.status == ExtractionStatus.NORMALIZED:
                section.status = ExtractionStatus.PARTIALLY_NORMALIZED
            note = (
                f"Unresolved {dependency.source_field} reference "
                f"'{dependency.reference}' (expected {dependency.expected_type}) "
                "requires manual review."
            )
            if note not in section.notes:
                section.notes.append(note)
        ir_config.audit_entries.append(
            IRAuditEntry(
                id=(
                    f"dependency:{context}:{dependency.source_path}:"
                    f"{dependency.source_object or '<section>'}:"
                    f"{dependency.source_field}:{dependency.reference}"
                ),
                category="FortiGate Dependency",
                message=(
                    f"Unresolved reference '{dependency.reference}' in "
                    f"{dependency.source_path} field '{dependency.source_field}' "
                    f"(expected {dependency.expected_type}) in VDOM '{context}'. "
                    "The source reference was preserved and no target behavior was broadened."
                ),
                confidence=MigrationConfidence.MANUAL,
            )
        )
    semantic_findings = validate_internet_service_group_directions(
        parser.source_inventory_items,
        dependencies,
        ir_config,
    )
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
        if (
            status in {
                ExtractionStatus.EXTRACT_ONLY,
                ExtractionStatus.UNSUPPORTED,
            }
            and _is_typed_ipv6_interface_inventory(item)
        ):
            status = ExtractionStatus.NORMALIZED
        has_source_only_operation = any(
            command.operation in {"unset", "append"}
            for command in item.commands
        )
        item.status = status
        item.requires_manual_review = (
            status in {ExtractionStatus.PARTIALLY_NORMALIZED, ExtractionStatus.UNSUPPORTED, ExtractionStatus.PARSE_ERROR}
            or "structured-security-profile" in item.notes
            or extract_only_requires_manual_review(item.source_path)
            or item.source_path in SOURCE_ONLY_TRAFFIC_SECTIONS
            or item.source_path == "firewall central-snat-map"
            or has_source_only_operation
            or any(note.startswith("incompatible-internet-service-group-direction:") for note in item.notes)
        )
        item_dependencies = [
            dependency for dependency in unresolved_dependencies
            if dependency.source_context == item.source_context
            and dependency.source_path == item.source_path
            and dependency.source_object in {item.name, item.source_id}
        ]
        if item_dependencies:
            item.requires_manual_review = True
            item.notes.extend(
                f"unresolved-reference:{dependency.reference}"
                for dependency in item_dependencies
                if f"unresolved-reference:{dependency.reference}" not in item.notes
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
        if context.ngfw_mode == "policy-based":
            blocking_reasons.append(
                f"VDOM '{context.vdom}' uses policy-based NGFW mode; security-policy is not portable firewall-policy intent"
            )

    traffic_prefixes = (
        "firewall", "router", "vpn", "system", "system interface", "system dhcp",
        "system settings", "system sdwan", "authentication", "user group",
    )
    for section in source_sections:
        if section.status in {ExtractionStatus.UNSUPPORTED, ExtractionStatus.PARSE_ERROR} and section.path.startswith(traffic_prefixes):
            blocking_reasons.append(
                f"{section.status.value}: {section.path}"
                + (f" in VDOM '{section.source_context}'" if section.source_context else "")
            )

        if (
            section.path in SOURCE_ONLY_OPERATIONAL_SECTIONS
            and section.object_count_source > 0
        ):
            blocking_reasons.append(
                f"FortiGate {section.path} is retained as source-only operational semantics"
                + (f" in VDOM '{section.source_context}'" if section.source_context else "")
            )

    for dependency in unresolved_dependencies:
        context = dependency.source_context or "root"
        blocking_reasons.append(
            f"Unresolved FortiGate reference '{dependency.reference}' in "
            f"{dependency.source_path} field '{dependency.source_field}' "
            f"(expected {dependency.expected_type}) in VDOM '{context}'"
        )
    blocking_reasons.extend(semantic_findings)

    critical_collections = (
        ir_config.interfaces, ir_config.policies, ir_config.nat_rules, ir_config.routes,
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

    if any(sdwan.health_checks for sdwan in ir_config.sdwans):
        blocking_reasons.append("FortiGate SD-WAN health checks are extract-only and require manual review")

    # These rule families are intentionally retained outside portable canonical
    # policy/routing/NAT models.  Their presence is therefore a migration and
    # generation blocker, not merely an inventory annotation.  Otherwise a
    # configured PBR, local-in rule, proxy rule, DHCPv6 server, or similar
    # source-only traffic construct could coexist with generation_safe=True.
    source_only_rule_collections = (
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

    # Nested interface nodes are separately tracked in source inventory as
    # well as being retained on their parent IRInterface. Keep this check
    # independent of the parent collection so an extract-only or unsupported
    # nested block cannot be mistaken for a fully normalized interface.
    for item in parser.source_inventory_items:
        if "interface-nested-config" not in item.notes:
            continue
        if item.status == ExtractionStatus.NORMALIZED:
            continue
        context = item.source_context or "root"
        blocking_reasons.append(
            f"FortiGate nested interface configuration '{item.source_path}' "
            f"in VDOM '{context}' is retained as {item.status.value} "
            "source semantics"
        )

    blocking_reasons = list(dict.fromkeys(blocking_reasons))
    requires_review = bool(blocking_reasons) or any(
        item.requires_manual_review for item in inventory_items
    )

    ir_config.generation_safe = not blocking_reasons
    ir_config.generation_blocking_reasons = list(blocking_reasons)
    ir_config.requires_manual_review = requires_review

    return ExtractionResult(
        canonical_ir=ir_config,
        source_sections=source_sections,
        inventory_items=inventory_items,
        unsupported_items=unsupported_items,
        dependencies=dependencies,
        requires_manual_review=requires_review,
        migration_complete=not blocking_reasons,
        generation_safe=not blocking_reasons,
        blocking_reasons=blocking_reasons,
    )
