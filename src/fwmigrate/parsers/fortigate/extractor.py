"""High-level FortiGate source extraction orchestration."""

from __future__ import annotations

import re
from typing import Dict, Optional

from fwmigrate.extraction.models import (
    ExtractionResult,
    ExtractionStatus,
    SourceCommand,
    SourceInventoryItem,
    UnsupportedItem,
)
from fwmigrate.parsers.fortigate.coverage import (
    classify_section_coverage,
    extract_only_requires_manual_review,
)
from fwmigrate.parsers.fortigate.dependencies import build_dependency_registry
from fwmigrate.parsers.fortigate.dependencies import _norm
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
from fwmigrate.ir.metadata import IRAuditEntry
from fwmigrate.ir.provenance import IRSourceConfigCommand
from fwmigrate.ir.enums import MigrationConfidence


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
    "system dns-server", "system dns64", "system fsso-polling", "firewall dnstranslation",
    "firewall access-proxy", "firewall access-proxy6",
    "firewall access-proxy-virtual-host", "firewall access-proxy-ssh-client-cert",
    "firewall ipv6-eh-filter",
    "firewall address6-template",
    "firewall ippool_grp",
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

IPV6_TYPED_CHILDREN = frozenset({
    "ip6-extra-addr",
    "ip6-prefix-list",
    "ip6-delegated-prefix-list",
    "dhcp6-iapd-list",
    "vrrp6",
})
IPV6_CHILD_FIELDS = {
    "ip6-extra-addr": set(),
    "ip6-prefix-list": {
        "autonomous-flag", "dnssl", "onlink-flag",
        "preferred-life-time", "rdnss", "valid-life-time",
    },
    "ip6-delegated-prefix-list": {
        "autonomous-flag", "delegated-prefix-iaid", "onlink-flag",
        "rdnss", "rdnss-service", "subnet", "upstream-interface",
    },
    "dhcp6-iapd-list": {"prefix-hint", "prefix-hint-plt", "prefix-hint-vlt"},
    "vrrp6": {
        "accept-mode", "adv-interval", "ignore-default-route", "preempt",
        "priority", "start-time", "status", "vrdst6", "vrdst6-priority",
        "vrgrp", "vrip6",
    },
}


def _is_typed_ipv6_interface_inventory(item) -> bool:
    """Identify the IPv6 interface subtree represented by typed source models."""
    if "interface-nested-config" not in item.notes:
        return False
    if not item.source_path.endswith(" interface ipv6"):
        return False
    if not all(
        command.operation in {"set", "append", "unset"}
        and str(command.key).replace("_", "-").lower()
        in INTERFACE_IPV6_TYPED_COMMANDS
        for command in item.commands
    ):
        return False

    def valid_child(node, section_name: Optional[str] = None) -> bool:
        current_section = section_name
        if node.source_path != item.source_path:
            suffix = node.source_path[len(item.source_path):].strip()
            if suffix:
                current_section = suffix.split()[0]
        if current_section and current_section not in IPV6_TYPED_CHILDREN:
            return False
        allowed_fields = IPV6_CHILD_FIELDS.get(current_section, set())
        for command in node.commands:
            key = str(command.key).replace("_", "-").lower()
            if command.operation not in {"set", "append", "unset"}:
                return False
            if current_section and key not in allowed_fields:
                return False
        return all(valid_child(child, current_section) for child in node.children)

    return all(valid_child(child) for child in item.children)


_GENERIC_CANONICAL_REVIEW_BLOCKER = (
    "One or more traffic-affecting canonical objects require manual review"
)


def _find_unquoted_hash(line: str) -> int | None:
    quote: str | None = None
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if char == "\\" and quote is not None:
            escaped = True
            continue
        if quote is not None:
            if char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if char == "#":
            return index
    return None


def _unsupported_source_lines(text: str) -> list[tuple[int, str, str]]:
    findings: list[tuple[int, str, str]] = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if re.match(r"^select(?:\s+|$)", stripped, flags=re.IGNORECASE):
            findings.append((line_number, "select", stripped))
            continue
        hash_index = _find_unquoted_hash(raw_line)
        if hash_index is not None and raw_line[:hash_index].strip():
            findings.append((line_number, "inline-comment", stripped))
    return findings


def _normalize_complete_vip_groups(ir) -> None:
    for group in getattr(ir, "virtual_ip_groups", []):
        if getattr(group, "unresolved_members", []):
            continue
        if getattr(group, "source_attributes", {}):
            continue
        group.migration_status = "NORMALIZED"
        group.requires_manual_review = False
        if getattr(group, "audit_note", None) and "unresolved" not in group.audit_note.lower():
            group.audit_note = None


def _critical_review_objects(ir):
    ipv4_pools = [
        pool for pool in getattr(ir, "ip_pools", [])
        if getattr(pool, "address_family", "ipv4") == "ipv4"
    ]
    collections = (
        getattr(ir, "interfaces", []),
        getattr(ir, "policies", []),
        getattr(ir, "multicast_policies", []),
        getattr(ir, "nat_rules", []),
        getattr(ir, "routes", []),
        getattr(ir, "addresses", []),
        getattr(ir, "address_groups", []),
        getattr(ir, "services", []),
        getattr(ir, "service_groups", []),
        ipv4_pools,
        getattr(ir, "virtual_ips", []),
    )
    for collection in collections:
        yield from collection


def _sync_vip_group_status(result) -> None:
    ir = result.canonical_ir
    groups = {
        (
            getattr(group, "source_context", None) or "root",
            group.name,
            getattr(group, "address_family", "ipv4"),
        ): group
        for group in getattr(ir, "virtual_ip_groups", [])
    }
    for item in result.inventory_items:
        if item.source_path not in {"firewall vipgrp", "firewall vipgrp6"} or not item.name:
            continue
        context = item.source_context or "root"
        family = "ipv6" if item.source_path.endswith("vipgrp6") else "ipv4"
        group = groups.get((context, item.name, family))
        if (
            group
            and group.migration_status == "NORMALIZED"
            and not group.requires_manual_review
            and not getattr(group, "source_attributes", {})
        ):
            item.status = ExtractionStatus.NORMALIZED
            item.requires_manual_review = False

    for section in result.source_sections:
        if section.path not in {"firewall vipgrp", "firewall vipgrp6"}:
            continue
        family = "ipv6" if section.path.endswith("vipgrp6") else "ipv4"
        context = section.source_context or "root"
        section_groups = [
            group
            for (group_context, _, item_family), group in groups.items()
            if group_context == context and item_family == family
        ]
        if section_groups and all(
            group.migration_status == "NORMALIZED"
            and not group.requires_manual_review
            and not getattr(group, "source_attributes", {})
            for group in section_groups
        ):
            section.status = ExtractionStatus.NORMALIZED


def _remove_resolved_source_only_blockers(result) -> None:
    ir = result.canonical_ir
    blockers = list(result.blocking_reasons)
    if _GENERIC_CANONICAL_REVIEW_BLOCKER in blockers:
        still_unsafe = any(
            getattr(obj, "requires_manual_review", False)
            or getattr(obj, "migration_status", "NORMALIZED") != "NORMALIZED"
            or bool(getattr(obj, "review_reasons", []))
            for obj in _critical_review_objects(ir)
        )
        if not still_unsafe:
            blockers.remove(_GENERIC_CANONICAL_REVIEW_BLOCKER)
    result.blocking_reasons = list(dict.fromkeys(blockers))
    ir.generation_blocking_reasons = list(result.blocking_reasons)
    result.generation_safe = not result.blocking_reasons
    result.migration_complete = not result.blocking_reasons
    ir.generation_safe = result.generation_safe


def _record_unsupported_syntax(
    result,
    findings: list[tuple[int, str, str]],
) -> None:
    if not findings:
        return
    for line_number, kind, raw in findings:
        if kind == "select":
            parts = raw.split()
            values = parts[1:]
            message = (
                f"Unsupported FortiOS select operation at line {line_number}; "
                "interactive selection semantics are not applied during configuration extraction."
            )
            result.inventory_items.append(
                SourceInventoryItem(
                    domain="unsupported-cli",
                    source_path="unsupported select",
                    commands=[
                        SourceCommand(
                            operation="select",
                            key=values[0] if values else "",
                            values=values[1:] if len(values) > 1 else [],
                            line_number=line_number,
                            status=ExtractionStatus.UNSUPPORTED,
                            requires_manual_review=True,
                        )
                    ],
                    status=ExtractionStatus.UNSUPPORTED,
                    requires_manual_review=True,
                    notes=["unsupported-interactive-operation"],
                )
            )
        else:
            message = (
                f"Unsupported unquoted inline comment syntax at line {line_number}; "
                "the source line is retained for review instead of guessing where the command ends."
            )
        result.unsupported_items.append(
            UnsupportedItem(
                source_path="raw configuration",
                reason=message,
                requires_manual_review=True,
                raw_capture=raw,
            )
        )
        result.blocking_reasons.append(message)
    result.blocking_reasons = list(dict.fromkeys(result.blocking_reasons))
    result.requires_manual_review = True
    result.generation_safe = False
    result.migration_complete = False
    ir = result.canonical_ir
    ir.requires_manual_review = True
    ir.generation_safe = False
    ir.generation_blocking_reasons = list(
        dict.fromkeys([*ir.generation_blocking_reasons, *result.blocking_reasons])
    )


def _apply_structured_extraction_regressions(result) -> None:
    for inventory in result.inventory_items:
        if _is_typed_ipv6_interface_inventory(inventory):
            inventory.requires_manual_review = bool(
                inventory.notes and any(
                    note.startswith("unresolved-reference:")
                    or note.startswith("incompatible-")
                    for note in inventory.notes
                )
            )

    reviewed_nested_ipv6 = any(
        interface.requires_manual_review
        and any(node.name == "ipv6" for node in interface.nested_source_configs)
        for interface in result.canonical_ir.interfaces
    )
    if not reviewed_nested_ipv6:
        return

    nested_reason = (
        "FortiGate nested interface configuration contains source-specific "
        "IPv6 behavior requiring target-platform review"
    )
    if any("nested interface configuration" in reason for reason in result.blocking_reasons):
        return
    result.blocking_reasons.append(nested_reason)
    result.requires_manual_review = True
    result.migration_complete = False
    result.generation_safe = False
    result.canonical_ir.requires_manual_review = True
    result.canonical_ir.generation_safe = False
    if nested_reason not in result.canonical_ir.generation_blocking_reasons:
        result.canonical_ir.generation_blocking_reasons.append(nested_reason)


def extract_fortigate_config(
    text: str,
    zone_mapping: Optional[Dict[str, str]] = None,
) -> ExtractionResult:
    source_sections = scan_fortigate_sections(text)

    parser = FortiGateParser(FortiGateTokenizer(text))
    fg_config = parser.parse()
    ir_config = FGToIRTransformer(fg_config, zone_mapping=zone_mapping or {}).transform()
    policy_inventory: Dict[tuple[str, str], list[SourceInventoryItem]] = {}
    for item in parser.source_inventory_items:
        if item.source_path == "firewall policy":
            policy_inventory.setdefault(
                (item.source_context or "root", str(item.source_id)),
                [],
            ).append(item)
    for policy in ir_config.policies:
        matches = policy_inventory.get(
            (policy.source_context or "root", str(policy.source_rule_id)),
            [],
        )
        extra_keys = {
            str(key).replace("-", "_")
            for key in policy.source_extra_settings
        }
        extra_keys.update(
            str(key).replace("-", "_")
            for key in policy.source_extra_settings.get("source_unset_settings", [])
        )
        policy.source_extra_setting_commands = [
            IRSourceConfigCommand(
                operation=command.operation,
                key=command.key,
                values=list(command.values),
            )
            for item in matches
            for command in item.commands
            if command.key.replace("-", "_") in extra_keys
        ]

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
    vip_group_safety = {
        (group.source_context or "root", group.name, group.address_family): group
        for group in ir_config.virtual_ip_groups
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
            and _norm(dependency.source_path) == _norm(item.source_path)
            and dependency.source_object in {item.name, item.source_id}
        ]
        if item_dependencies:
            item.requires_manual_review = True
            item.notes.extend(
                f"unresolved-reference:{dependency.reference}"
                for dependency in item_dependencies
                if f"unresolved-reference:{dependency.reference}" not in item.notes
            )
        if item.source_path in {"firewall vipgrp", "firewall vipgrp6"}:
            family = "ipv6" if item.source_path == "firewall vipgrp6" else "ipv4"
            group = vip_group_safety.get((context, item.name, family))
            if group:
                if group.audit_note and group.audit_note not in item.notes:
                    item.notes.append(group.audit_note)
                if family == "ipv6":
                    item.status = (
                        ExtractionStatus.PARTIALLY_NORMALIZED
                        if group.requires_manual_review
                        or group.migration_status != "NORMALIZED"
                        else ExtractionStatus.NORMALIZED
                    )
                    item.requires_manual_review = (
                        group.requires_manual_review
                        or group.migration_status != "NORMALIZED"
                        or has_source_only_operation
                        or any(note.startswith("unresolved-reference:") for note in item.notes)
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
                "firewall multicast-policy", "firewall multicast-policy6",
                "firewall vip", "firewall vip realservers", "firewall vip6",
                "firewall vip6 realservers", "firewall vipgrp", "firewall vipgrp6",
                "firewall central-snat-map", "firewall security-policy",
                "firewall ip-translation",
                "router policy", "router policy6", "system dhcp6 server",
                "system dhcp server",
                "firewall local-in-policy", "firewall local-in-policy6",
                "firewall proxy-policy", "firewall shaping-policy",
            }
            or item.source_path.startswith("system dhcp server ")
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
    for extension in ir_config.internet_service_extensions:
        children = [*extension.disable_entries, *extension.entries]
        nested = [
            port for entry in children for port in entry.port_ranges
        ]
        nested.extend(
            range_item
            for entry in extension.disable_entries
            for range_item in [*entry.ipv4_ranges, *entry.ipv6_ranges]
        )
        if any(item.source_attributes.get("invalid_fields") for item in [*children, *nested]):
            blocking_reasons.append(
                f"FortiGate Internet Service extension '{extension.source_id}' contains invalid typed source values"
            )

    ipv4_ip_pools = [
        pool for pool in ir_config.ip_pools if pool.address_family == "ipv4"
    ]
    critical_collections = (
        ir_config.interfaces, ir_config.policies, ir_config.multicast_policies,
        ir_config.nat_rules, ir_config.routes,
        ir_config.addresses, ir_config.address_groups, ir_config.services,
        ir_config.service_groups, ipv4_ip_pools, ir_config.virtual_ips,
    )
    if ir_config.dhcp_servers:
        blocking_reasons.append(
            "FortiGate DHCP servers are extract-only and require manual review"
        )
    if any(
        getattr(obj, "requires_manual_review", False)
        or getattr(obj, "migration_status", "NORMALIZED") != "NORMALIZED"
        or bool(getattr(obj, "review_reasons", []))
        for collection in critical_collections for obj in collection
    ):
        blocking_reasons.append("One or more traffic-affecting canonical objects require manual review")

    if any(sdwan.health_checks for sdwan in ir_config.vendor_extensions.fortios.sdwans):
        blocking_reasons.append("FortiGate SD-WAN health checks are extract-only and require manual review")

    # These rule families are intentionally retained outside portable canonical
    # policy/routing/NAT models.  Their presence is therefore a migration and
    # generation blocker, not merely an inventory annotation.  Otherwise a
    # configured PBR, local-in rule, proxy rule, DHCPv6 server, or similar
    # source-only traffic construct could coexist with generation_safe=True.
    source_only_rule_collections = (
        ir_config.vendor_extensions.fortios.security_policies,
        ir_config.vendor_extensions.fortios.policy_routes,
        ir_config.vendor_extensions.fortios.local_in_policies,
        ir_config.vendor_extensions.fortios.proxy_policies,
        ir_config.vendor_extensions.fortios.shaping_policies,
        ir_config.vendor_extensions.fortios.dhcp6_servers,
        ir_config.vendor_extensions.fortios.source_only_rules,
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

    result = ExtractionResult(
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
    _normalize_complete_vip_groups(result.canonical_ir)
    _sync_vip_group_status(result)
    _remove_resolved_source_only_blockers(result)
    _apply_structured_extraction_regressions(result)
    _record_unsupported_syntax(result, _unsupported_source_lines(text))
    result.requires_manual_review = bool(result.blocking_reasons) or any(
        item.requires_manual_review for item in result.inventory_items
    )
    result.canonical_ir.requires_manual_review = result.requires_manual_review
    return result
