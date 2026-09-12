"""Extraction coverage and accounting builder for Juniper SRX JunOS configurations."""

from __future__ import annotations

from collections import defaultdict
import ipaddress
from typing import List, Sequence

from fwmigrate.extraction.models import (
    ExtractionResult,
    DependencyRecord,
    ExtractionStatus,
    SourceCommand,
    SourceInventoryItem,
    SourceSectionResult,
    UnsupportedItem,
)
from fwmigrate.ir.core import IRConfig
from fwmigrate.parsers.juniper_srx.extraction import sanitize_tokens
from fwmigrate.parsers.juniper_srx.tokenizer import JunosCommand, JunosOperation
from fwmigrate.parsers.juniper_srx.resolver import JuniperReferenceResolver


def build_juniper_dependencies(config) -> List[DependencyRecord]:
    """Return typed Junos object-reference results for the report registry."""
    dependencies: List[DependencyRecord] = []

    def add(context, path, obj, field, reference, expected, resolved, notes=None):
        dependencies.append(
            DependencyRecord(
                source_context=None if context.name == "root" else context.name,
                source_path=path,
                source_object=obj,
                source_field=field,
                reference=str(reference),
                expected_type=expected,
                result="RESOLVED" if resolved else "UNRESOLVED",
                target_path=path if resolved else None,
                notes=notes,
            )
        )

    def scalar_is_literal(value):
        if str(value).lower() in {"any", "any-ipv4", "any-ipv6"}:
            return True
        try:
            ipaddress.ip_network(str(value), strict=False)
            return True
        except ValueError:
            return False

    for context in config.contexts.values():
        interfaces = context.interfaces

        def interface_exists(reference):
            if reference in interfaces:
                return True
            if "." not in reference:
                return False
            parent, unit = reference.rsplit(".", 1)
            return parent in interfaces and unit in interfaces[parent].units

        for interface in interfaces.values():
            for unit in interface.units.values():
                add(context, "interfaces", f"{interface.name}.{unit.unit}", "parent", interface.name, "physical-interface", interface.name in interfaces)

        for zone in context.zones.values():
            for interface in zone.interfaces:
                add(context, "security zones", zone.name, "interfaces", interface, "interface", interface_exists(interface))

        for instance in context.routing_instances.values():
            for interface in instance.interfaces:
                add(context, "routing-instances", instance.name, "interfaces", interface, "interface", interface_exists(interface))

        for book in context.address_books.values():
            for zone in book.attached_zones:
                add(context, "security address-book", book.name, "attach zone", zone, "security-zone", zone in context.zones)

        resolver = JuniperReferenceResolver(context)
        for policy in [*context.policies, *context.global_policies]:
            for zone in [*policy.from_zones, *policy.to_zones]:
                add(context, "security policies", policy.name, "zone", zone, "security-zone", zone in context.zones)
            for field, references in (
                ("source-address", policy.source_addresses),
                ("destination-address", policy.destination_addresses),
            ):
                for reference in references:
                    if not scalar_is_literal(reference):
                        result = resolver.resolve_global_policy(reference) if policy.policy_scope == "global" else resolver.resolve_policy_source(policy.from_zone, reference)
                        add(context, "security policies", policy.name, field, reference, "address/address-set", not result.is_unresolved)
            for reference in policy.applications:
                exists = resolver.resolve_application(reference)[2] is not None
                add(context, "security policies", policy.name, "application", reference, "application/application-set", exists)
            if policy.scheduler_name:
                add(context, "security policies", policy.name, "scheduler", policy.scheduler_name, "scheduler", resolver.resolve_scheduler(policy.scheduler_name) is not None)

        for nat_type, rule_sets in (
            ("source", context.nat.source_rule_sets),
            ("destination", context.nat.destination_rule_sets),
            ("static", context.nat.static_rule_sets),
        ):
            pools = context.nat.source_pools if nat_type == "source" else context.nat.destination_pools
            for rule_set in rule_sets.values():
                for zone in [*rule_set.from_context.zones, *(rule_set.to_context.zones if rule_set.to_context else [])]:
                    add(context, f"security nat {nat_type}", rule_set.name, "zone", zone, "security-zone", zone in context.zones)
                for interface in [*rule_set.from_context.interfaces, *(rule_set.to_context.interfaces if rule_set.to_context else [])]:
                    add(context, f"security nat {nat_type}", rule_set.name, "interface", interface, "interface", interface_exists(interface))
                for instance in [*rule_set.from_context.routing_instances, *(rule_set.to_context.routing_instances if rule_set.to_context else [])]:
                    add(context, f"security nat {nat_type}", rule_set.name, "routing-instance", instance, "routing-instance", instance in context.routing_instances)
                for rule in rule_set.rules:
                    action = rule.action or {}
                    pool_name = action.get("pool_name")
                    if pool_name:
                        add(context, f"security nat {nat_type}", rule.name, "pool", pool_name, f"{nat_type}-nat-pool", pool_name in pools)
                    for field, references in (
                        ("source-address-name", rule.match.source_address_names),
                        ("destination-address-name", rule.match.destination_address_names),
                    ):
                        for reference in references:
                            resolved = resolver.resolve_nat(reference)
                            add(
                                context,
                                f"security nat {nat_type}",
                                rule.name,
                                field,
                                reference,
                                "address/address-set",
                                not resolved.is_unresolved,
                            )

        for route in context.routes:
            if route.routing_instance:
                add(
                    context,
                    "routing-instances" if route.routing_instance else "routing-options",
                    route.destination,
                    "routing-instance",
                    route.routing_instance,
                    "routing-instance",
                    route.routing_instance in context.routing_instances,
                )

        for interface in interfaces.values():
            for unit in interface.units.values():
                for attachment in unit.filters:
                    name = attachment.get("name")
                    family = attachment.get("family", "inet")
                    if name:
                        add(context, "firewall filters", f"{interface.name}.{unit.unit}", "filter", name, "firewall-filter", name in context.firewall_filters and context.firewall_filters[name].family.lower() == str(family).lower())
                    filt = context.firewall_filters.get(name)
                    if not filt:
                        continue
                    for term in filt.terms:
                        for action in term.actions:
                            if action.get("action") == "routing-instance":
                                ref = action.get("value")
                                add(context, "firewall filters", f"{name}:{term.name}", "routing-instance", ref, "routing-instance", isinstance(ref, str) and ref in context.routing_instances)

    return dependencies


def get_command_section_path(cmd: JunosCommand) -> str:
    """Determine the hierarchy section path for a Junos set/activate/deactivate command."""
    if len(cmd.tokens) < 2:
        return "root"

    # Skip operation token (set/activate/deactivate)
    toks = cmd.tokens[1:]
    first = toks[0].lower()

    if first == "logical-systems" and len(toks) > 2:
        # e.g. logical-systems LS1 security policies ... -> logical-systems LS1 security policies
        sub_path = get_command_section_path(
            JunosCommand(
                operation=cmd.operation,
                tokens=[cmd.tokens[0]] + toks[2:],
                raw_sanitized=cmd.raw_sanitized,
                line_number=cmd.line_number,
            )
        )
        return f"logical-systems {toks[1]} {sub_path}"

    if first == "tenants" and len(toks) > 2:
        sub_path = get_command_section_path(
            JunosCommand(
                operation=cmd.operation,
                tokens=[cmd.tokens[0]] + toks[2:],
                raw_sanitized=cmd.raw_sanitized,
                line_number=cmd.line_number,
            )
        )
        return f"tenants {toks[1]} {sub_path}"

    if first == "security":
        if len(toks) > 1:
            second = toks[1].lower()
            if second in ("zones", "policies", "address-book", "nat", "ike", "ipsec", "utm", "screen"):
                return f"security {second}"
            return f"security {second}"
        return "security"

    if first == "routing-options":
        if len(toks) > 1:
            return f"routing-options {toks[1].lower()}"
        return "routing-options"

    if first == "routing-instances":
        if len(toks) > 2:
            return f"routing-instances {toks[1]}"
        return "routing-instances"

    if first in ("interfaces", "applications", "schedulers", "system", "version", "chassis", "protocols", "snmp"):
        return first

    return first


def build_extraction_result(
    commands: Sequence[JunosCommand],
    canonical_ir: IRConfig,
    dependencies: Sequence[DependencyRecord] | None = None,
) -> ExtractionResult:
    """
    Construct the authoritative ExtractionResult accounting for 100% of input JunOS commands.
    Ensures zero silent data loss.
    """
    section_commands: dict[str, List[JunosCommand]] = defaultdict(list)
    for cmd in commands:
        path = get_command_section_path(cmd)
        section_commands[path].append(cmd)

    source_sections: List[SourceSectionResult] = []
    inventory_items: List[SourceInventoryItem] = []
    unsupported_items: List[UnsupportedItem] = []

    for path, cmds in section_commands.items():
        line_start = min(c.line_number for c in cmds)
        line_end = max(c.line_number for c in cmds)

        # Determine overall section status
        statuses = [c.extraction_status or (ExtractionStatus.NORMALIZED if c.consumed else ExtractionStatus.UNSUPPORTED) for c in cmds]
        if any(s == ExtractionStatus.PARSE_ERROR for s in statuses):
            section_status = ExtractionStatus.PARSE_ERROR
        elif any(s == ExtractionStatus.UNSUPPORTED for s in statuses):
            section_status = (
                ExtractionStatus.PARTIALLY_NORMALIZED
                if any(s in (ExtractionStatus.NORMALIZED, ExtractionStatus.PARTIALLY_NORMALIZED) for s in statuses)
                else ExtractionStatus.UNSUPPORTED
            )
        elif any(s == ExtractionStatus.PARTIALLY_NORMALIZED for s in statuses):
            section_status = ExtractionStatus.PARTIALLY_NORMALIZED
        elif any(s == ExtractionStatus.EXTRACT_ONLY for s in statuses):
            section_status = ExtractionStatus.EXTRACT_ONLY
        elif any(s == ExtractionStatus.VENDOR_EXTENSION for s in statuses):
            section_status = ExtractionStatus.VENDOR_EXTENSION
        else:
            section_status = ExtractionStatus.NORMALIZED

        source_sections.append(
            SourceSectionResult(
                path=path,
                present=True,
                line_start=line_start,
                line_end=line_end,
                object_count_source=len(cmds),
                object_count_parsed=sum(1 for c in cmds if c.consumed),
                object_count_normalized=sum(
                    1 for c in cmds if c.extraction_status == ExtractionStatus.NORMALIZED
                ),
                status=section_status,
                parser_handler=cmds[0].handler if cmds else None,
            )
        )

        source_cmds: List[SourceCommand] = []
        for c in cmds:
            status = c.extraction_status or (
                ExtractionStatus.NORMALIZED if c.consumed else ExtractionStatus.UNSUPPORTED
            )
            op = c.operation.value if isinstance(c.operation, JunosOperation) else str(c.operation)
            safe_tokens = sanitize_tokens(c.tokens)
            key = (
                " ".join(safe_tokens[1:3])
                if len(safe_tokens) > 2
                else (safe_tokens[1] if len(safe_tokens) > 1 else "")
            )
            values = safe_tokens[3:] if len(safe_tokens) > 3 else []
            source_cmds.append(
                SourceCommand(
                    operation=op,
                    key=key,
                    values=values,
                    line_number=c.line_number,
                    status=status,
                    parser_handler=c.handler,
                    requires_manual_review=c.requires_manual_review or status in (ExtractionStatus.UNSUPPORTED, ExtractionStatus.PARTIALLY_NORMALIZED, ExtractionStatus.PARSE_ERROR),
                    source_context=c.context_name,
                )
            )

            if status in (ExtractionStatus.UNSUPPORTED, ExtractionStatus.PARSE_ERROR) or c.access_denied:
                reason = (
                    "Source configuration was hidden by Junos permissions (ACCESS-DENIED)"
                    if c.access_denied
                    else c.parse_error or f"Unsupported Junos hierarchy command in section '{path}'"
                )
                unsupported_items.append(
                    UnsupportedItem(
                        source_path=path,
                        source_name=" ".join(safe_tokens[:4]) if len(safe_tokens) >= 4 else (" ".join(safe_tokens) if safe_tokens else path),
                        reason=reason,
                        requires_manual_review=True,
                        raw_capture=c.raw_sanitized,
                        source_context=c.context_name,
                    )
                )

        inventory_items.append(
            SourceInventoryItem(
                domain="juniper_srx",
                source_path=path,
                name=path,
                source_context=next((c.context_name for c in cmds if c.context_name), None),
                commands=source_cmds,
                status=section_status,
                requires_manual_review=any(sc.requires_manual_review for sc in source_cmds),
            )
        )

    dependency_list = list(dependencies or [])
    unresolved_by_path: dict[str, int] = defaultdict(int)
    for dependency in dependency_list:
        if dependency.result == "UNRESOLVED":
            unresolved_by_path[dependency.source_path] += 1
    for section in source_sections:
        section.unresolved_dependencies = unresolved_by_path.get(section.path, 0)

    return ExtractionResult(
        canonical_ir=canonical_ir,
        source_sections=source_sections,
        inventory_items=inventory_items,
        unsupported_items=unsupported_items,
        dependencies=dependency_list,
    )


def assert_no_silent_loss(
    extraction_result: ExtractionResult,
    total_input_commands: int | None = None,
    expected_unsupported: int = 0,
) -> None:
    """
    Assert that 100% of input JunOS commands are categorized into valid extraction statuses
    with zero silent data loss.
    """
    total_commands = 0
    status_counts: dict[ExtractionStatus, int] = defaultdict(int)

    for item in extraction_result.inventory_items:
        for cmd in item.commands:
            total_commands += 1
            assert cmd.status is not None, f"Command at line {cmd.line_number} has no extraction status"
            assert isinstance(cmd.status, ExtractionStatus), f"Command at line {cmd.line_number} status is not ExtractionStatus"
            status_counts[cmd.status] += 1

    if total_input_commands is not None:
        assert total_commands == total_input_commands, (
            f"Command count mismatch: inventory has {total_commands} commands, "
            f"expected {total_input_commands}"
        )

    accounted_sum = sum(status_counts.values())
    assert accounted_sum == total_commands, "Not all commands were accounted for"

    if expected_unsupported > 0:
        actual_unsupported = (
            status_counts[ExtractionStatus.UNSUPPORTED]
            + status_counts[ExtractionStatus.PARSE_ERROR]
        )
        assert actual_unsupported == expected_unsupported, (
            f"Expected {expected_unsupported} unsupported/parse-error commands, got {actual_unsupported}"
        )
