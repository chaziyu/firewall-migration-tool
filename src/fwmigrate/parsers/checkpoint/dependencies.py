"""Dependency evidence for newly canonicalized Check Point records."""

from __future__ import annotations

from typing import Any, Iterable, Optional, Set

from fwmigrate.extraction.models import DependencyRecord
from fwmigrate.ir.core import IRConfig
from fwmigrate.parsers.checkpoint.resolver import CheckPointObjectResolver, ResolutionResult, SemanticKind


def _record(
    source_path: str, source_object: str, source_field: str, reference: Any,
    expected: str, resolution: ResolutionResult,
) -> DependencyRecord:
    return DependencyRecord(
        source_path=source_path, source_object=source_object, source_field=source_field,
        reference=str(reference), expected_type=expected,
        result="RESOLVED" if resolution.resolved else "UNRESOLVED",
        target_path=resolution.name or resolution.uid if resolution.resolved else None,
        target_uid=resolution.uid, target_name=resolution.name,
        semantic_kind=resolution.semantic_kind.value,
        normalization_status=resolution.normalization_status.value,
        reason=resolution.reason,
        notes=resolution.reason,
    )


def _refs(value: Any) -> Iterable[str]:
    values = value if isinstance(value, list) else ([] if value is None else [value])
    for item in values:
        if isinstance(item, dict):
            item = item.get("uid") or item.get("name")
        if item is not None:
            yield str(item)


def _check(
    resolver: CheckPointObjectResolver, ref: str, domain: Optional[str],
    expected: Set[SemanticKind],
) -> ResolutionResult:
    return resolver.resolve_typed_reference(ref, expected, domain=domain)


def build_checkpoint_dependencies(
    ir: IRConfig, resolver: CheckPointObjectResolver,
) -> list[DependencyRecord]:
    dependencies: list[DependencyRecord] = []
    interfaces = {item.name for item in ir.interfaces}
    zones = {item.name for item in ir.zones}

    for interface in ir.interfaces:
        if not interface.zone:
            continue
        resolved = ResolutionResult(
            resolved=interface.zone in zones, name=interface.zone,
            semantic_kind=SemanticKind.SECURITY_ZONE if interface.zone in zones else SemanticKind.UNKNOWN,
            reason=None if interface.zone in zones else "unresolved-security-zone",
        )
        dependencies.append(_record("interfaces", interface.name, "zone", interface.zone, "security-zone", resolved))

    for rule in ir.pbf_rules:
        domain = rule.source_context
        for field, refs, expected in (
            ("incoming-interface", rule.from_interface, {SemanticKind.UNKNOWN}),
            ("table-output-interface", [rule.table_output_interface], {SemanticKind.UNKNOWN}),
        ):
            for ref in _refs(refs):
                resolved = ResolutionResult(
                    resolved=ref in interfaces, name=ref,
                    semantic_kind=SemanticKind.UNKNOWN,
                    reason=None if ref in interfaces else "unresolved-interface-reference",
                )
                dependencies.append(_record("gaia/pbr", rule.name, field, ref, "interface", resolved))
        if rule.routing_table:
            table = ResolutionResult(
                resolved=bool(rule.source_attributes.get("table")),
                name=rule.routing_table, semantic_kind=SemanticKind.UNKNOWN,
                reason=None if rule.source_attributes.get("table") else "unresolved-pbr-routing-table",
            )
            dependencies.append(_record("gaia/pbr", rule.name, "routing-table", rule.routing_table, "routing-table", table))

    access_expected = {
        "source": {SemanticKind.ADDRESS, SemanticKind.ADDRESS_GROUP, SemanticKind.SECURITY_ZONE, SemanticKind.ACCESS_ROLE, SemanticKind.SPECIAL_ANY},
        "destination": {SemanticKind.ADDRESS, SemanticKind.ADDRESS_GROUP, SemanticKind.SECURITY_ZONE, SemanticKind.ACCESS_ROLE, SemanticKind.SPECIAL_ANY},
        "service": {SemanticKind.SERVICE, SemanticKind.SERVICE_GROUP, SemanticKind.APPLICATION, SemanticKind.APPLICATION_GROUP, SemanticKind.APPLICATION_CATEGORY, SemanticKind.SITE, SemanticKind.SPECIAL_ANY},
        "time": {SemanticKind.TIME, SemanticKind.TIME_GROUP, SemanticKind.SPECIAL_ANY},
        "install-on": {SemanticKind.INSTALL_TARGET, SemanticKind.SPECIAL_ANY},
    }
    for rule in ir.checkpoint_access_rules:
        for field, refs in (
            ("source", rule.source), ("destination", rule.destination),
            ("service", [*rule.services, *rule.applications]),
            ("access-role", rule.access_roles), ("time", rule.time),
            ("install-on", rule.install_on),
        ):
            expected = access_expected.get(field, access_expected["source"])
            for ref in _refs(refs):
                resolved = _check(resolver, ref, rule.domain, expected)
                dependencies.append(_record("access-rules", rule.name, field, ref, field, resolved))
        if rule.inline_layer_reference:
            resolved = resolver.resolve(rule.inline_layer_reference, domain=rule.domain)
            dependencies.append(_record("access-rules", rule.name, "inline-layer", rule.inline_layer_reference, "access-layer", resolved))

    for rule in ir.nat_rules:
        domain = rule.source_context
        for field, refs, expected in (
            ("original-source", rule.source, {SemanticKind.ADDRESS, SemanticKind.ADDRESS_GROUP, SemanticKind.SPECIAL_ANY}),
            ("original-destination", rule.destination, {SemanticKind.ADDRESS, SemanticKind.ADDRESS_GROUP, SemanticKind.SPECIAL_ANY}),
            ("original-service", rule.services, {SemanticKind.SERVICE, SemanticKind.SERVICE_GROUP, SemanticKind.SPECIAL_ANY}),
            ("translated-source", rule.translated_sources, {SemanticKind.ADDRESS, SemanticKind.ADDRESS_GROUP, SemanticKind.SPECIAL_ANY}),
            ("translated-destination", rule.translated_destinations, {SemanticKind.ADDRESS, SemanticKind.ADDRESS_GROUP, SemanticKind.SPECIAL_ANY}),
            ("translated-service", rule.translated_services, {SemanticKind.SERVICE, SemanticKind.SERVICE_GROUP, SemanticKind.SPECIAL_ANY}),
        ):
            for ref in _refs(refs):
                resolved = _check(resolver, ref, domain, expected)
                dependencies.append(_record("nat-rules", rule.name, field, ref, field, resolved))

    for pool in ir.ip_pools:
        if pool.source_origin != "checkpoint-management-ip-pool":
            continue
        domain = pool.source_context
        for field, refs, expected in (
            ("network", pool.checkpoint_network_references, {SemanticKind.ADDRESS, SemanticKind.ADDRESS_GROUP}),
            ("network-group", pool.checkpoint_network_group_references, {SemanticKind.ADDRESS_GROUP}),
            ("address-range", pool.checkpoint_address_range_references, {SemanticKind.ADDRESS}),
            ("gateway", pool.checkpoint_gateway_references, {SemanticKind.INSTALL_TARGET, SemanticKind.UNKNOWN}),
        ):
            for ref in _refs(refs):
                resolved = _check(resolver, ref, domain, expected)
                dependencies.append(_record("ip-pool-nat", pool.name, field, ref, field, resolved))
        member_refs = (
            pool.checkpoint_member_assignments.keys()
            if isinstance(pool.checkpoint_member_assignments, dict)
            else pool.checkpoint_member_assignments
        )
        for member in _refs(list(member_refs)):
            resolved = resolver.resolve(member, domain=domain)
            dependencies.append(_record("ip-pool-nat", pool.name, "member", member, "cluster-member", resolved))

    return dependencies
