from __future__ import annotations

import ipaddress
from typing import Any, Dict, Iterable, List, Sequence, Set

from fwmigrate.core.constants import UNIVERSAL_KEYWORDS
from fwmigrate.ir.core import IRConfig
from fwmigrate.jobs.models import MigrationIssue


def _issue(
    *,
    severity: str,
    category: str,
    source_object: str,
    message: str,
    blocking: bool,
) -> MigrationIssue:
    return MigrationIssue(
        severity=severity,
        category=category,
        source_object=source_object,
        message=message,
        blocking=blocking,
    )


def _names(items: Iterable[Any]) -> Set[str]:
    return {item.name for item in items if getattr(item, "name", None)}


def _is_universal(value: str) -> bool:
    return value in UNIVERSAL_KEYWORDS or value.casefold() in {
        "any",
        "all",
        "none",
        "application-default",
    }


def _is_literal_address(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        parts = value.split()
        if len(parts) == 2:
            try:
                ipaddress.ip_network(f"{parts[0]}/{parts[1]}", strict=False)
                return True
            except ValueError:
                pass
    return value.casefold() in {"interface", "dynamic", "original", "preserve"}


def _values(item: Any, *fields: str) -> List[str]:
    result: List[str] = []
    for field in fields:
        value = getattr(item, field, None)
        if isinstance(value, str):
            result.append(value)
        elif value:
            result.extend(str(entry) for entry in value)
    return result


class Validator:
    """Base class for read-only validation passes over canonical ``IRConfig``."""

    def validate(self, ir_config: IRConfig) -> List[MigrationIssue]:
        raise NotImplementedError


class SchemaValidator(Validator):
    def validate(self, ir_config: IRConfig) -> List[MigrationIssue]:
        if ir_config.schema_version:
            return []
        return [_issue(
            severity="CRITICAL",
            category="SCHEMA",
            source_object="IRConfig",
            message="IR schema version is missing.",
            blocking=True,
        )]


class SafetyValidator(Validator):
    def validate(self, ir_config: IRConfig) -> List[MigrationIssue]:
        if ir_config.generation_safe or ir_config.generation_blocking_reasons:
            return []
        return [_issue(
            severity="CRITICAL",
            category="SAFETY",
            source_object="IRConfig",
            message="IR is marked unsafe without a blocking reason.",
            blocking=True,
        )]


class DependencyValidator(Validator):
    """Validate canonical object references without mutating the IR."""

    def validate(self, ir_config: IRConfig) -> List[MigrationIssue]:
        issues: List[MigrationIssue] = []
        known_zones = _names(ir_config.zones)
        for interface in ir_config.interfaces:
            for field in ("zone", "nameif"):
                value = getattr(interface, field, None)
                if value:
                    known_zones.add(value)
        known_addresses = _names(ir_config.addresses) | _names(ir_config.address_groups)
        known_services = _names(ir_config.services) | _names(ir_config.service_groups)
        known_interfaces = _names(ir_config.interfaces)
        known_pools = _names(ir_config.ip_pools) | _names(ir_config.virtual_ips)
        for nat in ir_config.nat_rules:
            known_zones.update(_values(nat, "source_from_interfaces", "source_to_interfaces"))

        for label, collection in (
            ("zone", ir_config.zones),
            ("address", ir_config.addresses),
            ("address group", ir_config.address_groups),
            ("service", ir_config.services),
            ("service group", ir_config.service_groups),
            ("policy", ir_config.policies),
            ("NAT rule", ir_config.nat_rules),
            ("route", ir_config.routes),
            ("VPN tunnel", ir_config.vpn_tunnels),
        ):
            seen: Set[str] = set()
            for item in collection:
                name = getattr(item, "name", None)
                if not name:
                    continue
                if name in seen:
                    issues.append(_issue(
                        severity="HIGH",
                        category="DEPENDENCY",
                        source_object=f"{label}:{name}",
                        message=f"Duplicate {label} identifier: {name}",
                        blocking=True,
                    ))
                seen.add(name)

        for group in ir_config.address_groups:
            for member in group.members:
                if not _is_universal(member) and member not in known_addresses:
                    issues.append(_issue(
                        severity="HIGH",
                        category="DEPENDENCY",
                        source_object=f"AddressGroup:{group.name}",
                        message=f"References unknown member: {member}",
                        blocking=True,
                    ))

        for group in ir_config.service_groups:
            for member in group.members:
                if not _is_universal(member) and member not in known_services:
                    issues.append(_issue(
                        severity="HIGH",
                        category="DEPENDENCY",
                        source_object=f"ServiceGroup:{group.name}",
                        message=f"References unknown member: {member}",
                        blocking=True,
                    ))

        def require(values: Sequence[str], known: Set[str], kind: str, owner: str) -> None:
            for value in values:
                if (
                    not _is_universal(value)
                    and (known or kind != "nat zone")
                    and value not in known
                    and not ("address" in kind and _is_literal_address(value))
                ):
                    issues.append(_issue(
                        severity="HIGH",
                        category="DEPENDENCY",
                        source_object=owner,
                        message=f"References unknown {kind}: {value}",
                        blocking=True,
                    ))

        for policy in ir_config.policies:
            owner = f"SecurityRule:{policy.name}"
            for fields, kind, known in (
                (("from_zone", "to_zone"), "zone", known_zones),
                (("source", "source_address_references", "source_ipv6_address_references"), "source address", known_addresses),
                (("destination", "destination_address_references", "destination_ipv6_address_references"), "destination address", known_addresses),
                (("service", "source_service_references"), "service", known_services),
            ):
                require(_values(policy, *fields), known, kind, owner)
            for field in ("source", "destination", "service"):
                if not getattr(policy, field, None):
                    issues.append(_issue(
                        severity="CRITICAL",
                        category="SEMANTIC",
                        source_object=owner,
                        message=f"Policy {field} is empty and cannot be safely defaulted.",
                        blocking=True,
                    ))

        for rule in ir_config.nat_rules:
            owner = f"NAT:{rule.name}"
            require(_values(rule, "from_zone", "to_zone"), known_zones, "nat zone", owner)
            require(
                _values(
                    rule,
                    "source", "destination", "source_pool_references", "destination_pool_references",
                    "translated_source_address_references", "translated_destination_address_references",
                    "source_vip_reference", "source_vip_group_reference", "translated_sources", "translated_destinations",
                ),
                known_addresses | known_pools,
                "address or pool",
                owner,
            )
            require(_values(rule, "services", "translated_services"), known_services, "service", owner)

        for tunnel in ir_config.vpn_tunnels:
            if tunnel.local_interface and tunnel.local_interface not in known_interfaces:
                issues.append(_issue(
                    severity="HIGH",
                    category="DEPENDENCY",
                    source_object=f"VPN:{tunnel.name}",
                    message=f"References unknown local interface: {tunnel.local_interface}",
                    blocking=True,
                ))
            for reference in tunnel.unresolved_interfaces + tunnel.unresolved_certificates + tunnel.unresolved_auth_user_groups:
                issues.append(_issue(
                    severity="HIGH",
                    category="DEPENDENCY",
                    source_object=f"VPN:{tunnel.name}",
                    message=f"Unresolved VPN dependency: {reference}",
                    blocking=True,
                ))

        return issues


class ReferenceValidator(DependencyValidator):
    """Named production entry point for canonical reference validation."""


class SemanticValidator(Validator):
    def validate(self, ir_config: IRConfig) -> List[MigrationIssue]:
        issues: List[MigrationIssue] = []
        parsed: Dict[str, Any] = {}
        for address in ir_config.addresses:
            value = address.value
            if address.type.value not in {"network", "host"} or not value:
                continue
            try:
                network = ipaddress.ip_network(value, strict=False)
            except ValueError:
                issues.append(_issue(
                    severity="MEDIUM",
                    category="SEMANTIC",
                    source_object=f"Address:{address.name}",
                    message=f"Invalid IP format: {value}",
                    blocking=True,
                ))
                continue
            for existing_name, existing_network in parsed.items():
                if network.overlaps(existing_network):
                    issues.append(_issue(
                        severity="LOW",
                        category="SEMANTIC",
                        source_object=f"Address:{address.name}",
                        message=f"Overlaps with existing address {existing_name} ({existing_network})",
                        blocking=False,
                    ))
            parsed[address.name] = network
        return issues


class CapacityValidator(Validator):
    def __init__(self, limits: Dict[str, int]):
        self.limits = limits

    def validate(self, ir_config: IRConfig) -> List[MigrationIssue]:
        counts = {
            "max_policies": len(ir_config.policies),
            "max_address_objects": len(ir_config.addresses) + len(ir_config.address_groups),
            "max_zones": len(ir_config.zones),
        }
        return [
            _issue(
                severity="CRITICAL",
                category="CAPACITY",
                source_object="Global",
                message=f"Exceeded {key}: configured {count}, limit {limit}",
                blocking=True,
            )
            for key, count in counts.items()
            if (limit := self.limits.get(key)) and count > limit
        ]
