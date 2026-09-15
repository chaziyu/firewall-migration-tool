import heapq
import ipaddress
from typing import Dict, List, Optional
from fwmigrate.ir import IRConfig
from fwmigrate.ir.enums import AddressType
from fwmigrate.ir.index import IRIndex
from fwmigrate.core.constants import UNIVERSAL_KEYWORDS
from fwmigrate.validation.models import ValidationIssue, ValidationResult

_UNIVERSAL_KEYWORDS = {keyword.casefold() for keyword in UNIVERSAL_KEYWORDS}

class Validator:
    """Base class for validation passes."""
    def validate(self, ir_config: IRConfig) -> List[ValidationIssue]:
        raise NotImplementedError

class DependencyValidator(Validator):
    """
    Ensures referential integrity across the IR.
    E.g., Policies must only reference valid zones, addresses, and services.
    """
    def __init__(self, ir_index: Optional[IRIndex] = None):
        self.ir_index = ir_index

    def validate(self, ir_config: IRConfig) -> List[ValidationIssue]:
        issues = []
        index = self.ir_index or IRIndex.build(ir_config)
        known_zones = set(index.by_name.get("zones", {}))
        known_addresses = set(index.by_name.get("addresses", {}))
        known_address_groups = set(index.by_name.get("address_groups", {}))
        all_address_objects = known_addresses.union(known_address_groups)
        known_services = set(index.by_name.get("services", {}))
        known_service_groups = set(index.by_name.get("service_groups", {}))
        all_service_objects = known_services.union(known_service_groups)
        
        # Phase 14: PAN Builtin/Predefined namespaces
        pan_builtin_tokens = {"any", "all", "none"}
        pan_predefined_services = {"service-http", "service-https"}
        
        is_panos = False
        if hasattr(ir_config, "metadata") and ir_config.metadata:
            is_panos = getattr(ir_config.metadata, "source_vendor", None) == "palo_alto"
        
        # Check Address Groups
        for ag in ir_config.address_groups:
            for member in ag.members:
                if member not in all_address_objects:
                    issues.append(ValidationIssue(
                        severity="HIGH",
                        category="DEPENDENCY",
                        source_object=f"AddressGroup:{ag.name}",
                        message=f"References unknown member: {member}",
                        blocking=True
                    ))
                    
        # Check Policies
        for policy in ir_config.policies:
            if not policy.source:
                issues.append(ValidationIssue(
                    severity="CRITICAL",
                    category="SEMANTIC",
                    source_object=f"SecurityRule:{policy.name}",
                    message="Policy source is empty. This cannot be safely defaulted to 'any'.",
                    blocking=True
                ))
            if not policy.destination:
                issues.append(ValidationIssue(
                    severity="CRITICAL",
                    category="SEMANTIC",
                    source_object=f"SecurityRule:{policy.name}",
                    message="Policy destination is empty. This cannot be safely defaulted to 'any'.",
                    blocking=True
                ))
            if not policy.service:
                issues.append(ValidationIssue(
                    severity="CRITICAL",
                    category="SEMANTIC",
                    source_object=f"SecurityRule:{policy.name}",
                    message="Policy service is empty. This cannot be safely defaulted to 'any'.",
                    blocking=True
                ))
            # Check Zones
            for z in policy.from_zone:
                if z.casefold() not in _UNIVERSAL_KEYWORDS and z not in known_zones:
                    issues.append(ValidationIssue(
                        severity="HIGH",
                        category="DEPENDENCY",
                        source_object=f"SecurityRule:{policy.name}",
                        message=f"References unknown from_zone: {z}",
                        blocking=True
                    ))
            
            # Check Addresses
            for src in policy.source:
                if src.casefold() not in _UNIVERSAL_KEYWORDS and src.casefold() not in pan_builtin_tokens and src not in all_address_objects:
                    issues.append(ValidationIssue(
                        severity="HIGH",
                        category="DEPENDENCY",
                        source_object=f"SecurityRule:{policy.name}",
                        message=f"References unknown source address: {src}",
                        blocking=True
                    ))
                    
            for dst in policy.destination:
                if dst.casefold() not in _UNIVERSAL_KEYWORDS and dst.casefold() not in pan_builtin_tokens and dst not in all_address_objects:
                    issues.append(ValidationIssue(
                        severity="HIGH",
                        category="DEPENDENCY",
                        source_object=f"SecurityRule:{policy.name}",
                        message=f"References unknown destination address: {dst}",
                        blocking=True
                    ))
                    
            # Check Services
            for srv in policy.service:
                # Allow application-default, and predefined PAN services if vendor is palo_alto
                is_builtin = srv.casefold() in _UNIVERSAL_KEYWORDS or srv.casefold() == 'application-default'
                if is_panos and srv.lower() in pan_predefined_services:
                    is_builtin = True
                    
                if not is_builtin and srv not in all_service_objects:
                    issues.append(ValidationIssue(
                        severity="HIGH",
                        category="DEPENDENCY",
                        source_object=f"SecurityRule:{policy.name}",
                        message=f"References unknown service: {srv}",
                        blocking=True
                    ))
                    
        return issues


class SemanticValidator(Validator):
    """
    Identifies logical flaws like shadowed rules or overlapping definitions.
    """
    def validate(self, ir_config: IRConfig) -> List[ValidationIssue]:
        issues = []
        
        # Parse each family once, then sweep only intervals that can overlap.
        intervals = {4: [], 6: []}
        issues_by_order = []
        latest_by_name = {4: {}, 6: {}}
        for index, addr in enumerate(ir_config.addresses):
            if addr.type in (AddressType.NETWORK, AddressType.HOST, AddressType.RANGE):
                try:
                    if '/' in addr.value:
                        network = ipaddress.ip_network(addr.value, strict=False)
                    elif '-' in addr.value:
                        # Skip range validation for this basic check
                        continue
                    else:
                        network = ipaddress.ip_network(f"{addr.value}/32")

                    intervals[network.version].append((
                        network.network_address, network.broadcast_address,
                        index, addr.name, network,
                        latest_by_name[network.version].get(addr.name),
                    ))
                    latest_by_name[network.version][addr.name] = index
                except ValueError:
                    issues_by_order.append((index, -1, ValidationIssue(
                        severity="MEDIUM",
                        category="SEMANTIC",
                        source_object=f"Address:{addr.name}",
                        message=f"Invalid IP format: {addr.value}",
                        blocking=True
                    )))

        overlap_pairs = []
        for family_intervals in intervals.values():
            active = {}
            expirations = []
            for start, end, index, name, network, previous_same_name in sorted(
                family_intervals, key=lambda item: (item[0], item[1], item[2])
            ):
                while expirations and expirations[0][0] < start:
                    _, expired_index = heapq.heappop(expirations)
                    active.pop(expired_index, None)
                current = (start, end, index, name, network, previous_same_name)
                # ponytail: worst-case O(n²) remains when every pair overlaps; emitting every issue is the contract.
                for existing in active.values():
                    existing_index = existing[2]
                    later_index, earlier_index, later_interval, earlier_interval = (
                        (index, existing_index, current, existing)
                        if index > existing_index
                        else (existing_index, index, existing, current)
                    )
                    if (
                        later_interval[3] != earlier_interval[3]
                        or later_interval[5] == earlier_index
                    ):
                        overlap_pairs.append((
                            later_index, earlier_index, later_interval, earlier_interval,
                        ))
                active[index] = current
                heapq.heappush(expirations, (end, index))

        for later_index, earlier_index, later_interval, earlier_interval in sorted(
            overlap_pairs, key=lambda pair: (pair[0], pair[1])
        ):
            issues_by_order.append((later_index, earlier_index, ValidationIssue(
                severity="LOW",
                category="SEMANTIC",
                source_object=f"Address:{later_interval[3]}",
                message=(
                    f"Overlaps with existing address {earlier_interval[3]} "
                    f"({earlier_interval[4]})"
                ),
                blocking=False,
            )))

        issues = [issue for _, _, issue in sorted(issues_by_order, key=lambda item: (item[0], item[1]))]
        return issues


class CapacityValidator(Validator):
    """
    Ensures the generated IR does not exceed the target platform's hardware limits.
    """
    def __init__(self, limits: Dict[str, int]):
        self.limits = limits
        
    def validate(self, ir_config: IRConfig) -> List[ValidationIssue]:
        issues = []
        
        limit_checks = {
            'max_policies': len(ir_config.policies),
            'max_address_objects': len(ir_config.addresses) + len(ir_config.address_groups),
            'max_zones': len(ir_config.zones)
        }
        
        for key, count in limit_checks.items():
            limit = self.limits.get(key)
            if limit and count > limit:
                issues.append(ValidationIssue(
                    severity="CRITICAL",
                    category="CAPACITY",
                    source_object="Global",
                    message=f"Exceeded {key}: configured {count}, limit {limit}",
                    blocking=True
                ))
                
        return issues


def validate_ir(ir_config: IRConfig, ir_index: Optional[IRIndex] = None) -> ValidationResult:
    return ValidationResult(
        DependencyValidator(ir_index).validate(ir_config)
        + SemanticValidator().validate(ir_config)
    )
