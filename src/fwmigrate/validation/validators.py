from typing import List, Set, Dict
from fwmigrate.ir.v2.models import IRConfigV2
from fwmigrate.jobs.models import MigrationIssue
from fwmigrate.core.constants import UNIVERSAL_KEYWORDS
import ipaddress

class Validator:
    """Base class for validation passes."""
    def validate(self, ir_config: IRConfigV2) -> List[MigrationIssue]:
        raise NotImplementedError

class DependencyValidator(Validator):
    """
    Ensures referential integrity across the IR.
    E.g., Policies must only reference valid zones, addresses, and services.
    """
    def validate(self, ir_config: IRConfigV2) -> List[MigrationIssue]:
        issues = []
        
        known_zones = {z.name for z in ir_config.zones}
        known_addresses = {a.name for a in ir_config.addresses}
        known_address_groups = {ag.name for ag in ir_config.address_groups}
        all_address_objects = known_addresses.union(known_address_groups)
        
        known_services = {s.name for s in ir_config.services}
        known_service_groups = {sg.name for sg in ir_config.service_groups}
        all_service_objects = known_services.union(known_service_groups)
        
        # Check Address Groups
        for ag in ir_config.address_groups:
            for member in ag.members:
                if member not in all_address_objects:
                    issues.append(MigrationIssue(
                        severity="HIGH",
                        category="DEPENDENCY",
                        source_object=f"AddressGroup:{ag.name}",
                        message=f"References unknown member: {member}",
                        blocking=True
                    ))
                    
        # Check Policies
        for policy in ir_config.policies:
            # Check Zones
            for z in policy.from_zone:
                if z not in UNIVERSAL_KEYWORDS and z not in known_zones:
                    issues.append(MigrationIssue(
                        severity="HIGH",
                        category="DEPENDENCY",
                        source_object=f"SecurityRule:{policy.name}",
                        message=f"References unknown from_zone: {z}",
                        blocking=True
                    ))
            
            # Check Addresses
            for src in policy.source:
                if src not in UNIVERSAL_KEYWORDS and src not in all_address_objects:
                    issues.append(MigrationIssue(
                        severity="HIGH",
                        category="DEPENDENCY",
                        source_object=f"SecurityRule:{policy.name}",
                        message=f"References unknown source address: {src}",
                        blocking=True
                    ))
                    
            for dst in policy.destination:
                if dst not in UNIVERSAL_KEYWORDS and dst not in all_address_objects:
                    issues.append(MigrationIssue(
                        severity="HIGH",
                        category="DEPENDENCY",
                        source_object=f"SecurityRule:{policy.name}",
                        message=f"References unknown destination address: {dst}",
                        blocking=True
                    ))
                    
            # Check Services
            for srv in policy.service:
                if srv not in UNIVERSAL_KEYWORDS and srv.lower() != 'application-default' and srv not in all_service_objects:
                    issues.append(MigrationIssue(
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
    def validate(self, ir_config: IRConfigV2) -> List[MigrationIssue]:
        issues = []
        
        # Check for address object overlaps
        addr_map = {}
        for addr in ir_config.addresses:
            if addr.type == 'ip-netmask' or addr.type == 'ip-range':
                try:
                    if '/' in addr.value:
                        network = ipaddress.ip_network(addr.value, strict=False)
                    elif '-' in addr.value:
                        # Skip range validation for this basic check
                        continue
                    else:
                        network = ipaddress.ip_network(f"{addr.value}/32")
                        
                    for existing_name, existing_net in addr_map.items():
                        if network.overlaps(existing_net):
                            issues.append(MigrationIssue(
                                severity="LOW",
                                category="SEMANTIC",
                                source_object=f"Address:{addr.name}",
                                message=f"Overlaps with existing address {existing_name} ({existing_net})",
                                blocking=False
                            ))
                    addr_map[addr.name] = network
                except ValueError:
                    issues.append(MigrationIssue(
                        severity="MEDIUM",
                        category="SEMANTIC",
                        source_object=f"Address:{addr.name}",
                        message=f"Invalid IP format: {addr.value}",
                        blocking=True
                    ))
                    
        return issues


class CapacityValidator(Validator):
    """
    Ensures the generated IR does not exceed the target platform's hardware limits.
    """
    def __init__(self, limits: Dict[str, int]):
        self.limits = limits
        
    def validate(self, ir_config: IRConfigV2) -> List[MigrationIssue]:
        issues = []
        
        limit_checks = {
            'max_policies': len(ir_config.policies),
            'max_address_objects': len(ir_config.addresses) + len(ir_config.address_groups),
            'max_zones': len(ir_config.zones)
        }
        
        for key, count in limit_checks.items():
            limit = self.limits.get(key)
            if limit and count > limit:
                issues.append(MigrationIssue(
                    severity="CRITICAL",
                    category="CAPACITY",
                    source_object="Global",
                    message=f"Exceeded {key}: configured {count}, limit {limit}",
                    blocking=True
                ))
                
        return issues
