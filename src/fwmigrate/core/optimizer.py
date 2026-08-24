from typing import Dict, List, Set, Any
from fwmigrate.ir.core import IRConfig, IRAddress, IRService, IRPolicy, IRAuditEntry
from fwmigrate.ir.enums import PolicyAction, MigrationConfidence

class RuleOptimizer:
    """Security rulebase and object optimization engine."""

    def __init__(self, ir: IRConfig):
        self.ir = ir

    def find_unused_objects(self) -> Dict[str, List[str]]:
        """Identify address and service objects not referenced anywhere."""
        used_addresses: Set[str] = set()
        used_services: Set[str] = set()
        used_address_groups: Set[str] = set()
        used_service_groups: Set[str] = set()

        # Check policies
        for pol in self.ir.policies:
            used_addresses.update(pol.source)
            used_addresses.update(pol.destination)
            used_services.update(pol.service)

        # Check NAT
        for nat in self.ir.nat_rules:
            used_addresses.update(nat.source)
            used_addresses.update(nat.destination)
            used_addresses.update(nat.translated_sources)
            used_addresses.update(nat.translated_destinations)
            used_services.update(service for service in nat.services if service != "any")

        addr_group_dict = {g.name: g.members for g in self.ir.address_groups}
        svc_group_dict = {g.name: g.members for g in self.ir.service_groups}

        added_new = True
        while added_new:
            added_new = False
            # For addresses
            current_addrs = list(used_addresses)
            for item in current_addrs:
                if item in addr_group_dict and item not in used_address_groups:
                    used_address_groups.add(item)
                    for member in addr_group_dict[item]:
                        if member not in used_addresses:
                            used_addresses.add(member)
                            added_new = True
            
            # For services
            current_svcs = list(used_services)
            for item in current_svcs:
                if item in svc_group_dict and item not in used_service_groups:
                    used_service_groups.add(item)
                    for member in svc_group_dict[item]:
                        if member not in used_services:
                            used_services.add(member)
                            added_new = True

        unused_addrs = [a.name for a in self.ir.addresses if a.name not in used_addresses and a.name not in ["any", "all"]]
        unused_svcs = [s.name for s in self.ir.services if s.name not in used_services and s.name not in ["any", "ALL", "service-http", "service-https"]]
        unused_addr_groups = [g.name for g in self.ir.address_groups if g.name not in used_address_groups]
        unused_svc_groups = [g.name for g in self.ir.service_groups if g.name not in used_service_groups]

        return {
            "unused_addresses": unused_addrs,
            "unused_services": unused_svcs,
            "unused_address_groups": unused_addr_groups,
            "unused_service_groups": unused_svc_groups
        }

    def find_duplicate_objects(self) -> Dict[str, List[List[str]]]:
        """Identify address and service objects with identical values."""
        val_to_addrs: Dict[str, List[str]] = {}
        for addr in self.ir.addresses:
            val_to_addrs.setdefault(addr.value, []).append(addr.name)

        duplicate_addrs = [names for names in val_to_addrs.values() if len(names) > 1]

        # Service port duplicates
        port_to_svcs: Dict[str, List[str]] = {}
        for svc in self.ir.services:
            key = ",".join([f"{p.protocol}:{p.port}" for p in svc.ports])
            if key:
                port_to_svcs.setdefault(key, []).append(svc.name)

        duplicate_svcs = [names for names in port_to_svcs.values() if len(names) > 1]

        return {
            "duplicate_addresses": duplicate_addrs,
            "duplicate_services": duplicate_svcs
        }

    def find_shadowed_rules(self) -> List[Dict[str, Any]]:
        """Identify rules shadowed by preceding broad rules."""
        shadowed = []
        # Check rulebase sequentially
        for i in range(len(self.ir.policies)):
            current = self.ir.policies[i]
            for j in range(i):
                preceding = self.ir.policies[j]
                same_action = (preceding.action == current.action)
                
                def is_subset(curr_list, prec_list, any_keywords):
                    if not curr_list:
                        return True
                    if not prec_list:
                        return False
                    if any(kw in prec_list for kw in any_keywords):
                        return True
                    return set(curr_list).issubset(set(prec_list))
                
                preceding_broad_src = is_subset(current.source, preceding.source, ["any", "all"])
                preceding_broad_dst = is_subset(current.destination, preceding.destination, ["any", "all"])
                preceding_broad_svc = is_subset(current.service, preceding.service, ["any", "ALL"])
                
                prec_from_any = not preceding.from_zone or "any" in preceding.from_zone
                prec_to_any = not preceding.to_zone or "any" in preceding.to_zone
                
                preceding_broad_zones = (
                    (prec_from_any or set(current.from_zone).issubset(set(preceding.from_zone))) and
                    (prec_to_any or set(current.to_zone).issubset(set(preceding.to_zone)))
                )

                if preceding_broad_src and preceding_broad_dst and preceding_broad_svc and preceding_broad_zones:
                    shadowed.append({
                        "rule": current.name,
                        "rule_index": i + 1,
                        "shadowed_by": preceding.name,
                        "shadowed_by_index": j + 1,
                        "action_match": same_action
                    })
                    break
        return shadowed

    def prune_unused_objects(self) -> IRConfig:
        """Create a new IRConfig copy with unused objects removed."""
        unused = self.find_unused_objects()
        unused_addr_set = set(unused["unused_addresses"])
        unused_svc_set = set(unused["unused_services"])
        unused_addr_grp_set = set(unused.get("unused_address_groups", []))
        unused_svc_grp_set = set(unused.get("unused_service_groups", []))

        new_ir = self.ir.model_copy(deep=True)
        new_ir.addresses = [a for a in new_ir.addresses if a.name not in unused_addr_set]
        new_ir.services = [s for s in new_ir.services if s.name not in unused_svc_set]
        new_ir.address_groups = [g for g in new_ir.address_groups if g.name not in unused_addr_grp_set]
        new_ir.service_groups = [g for g in new_ir.service_groups if g.name not in unused_svc_grp_set]
        return new_ir

    def fix_outbound_threat_source_anomalies(self) -> None:
        """
        Identify and automatically fix rules where a threat object was accidentally
        used as the source in an outbound block rule instead of the destination.
        Modifies self.ir in place.
        """
        for pol in self.ir.policies:
            if pol.action == PolicyAction.DENY and len(pol.source) == 1 and len(pol.destination) >= 5:
                src_val = pol.source[0]
                if src_val not in ["all", "any"] and any("botnet" in a.lower() or "emotet" in a.lower() or "bad" in a.lower() or "malicious" in a.lower() for a in pol.destination):
                    # This is the anomaly: source is a single specific non-any object, and destination contains threat feeds
                    pol.source = ["any"]
                    
                    # Ensure the threat object is also in the destination (if it's not already there)
                    if src_val not in pol.destination:
                        pol.destination.append(src_val)
                    
                    self.ir.audit_entries.append(IRAuditEntry(
                        id=pol.name,
                        category="Policy Optimization",
                        message=f"Automatically fixed source field anomaly in outbound block rule '{pol.name}': Changed source from '{src_val}' to 'any' and ensured '{src_val}' is in the destination list.",
                        confidence=MigrationConfidence.FULL
                    ))
