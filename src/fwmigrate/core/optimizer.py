from typing import Dict, List, Set, Any
from fwmigrate.ir.core import IRConfig, IRAddress, IRService, IRPolicy
from fwmigrate.ir.enums import PolicyAction

class RuleOptimizer:
    """Security rulebase and object optimization engine."""

    def __init__(self, ir: IRConfig):
        self.ir = ir

    def find_unused_objects(self) -> Dict[str, List[str]]:
        """Identify address and service objects not referenced anywhere."""
        used_addresses: Set[str] = set()
        used_services: Set[str] = set()

        # Check groups
        for grp in self.ir.address_groups:
            used_addresses.update(grp.members)
        for sgrp in self.ir.service_groups:
            used_services.update(sgrp.members)

        # Check policies
        for pol in self.ir.policies:
            used_addresses.update(pol.source)
            used_addresses.update(pol.destination)
            used_services.update(pol.service)

        # Check NAT
        for nat in self.ir.nat_rules:
            used_addresses.update(nat.source)
            used_addresses.update(nat.destination)
            if nat.service and nat.service != "any":
                used_services.add(nat.service)

        unused_addrs = [a.name for a in self.ir.addresses if a.name not in used_addresses and a.name not in ["any", "all"]]
        unused_svcs = [s.name for s in self.ir.services if s.name not in used_services and s.name not in ["any", "ALL", "service-http", "service-https"]]

        return {
            "unused_addresses": unused_addrs,
            "unused_services": unused_svcs
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
                # If preceding matches any/all and same zones
                same_action = (preceding.action == current.action)
                preceding_broad_src = preceding.source in [["any"], ["all"], []]
                preceding_broad_dst = preceding.destination in [["any"], ["all"], []]
                preceding_broad_svc = preceding.service in [["any"], ["ALL"], []]
                preceding_broad_zones = (
                    (preceding.from_zone in [["any"], []] or preceding.from_zone == current.from_zone) and
                    (preceding.to_zone in [["any"], []] or preceding.to_zone == current.to_zone)
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

        new_ir = self.ir.model_copy(deep=True)
        new_ir.addresses = [a for a in new_ir.addresses if a.name not in unused_addr_set]
        new_ir.services = [s for s in new_ir.services if s.name not in unused_svc_set]
        return new_ir
