from typing import Dict, List
from fwmigrate.ir import IRConfig
from fwmigrate.core.normalizer import IRNormalizer
from fwmigrate.ir.dependency import DependencyGraph
from fwmigrate.ir.index import IRIndex


class RuleOptimizer:
    """Security rulebase and object optimization engine."""

    def __init__(
        self,
        ir: IRConfig,
        *,
        ir_index: IRIndex | None = None,
        dependency_graph: DependencyGraph | None = None,
    ):
        self.ir = ir
        self.ir_index = ir_index
        self.dependency_graph = dependency_graph or DependencyGraph(ir)
        self._unused_objects_cache: Dict[str, List[str]] | None = None

    def find_unused_objects(self) -> Dict[str, List[str]]:
        """Identify address and service objects not referenced anywhere."""
        if self._unused_objects_cache is not None:
            return self._unused_objects_cache

        used = self.dependency_graph.reachable_reference_names()
        used_addresses = used["addresses"]
        used_services = used["services"]
        used_address_groups = used["address_groups"]
        used_service_groups = used["service_groups"]

        unused_addrs = [a.name for a in self.ir.addresses if a.name not in used_addresses and a.name not in ["any", "all"]]
        unused_svcs = [s.name for s in self.ir.services if s.name not in used_services and s.name not in ["any", "ALL", "service-http", "service-https"]]
        unused_addr_groups = [g.name for g in self.ir.address_groups if g.name not in used_address_groups]
        unused_svc_groups = [g.name for g in self.ir.service_groups if g.name not in used_service_groups]

        self._unused_objects_cache = {
            "unused_addresses": unused_addrs,
            "unused_services": unused_svcs,
            "unused_address_groups": unused_addr_groups,
            "unused_service_groups": unused_svc_groups,
        }
        return self._unused_objects_cache

    def prune_unused_objects(self) -> IRConfig:
        """Create a new IRConfig copy with unused objects removed."""
        unused = self.find_unused_objects()
        unused_addr_set = set(unused["unused_addresses"])
        unused_svc_set = set(unused["unused_services"])
        unused_addr_grp_set = set(unused.get("unused_address_groups", []))
        unused_svc_grp_set = set(unused.get("unused_service_groups", []))

        new_ir = self.ir.model_copy()
        new_ir.addresses = [a for a in self.ir.addresses if a.name not in unused_addr_set]
        new_ir.services = [s for s in self.ir.services if s.name not in unused_svc_set]
        new_ir.address_groups = [g for g in self.ir.address_groups if g.name not in unused_addr_grp_set]
        new_ir.service_groups = [g for g in self.ir.service_groups if g.name not in unused_svc_grp_set]
        return new_ir

    def fix_outbound_threat_source_anomalies(self):
        """Compatibility wrapper for callers of the former optimizer method."""
        return IRNormalizer(self.ir).normalize_outbound_threat_source_anomalies()
