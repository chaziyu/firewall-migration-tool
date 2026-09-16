from dataclasses import dataclass, field
from typing import Dict, List, Any
from fwmigrate.ir import IRConfig
from fwmigrate.core.normalizer import IRNormalizer
from fwmigrate.ir.dependency import DependencyGraph
from fwmigrate.ir.index import IRIndex


@dataclass(frozen=True)
class _ShadowRule:
    source: frozenset[str]
    destination: frozenset[str]
    service: frozenset[str]
    from_zone: frozenset[str]
    to_zone: frozenset[str]
    from_zone_any: bool
    to_zone_any: bool


@dataclass
class _ShadowDimensionIndex:
    any_keywords: frozenset[str]
    broad: set[int] = field(default_factory=set)
    by_value: Dict[str, set[int]] = field(default_factory=dict)

    def add(self, index: int, values: frozenset[str]) -> None:
        if not values or self.any_keywords.intersection(values):
            self.broad.add(index)
        for value in values:
            self.by_value.setdefault(value, set()).add(index)

    def candidates(self, values: frozenset[str]) -> set[int] | None:
        if not values:
            return None
        specific: set[int] | None = None
        for value in values:
            matching = self.by_value.get(value, set())
            specific = set(matching) if specific is None else specific.intersection(matching)
        return self.broad | (specific or set())


def _is_subset(
    current: frozenset[str],
    preceding: frozenset[str],
    any_keywords: frozenset[str],
) -> bool:
    if not current:
        return True
    if not preceding:
        return False
    if any_keywords.intersection(preceding):
        return True
    return current.issubset(preceding)


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
        indexes = (
            _ShadowDimensionIndex(frozenset({"any", "all"})),
            _ShadowDimensionIndex(frozenset({"any", "all"})),
            _ShadowDimensionIndex(frozenset({"any", "ALL"})),
            _ShadowDimensionIndex(frozenset({"any"})),
            _ShadowDimensionIndex(frozenset({"any"})),
        )
        safe_indices: set[int] = set()
        rules = [
            _ShadowRule(
                source=frozenset(policy.source),
                destination=frozenset(policy.destination),
                service=frozenset(policy.service),
                from_zone=frozenset(policy.from_zone),
                to_zone=frozenset(policy.to_zone),
                from_zone_any=not policy.from_zone or "any" in policy.from_zone,
                to_zone_any=not policy.to_zone or "any" in policy.to_zone,
            )
            for policy in self.ir.policies
        ]

        for i, current_policy in enumerate(self.ir.policies):
            current = rules[i]
            if not current_policy.safe_for_target_generation:
                continue

            candidates = None
            for index, values in zip(indexes, (
                current.source,
                current.destination,
                current.service,
                current.from_zone,
                current.to_zone,
            )):
                possible = index.candidates(values)
                if possible is not None:
                    candidates = possible if candidates is None else candidates.intersection(possible)
            candidate_indices = safe_indices if candidates is None else candidates

            # ponytail: broad-rule buckets can still be O(P²); add subset indexes if profiling large rulebases requires it.
            for j in sorted(candidate_indices):
                preceding_policy = self.ir.policies[j]
                preceding = rules[j]
                if not (
                    _is_subset(current.source, preceding.source, frozenset({"any", "all"}))
                    and _is_subset(current.destination, preceding.destination, frozenset({"any", "all"}))
                    and _is_subset(current.service, preceding.service, frozenset({"any", "ALL"}))
                    and (
                        preceding.from_zone_any
                        or current.from_zone.issubset(preceding.from_zone)
                    )
                    and (
                        preceding.to_zone_any
                        or current.to_zone.issubset(preceding.to_zone)
                    )
                ):
                    continue
                shadowed.append({
                    "rule": current_policy.name,
                    "rule_index": i + 1,
                    "shadowed_by": preceding_policy.name,
                    "shadowed_by_index": j + 1,
                    "action_match": preceding_policy.action == current_policy.action,
                })
                break

            safe_indices.add(i)
            for index, values in zip(indexes, (
                current.source,
                current.destination,
                current.service,
                current.from_zone,
                current.to_zone,
            )):
                index.add(i, values)
        return shadowed

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
