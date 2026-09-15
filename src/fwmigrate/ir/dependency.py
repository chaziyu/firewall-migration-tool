from dataclasses import dataclass
from typing import List, Dict, Set, Tuple
from collections import defaultdict
from fwmigrate.ir import IRConfig
from fwmigrate.ir.metadata import IRAuditEntry
from fwmigrate.ir.enums import MigrationConfidence


@dataclass(frozen=True)
class DependencyEdge:
    source_type: str
    source_id: str
    target_type: str
    target_id: str
    field: str


@dataclass(frozen=True)
class DependencyIssue:
    source_type: str
    source_id: str
    target_type: str
    reference: str
    field: str
    reason: str

class DependencyGraph:
    """
    Manages dependency ordering of IR objects for output generation.
    PAN-OS requires objects to be defined before they are referenced.
    Order: Zones -> Interfaces -> Addresses -> Address Groups -> Services ->
           Service Groups -> Schedules -> NAT Rules -> Policies -> Routes -> VPN
    """
    
    def __init__(self, config: IRConfig):
        self.config = config
        self.edges: List[DependencyEdge] = []
        self.issues: List[DependencyIssue] = []
        self._dependencies: Dict[Tuple[str, str], Set[Tuple[str, str]]] = {}
        self._root_references: Dict[str, Set[str]] = {"addresses": set(), "services": set()}
        self._built = False

    _UNIVERSAL = {"any", "all", "none", "ALL", "application-default"}

    def build(self) -> "DependencyGraph":
        """Build reference edges once; this derived graph never mutates the IR."""
        if self._built:
            return self

        address_names = {item.name for item in self.config.addresses}
        address_group_names = {item.name for item in self.config.address_groups}
        service_names = {item.name for item in self.config.services}
        service_group_names = {item.name for item in self.config.service_groups}
        zone_names = {item.name for item in self.config.zones}

        def resolve(name: str, target_type: str) -> List[Tuple[str, str]]:
            if target_type == "addresses":
                return [("address_groups", name)] if name in address_group_names else [("addresses", name)] if name in address_names else []
            if target_type == "services":
                return [("service_groups", name)] if name in service_group_names else [("services", name)] if name in service_names else []
            if target_type == "zones" and name in zone_names:
                return [("zones", name)]
            return []

        def add(source_type: str, source_id: str, target_type: str, name: str, field: str) -> None:
            if not name or name in self._UNIVERSAL or name.casefold() in {item.casefold() for item in self._UNIVERSAL}:
                return
            targets = resolve(name, target_type)
            if not targets:
                self.issues.append(DependencyIssue(source_type, source_id, target_type, name, field, "unresolved reference"))
                return
            source = (source_type, source_id)
            for target in targets:
                self.edges.append(DependencyEdge(source_type, source_id, target[0], target[1], field))
                self._dependencies.setdefault(source, set()).add(target)

        for group in self.config.address_groups:
            for member in [*group.members, *getattr(group, "exclude_members", [])]:
                add("address_groups", group.name, "addresses", member, "members")
        for group in self.config.service_groups:
            for member in [*group.members, *getattr(group, "unsafe_members", [])]:
                add("service_groups", group.name, "services", member, "members")
        for policy in self.config.policies:
            for ref in [*policy.source, *policy.destination]:
                self._root_references["addresses"].add(ref)
                add("policies", policy.name, "addresses", ref, "source_or_destination")
            for ref in policy.service:
                self._root_references["services"].add(ref)
                add("policies", policy.name, "services", ref, "service")
            for ref in [*policy.from_zone, *policy.to_zone]:
                add("policies", policy.name, "zones", ref, "zone")
        for nat in self.config.nat_rules:
            for ref in [
                *nat.source,
                *nat.destination,
                *getattr(nat, "translated_sources", []),
                *getattr(nat, "translated_destinations", []),
            ]:
                self._root_references["addresses"].add(ref)
                add("nat_rules", nat.name, "addresses", ref, "address")
            for ref in [
                *getattr(nat, "services", []),
                *getattr(nat, "translated_services", []),
            ]:
                self._root_references["services"].add(ref)
                add("nat_rules", nat.name, "services", ref, "service")
        self._built = True
        return self

    def reachable_reference_names(self) -> Dict[str, Set[str]]:
        """Return names reachable from policy/NAT roots for optimizer pruning."""
        self.build()
        result = {
            "addresses": set(),
            "services": set(),
            "address_groups": set(),
            "service_groups": set(),
        }
        result["addresses"].update(self._root_references["addresses"])
        result["services"].update(self._root_references["services"])
        roots = [
            ("policies", policy.name) for policy in self.config.policies
        ] + [
            ("nat_rules", rule.name) for rule in self.config.nat_rules
        ]
        stack = list(roots)
        seen: Set[Tuple[str, str]] = set()
        while stack:
            node = stack.pop()
            if node in seen:
                continue
            seen.add(node)
            for target in self._dependencies.get(node, set()):
                if target[0] in {"addresses", "address_groups"}:
                    result["addresses"].add(target[1])
                elif target[0] in {"services", "service_groups"}:
                    result["services"].add(target[1])
                if target[0] in result:
                    result[target[0]].add(target[1])
                stack.append(target)

        # Preserve the optimizer's historic behavior for unresolved references:
        # a same-named object is never pruned merely because resolution failed.
        for edge in self.edges:
            if edge.source_type in {"policies", "nat_rules"}:
                if edge.target_type in {"addresses", "address_groups"}:
                    result["addresses"].add(edge.target_id)
                elif edge.target_type in {"services", "service_groups"}:
                    result["services"].add(edge.target_id)
                if edge.target_type in result:
                    result[edge.target_type].add(edge.target_id)
        for issue in self.issues:
            if issue.source_type in {"policies", "nat_rules"}:
                if issue.target_type in {"addresses", "services"}:
                    result[issue.target_type].add(issue.reference)
        return result

    @property
    def dependencies(self) -> Dict[Tuple[str, str], Set[Tuple[str, str]]]:
        self.build()
        return self._dependencies

    @property
    def missing(self) -> List[DependencyIssue]:
        self.build()
        return self.issues

    def get_dependencies(self, source_type: str, source_id: str) -> Set[Tuple[str, str]]:
        return set(self.dependencies.get((source_type, source_id), set()))

    def get_dependents(self, target_type: str, target_id: str) -> Set[Tuple[str, str]]:
        target = (target_type, target_id)
        return {
            source
            for source, targets in self.dependencies.items()
            if target in targets
        }
        
    def get_ordered_components(self):
        """Returns the configuration components in the correct dependency order."""
        # For MVP, we can rely on static ordering because PAN-OS schema naturally groups these.
        # But within address groups, we might need topological sort if they reference other groups.
        
        # Sort address groups if there are nested groups
        ordered_address_groups = self._topological_sort_groups(self.config.address_groups)
        
        # Sort service groups
        ordered_service_groups = self._topological_sort_groups(self.config.service_groups)
        
        return {
            "zones": self.config.zones,
            "interfaces": self.config.interfaces,
            "addresses": self.config.addresses,
            "address_groups": ordered_address_groups,
            "services": self.config.services,
            "service_groups": ordered_service_groups,
            "schedules": self.config.schedules,
            "nat_rules": self.config.nat_rules,
            "policies": self.config.policies,
            "vpn_tunnels": self.config.vpn_tunnels,
            "routes": self.config.routes,
        }

    def _topological_sort_groups(self, groups: List) -> List:
        """Simple topological sort for groups that might reference each other."""
        graph = defaultdict(list)
        in_degree = defaultdict(int)
        
        name_to_group = {g.name: g for g in groups}
        
        # Initialize in-degree for all groups
        for g in groups:
            if g.name not in in_degree:
                in_degree[g.name] = 0
                
        # Build graph
        for g in groups:
            for member in [*g.members, *getattr(g, "exclude_members", [])]:
                if member in name_to_group:
                    # member is a group, so g depends on member
                    # member -> g
                    graph[member].append(g.name)
                    in_degree[g.name] += 1
                    
        # Sort
        queue = [name for name, deg in in_degree.items() if deg == 0]
        sorted_groups = []
        
        while queue:
            node = queue.pop(0)
            sorted_groups.append(name_to_group[node])
            
            for neighbor in graph[node]:
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)
                    
        # If there's a cycle, the sorted list will be smaller than the original
        if len(sorted_groups) != len(groups):
            # For our MVP, just append the remaining (cycle handling)
            added = {g.name for g in sorted_groups}
            for g in groups:
                if g.name not in added:
                    sorted_groups.append(g)
                    self.config.audit_entries.append(IRAuditEntry(
                        id=g.name,
                        category="Dependency Graph",
                        message=f"Circular dependency detected involving group '{g.name}'. This may cause target generation or deployment failures.",
                        confidence=MigrationConfidence.MANUAL
                    ))
                    
        return sorted_groups
