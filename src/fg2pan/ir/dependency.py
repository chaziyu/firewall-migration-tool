from typing import List, Dict, Set
from collections import defaultdict
from fg2pan.ir.core import IRConfig

class DependencyGraph:
    """
    Manages dependency ordering of IR objects for output generation.
    PAN-OS requires objects to be defined before they are referenced.
    Order: Zones -> Interfaces -> Addresses -> Address Groups -> Services ->
           Service Groups -> Schedules -> NAT Rules -> Policies -> Routes -> VPN
    """
    
    def __init__(self, config: IRConfig):
        self.config = config
        
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
            for member in g.members:
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
                    
        return sorted_groups
