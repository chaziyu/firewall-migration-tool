from typing import Dict, Any, Optional, List
from .source_model import PANScope, PANSourceObject

class PANResolver:
    def __init__(self):
        # (scope_kind, scope_name) -> { object_type -> { object_name -> PANSourceObject } }
        self._objects: Dict[tuple, Dict[str, Dict[str, PANSourceObject]]] = {}
        # Hierarchy: child device-group -> parent device-group
        self._dg_parents: Dict[str, str] = {}
        # mapping of vsys -> device-group (simplified for now)
        self._vsys_dg: Dict[str, str] = {}

    def register_object(self, obj: PANSourceObject, obj_type: str) -> bool:
        scope_key = (obj.scope.kind, obj.scope.name) if obj.scope else ("shared", "shared")
        if scope_key not in self._objects:
            self._objects[scope_key] = {}
        if obj_type not in self._objects[scope_key]:
            self._objects[scope_key][obj_type] = {}
        if obj.name in self._objects[scope_key][obj_type]:
            return False
        self._objects[scope_key][obj_type][obj.name] = obj
        return True

    def set_dg_parent(self, child_dg: str, parent_dg: str):
        self._dg_parents[child_dg] = parent_dg

    def _search_scopes(self, scope: Optional[PANScope]) -> List[tuple]:
        # Search path: current scope -> parent DGs -> shared
        search_scopes = []
        if scope:
            search_scopes.append((scope.kind, scope.name))
            if scope.kind == "vsys":
                if scope.name in self._vsys_dg:
                    current_dg = self._vsys_dg[scope.name]
                    search_scopes.append(("device-group", current_dg))
                    while current_dg in self._dg_parents:
                        parent = self._dg_parents[current_dg]
                        search_scopes.append(("device-group", parent))
                        current_dg = parent
            elif scope.kind == "device-group":
                current_dg = scope.name
                while current_dg in self._dg_parents:
                    parent = self._dg_parents[current_dg]
                    search_scopes.append(("device-group", parent))
                    current_dg = parent
        search_scopes.append(("shared", "shared"))
        return search_scopes

    def resolve_exact(self, name: str, obj_type: str, scope: Optional[PANScope]) -> Optional[PANSourceObject]:
        scope_key = (scope.kind, scope.name) if scope else ("shared", "shared")
        return self._objects.get(scope_key, {}).get(obj_type, {}).get(name)

    def resolve(self, name: str, obj_type: str, scope: Optional[PANScope]) -> Optional[PANSourceObject]:
        search_scopes = self._search_scopes(scope)
        reference_namespaces = {
            "address-reference": ("address", "address-group"),
            "service-reference": ("service", "service-group"),
            "application-reference": ("application", "application-group", "application-filter"),
        }

        for sk in search_scopes:
            types = self._objects.get(sk, {})
            if obj_type in reference_namespaces:
                candidates = [
                    types[registered_type][name]
                    for registered_type in reference_namespaces[obj_type]
                    if name in types.get(registered_type, {})
                ]
                if len(candidates) == 1:
                    return candidates[0]
                if len(candidates) > 1:
                    # A malformed same-scope collision is ambiguous and must
                    # never resolve by registration order.
                    return None
            elif name in types.get(obj_type, {}):
                return types[obj_type][name]
        
        return None

    def build_canonical_names(self):
        # Address objects and groups have distinct registered identities but
        # share the reference namespace for collision-safe canonical naming.
        for object_types in [
            ("address", "address-group"),
            ("service", "service-group"),
            ("schedule",),
            ("application", "application-group", "application-filter"),
            ("tag",),
        ]:
            name_counts = {}
            for sk, types_dict in self._objects.items():
                for obj_type in object_types:
                    for name in types_dict.get(obj_type, {}):
                        name_counts[name] = name_counts.get(name, 0) + 1

            for sk, types_dict in self._objects.items():
                for obj_type in object_types:
                    for name, obj in types_dict.get(obj_type, {}).items():
                        if name_counts[name] > 1 and sk[0] != "shared":
                            obj.canonical_name = f"{sk[1]}::{name}"
                        else:
                            obj.canonical_name = name
                            
                        if obj.ir_object:
                            obj.ir_object.name = obj.canonical_name

    def canonical_name_for(self, name: str, obj_type: str, scope: Optional[PANScope]) -> Optional[str]:
        obj = self.resolve(name, obj_type, scope)
        if obj and obj.canonical_name:
            return obj.canonical_name
        return None
