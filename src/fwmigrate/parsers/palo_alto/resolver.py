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

    def register_object(self, obj: PANSourceObject, obj_type: str):
        scope_key = (obj.scope.kind, obj.scope.name) if obj.scope else ("shared", "shared")
        if scope_key not in self._objects:
            self._objects[scope_key] = {}
        if obj_type not in self._objects[scope_key]:
            self._objects[scope_key][obj_type] = {}
        self._objects[scope_key][obj_type][obj.name] = obj

    def set_dg_parent(self, child_dg: str, parent_dg: str):
        self._dg_parents[child_dg] = parent_dg

    def resolve(self, name: str, obj_type: str, scope: Optional[PANScope]) -> Optional[PANSourceObject]:
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
        
        for sk in search_scopes:
            if sk in self._objects and obj_type in self._objects[sk]:
                if name in self._objects[sk][obj_type]:
                    return self._objects[sk][obj_type][name]
        
        return None
