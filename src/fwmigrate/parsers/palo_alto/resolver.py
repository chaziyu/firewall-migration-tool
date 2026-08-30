from typing import Dict, Any, Optional, List
from dataclasses import dataclass

from .source_model import PANScope, PANSourceObject


@dataclass(frozen=True)
class PANVsysIdentity:
    """Stable internal identity for a managed firewall VSYS."""

    device_serial: str
    vsys_name: str

class PANResolver:
    def __init__(self):
        # (scope_kind, scope_name) -> { object_type -> { object_name -> PANSourceObject } }
        self._objects: Dict[tuple, Dict[str, Dict[str, PANSourceObject]]] = {}
        # Hierarchy: child device-group -> parent device-group
        self._dg_parents: Dict[str, str] = {}
        # Compatibility mapping for unqualified/standalone VSYS scopes.
        self._vsys_dg: Dict[str, str] = {}
        # Panorama mapping keyed by the complete managed-firewall identity.
        self._vsys_dg_by_device: Dict[PANVsysIdentity, str] = {}

    def register_object(self, obj: PANSourceObject, obj_type: str) -> bool:
        scope_key = self._scope_key(obj.scope)
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

    @staticmethod
    def _scope_key(scope: Optional[PANScope]) -> tuple:
        if scope is None:
            return ("shared", "shared")
        if scope.kind == "vsys" and scope.device_serial:
            return (scope.kind, scope.name, scope.device_serial)
        return (scope.kind, scope.name)

    @staticmethod
    def scope_from_key(scope_key: tuple) -> PANScope:
        if len(scope_key) >= 3 and scope_key[0] == "vsys":
            return PANScope(kind=scope_key[0], name=scope_key[1], vsys=scope_key[1],
                            device_serial=scope_key[2], device_name=scope_key[2])
        return PANScope(kind=scope_key[0], name=scope_key[1])

    def set_vsys_device_group(self, vsys: str, device_group: str,
                               device_serial: Optional[str] = None):
        if device_serial:
            self._vsys_dg_by_device[PANVsysIdentity(device_serial, vsys)] = device_group
            # Keep the old map only while the name is unambiguous.  This
            # prevents a second firewall's vsys1 from overwriting the first.
            if vsys not in self._vsys_dg:
                self._vsys_dg[vsys] = device_group
            elif self._vsys_dg[vsys] != device_group:
                self._vsys_dg.pop(vsys, None)
        else:
            self._vsys_dg[vsys] = device_group

    def device_group_for_vsys(self, vsys: str, device_serial: Optional[str] = None) -> Optional[str]:
        if device_serial:
            return self._vsys_dg_by_device.get(PANVsysIdentity(device_serial, vsys))
        return self._vsys_dg.get(vsys)

    def managed_vsys_identities(self) -> List[PANVsysIdentity]:
        return list(self._vsys_dg_by_device)

    def _search_scopes(self, scope: Optional[PANScope]) -> List[tuple]:
        # Search path: current scope -> parent DGs -> shared
        search_scopes = []
        if scope:
            search_scopes.append(self._scope_key(scope))
            if scope.kind == "vsys":
                current_dg = self.device_group_for_vsys(scope.name, scope.device_serial)
                if current_dg:
                    search_scopes.append(("device-group", current_dg))
                    visited = {current_dg}
                    while current_dg in self._dg_parents:
                        parent = self._dg_parents[current_dg]
                        if parent in visited:
                            break
                        visited.add(parent)
                        search_scopes.append(("device-group", parent))
                        current_dg = parent
            elif scope.kind == "device-group":
                current_dg = scope.name
                visited = {current_dg}
                while current_dg in self._dg_parents:
                    parent = self._dg_parents[current_dg]
                    if parent in visited:
                        break
                    visited.add(parent)
                    search_scopes.append(("device-group", parent))
                    current_dg = parent
        search_scopes.append(("shared", "shared"))
        return search_scopes

    def resolve_exact(self, name: str, obj_type: str, scope: Optional[PANScope]) -> Optional[PANSourceObject]:
        scope_key = self._scope_key(scope)
        return self._objects.get(scope_key, {}).get(obj_type, {}).get(name)

    def resolve(self, name: str, obj_type: str, scope: Optional[PANScope]) -> Optional[PANSourceObject]:
        search_scopes = self._search_scopes(scope)
        # A legacy caller may omit the serial.  Falling back is safe only when
        # exactly one qualified VSYS with this name exists; with two devices,
        # ambiguity must remain unresolved rather than crossing devices.
        if scope and scope.kind == "vsys" and not scope.device_serial:
            qualified = [key for key in self._objects
                         if len(key) >= 3 and key[0] == "vsys" and key[1] == scope.name]
            if len(qualified) == 1:
                search_scopes.insert(1, qualified[0])
        reference_namespaces = {
            "address-reference": ("address", "address-group"),
            "service-reference": ("service", "service-group"),
            "application-reference": ("application", "application-group", "application-filter"),
        }

        for sk in search_scopes:
            types = self._objects.get(sk, {})
            if obj_type == "security-profile-reference":
                candidates = [
                    registered_objects[name]
                    for registered_type, registered_objects in types.items()
                    if registered_type.startswith("security-profile:")
                    and name in registered_objects
                ]
                if len(candidates) == 1:
                    return candidates[0]
                if len(candidates) > 1:
                    return None
            elif obj_type in reference_namespaces:
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
            ("profile-group",),
        ]:
            name_counts = {}
            for sk, types_dict in self._objects.items():
                for obj_type in object_types:
                    for name in types_dict.get(obj_type, {}):
                        name_counts[name] = name_counts.get(name, 0) + 1

            for sk, types_dict in self._objects.items():
                for obj_type in object_types:
                    for name, obj in types_dict.get(obj_type, {}).items():
                        if len(sk) >= 3 and sk[0] == "vsys":
                            obj.canonical_name = f"{sk[2]}::{sk[1]}::{name}"
                        elif name_counts[name] > 1 and sk[0] != "shared":
                            obj.canonical_name = f"{sk[1]}::{name}"
                        else:
                            obj.canonical_name = name
                            
                        if obj.ir_object:
                            obj.ir_object.name = obj.canonical_name

        # Security-profile definitions are source-only, but references still
        # need collision-safe names when inherited definitions shadow one
        # another or multiple managed VSYSs use the same profile name.
        profile_counts = {}
        for types_dict in self._objects.values():
            for obj_type, objects in types_dict.items():
                if obj_type.startswith("security-profile:"):
                    for name in objects:
                        profile_counts[(obj_type, name)] = profile_counts.get((obj_type, name), 0) + 1
        for sk, types_dict in self._objects.items():
            for obj_type, objects in types_dict.items():
                if not obj_type.startswith("security-profile:"):
                    continue
                for name, obj in objects.items():
                    if len(sk) >= 3 and sk[0] == "vsys":
                        obj.canonical_name = f"{sk[2]}::{sk[1]}::{name}"
                    elif profile_counts[(obj_type, name)] > 1 and sk[0] != "shared":
                        obj.canonical_name = f"{sk[1]}::{name}"
                    else:
                        obj.canonical_name = name

    def canonical_name_for(self, name: str, obj_type: str, scope: Optional[PANScope]) -> Optional[str]:
        obj = self.resolve(name, obj_type, scope)
        if obj and obj.canonical_name:
            return obj.canonical_name
        return None
