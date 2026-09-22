from __future__ import annotations

from dataclasses import dataclass

from ..source_model import PANScope, pan_scope_identity


@dataclass(frozen=True, slots=True)
class PANDeviceGroupHierarchy:
    parents: tuple[tuple[str, str | None], ...] = ()
    ancestors: tuple[tuple[str, tuple[str, ...]], ...] = ()
    descendants: tuple[tuple[str, tuple[str, ...]], ...] = ()
    issues: tuple[str, ...] = ()

    def parent_of(self, name: str) -> str | None:
        return dict(self.parents).get(name)


def build_scope_hierarchy(scopes: list[PANScope]) -> PANDeviceGroupHierarchy:
    parents: dict[str, str | None] = {}
    issues: list[str] = []
    for scope in scopes:
        if scope.kind != "device-group":
            continue
        if scope.name in parents and parents[scope.name] != scope.parent_device_group:
            issues.append(f"conflicting parent declarations for device-group {scope.name}")
        parents[scope.name] = scope.parent_device_group
    ancestors: dict[str, tuple[str, ...]] = {}
    for name in parents:
        chain: list[str] = []
        current = parents[name]
        seen = {name}
        while current:
            if current in seen:
                issues.append(f"device-group hierarchy cycle at {current}")
                break
            chain.append(current)
            seen.add(current)
            if current not in parents:
                issues.append(f"missing parent device-group {current} for {name}")
                break
            current = parents[current]
        ancestors[name] = tuple(chain)
    descendants = {name: [] for name in parents}
    for child, chain in ancestors.items():
        for parent in chain:
            if parent in descendants:
                descendants[parent].append(child)
    return PANDeviceGroupHierarchy(tuple(parents.items()), tuple(ancestors.items()), tuple((k, tuple(v)) for k, v in descendants.items()), tuple(dict.fromkeys(issues)))


def visible_scopes(scope: PANScope | None, hierarchy: PANDeviceGroupHierarchy) -> tuple[str, ...]:
    if scope is None:
        return ("shared:shared",)
    if scope.kind == "device-group":
        return (f"device-group:{scope.name}", *[f"device-group:{name}" for name in dict(hierarchy.ancestors).get(scope.name, ())], "shared:shared")
    if scope.kind in {"vsys", "device"}:
        return (pan_scope_identity(scope), "shared:shared")
    return (pan_scope_identity(scope),)
