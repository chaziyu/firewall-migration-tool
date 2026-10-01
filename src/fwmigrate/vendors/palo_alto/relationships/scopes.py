from __future__ import annotations

from dataclasses import dataclass

from ..source_model import PANScope, pan_scope_identity


@dataclass(frozen=True, slots=True)
class PANDeviceGroupHierarchy:
    parents: tuple[tuple[str, str | None], ...] = ()
    ancestors: tuple[tuple[str, tuple[str, ...]], ...] = ()
    descendants: tuple[tuple[str, tuple[str, ...]], ...] = ()
    issues: tuple[str, ...] = ()

    def parent_of(self, scope_identity: str) -> str | None:
        return dict(self.parents).get(scope_identity)


def _device_owner(scope: PANScope) -> str | None:
    return scope.device_serial or scope.device_name


def build_scope_hierarchy(scopes: list[PANScope]) -> PANDeviceGroupHierarchy:
    device_groups = [scope for scope in scopes if scope.kind == "device-group"]
    by_owner_name = {(_device_owner(scope), scope.name): scope for scope in device_groups}
    parents: dict[str, str | None] = {}
    issues: list[str] = []

    for scope in device_groups:
        identity = pan_scope_identity(scope)
        parent_identity = None
        if scope.parent_device_group:
            parent_scope = by_owner_name.get((_device_owner(scope), scope.parent_device_group))
            if parent_scope is None:
                issues.append(
                    f"missing parent device-group {scope.parent_device_group} for {identity}"
                )
            else:
                parent_identity = pan_scope_identity(parent_scope)
        if identity in parents and parents[identity] != parent_identity:
            issues.append(f"conflicting parent declarations for device-group {identity}")
        parents[identity] = parent_identity

    ancestors: dict[str, tuple[str, ...]] = {}
    for identity in parents:
        chain: list[str] = []
        current = parents[identity]
        seen = {identity}
        while current:
            if current in seen:
                issues.append(f"device-group hierarchy cycle at {current}")
                break
            chain.append(current)
            seen.add(current)
            if current not in parents:
                issues.append(f"missing parent device-group {current} for {identity}")
                break
            current = parents[current]
        ancestors[identity] = tuple(chain)

    descendants = {identity: [] for identity in parents}
    for child, chain in ancestors.items():
        for parent in chain:
            if parent in descendants:
                descendants[parent].append(child)

    return PANDeviceGroupHierarchy(
        tuple(parents.items()),
        tuple(ancestors.items()),
        tuple((key, tuple(value)) for key, value in descendants.items()),
        tuple(dict.fromkeys(issues)),
    )


def visible_scopes(scope: PANScope | None, hierarchy: PANDeviceGroupHierarchy) -> tuple[str, ...]:
    if scope is None:
        return ("shared:shared",)
    if scope.kind == "device-group":
        identity = pan_scope_identity(scope)
        return (identity, *dict(hierarchy.ancestors).get(identity, ()), "shared:shared")
    if scope.kind in {"vsys", "device"}:
        return (pan_scope_identity(scope), "shared:shared")
    return (pan_scope_identity(scope),)
