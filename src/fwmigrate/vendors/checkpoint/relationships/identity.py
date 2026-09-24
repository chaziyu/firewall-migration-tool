from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..model.source import CheckPointConfig
from .references import CPMembership, CPBrokenReference, CPReferenceIndex, CPReferenceKind, CPResolvedReference


@dataclass(frozen=True, slots=True)
class CPAdministratorPermissionRelationship:
    administrator: Any; permission_profile: Any | None; reference: str; issue: CPBrokenReference | None = None


@dataclass(frozen=True, slots=True)
class CPAccessRoleRelationship:
    role: Any; field: str; reference: str; target: Any | None; kind: CPReferenceKind | None; issue: CPBrokenReference | None = None


@dataclass(frozen=True, slots=True)
class CPIdentityRelationships:
    administrator_permissions: tuple[CPAdministratorPermissionRelationship, ...] = ()
    memberships: tuple[CPMembership, ...] = ()
    access_roles: tuple[CPAccessRoleRelationship, ...] = ()
    issues: tuple[CPBrokenReference, ...] = ()


def build_identity_relationships(config: CheckPointConfig, references: CPReferenceIndex | None = None) -> CPIdentityRelationships:
    from .references import build_reference_index
    references = references or build_reference_index(config); admins = []; memberships = []; roles = []; issues = []
    for admin in config.administrators:
        for value in admin.permission_profiles:
            result = references.resolve(value, owner=admin, expected_kinds=(CPReferenceKind.PERMISSION_PROFILE,), source_field="permission_profiles")
            if isinstance(result, CPResolvedReference): admins.append(CPAdministratorPermissionRelationship(admin, result.target, result.reference))
            else: admins.append(CPAdministratorPermissionRelationship(admin, None, result.reference, result)); issues.append(result)
    for user in config.users: memberships.extend(_user_edges(user, references))
    for group in config.user_groups:
        memberships.extend(_membership_edges(group, "members", group.members, references, (CPReferenceKind.USER, CPReferenceKind.USER_GROUP)))
        memberships.extend(_membership_edges(group, "users", group.users, references, (CPReferenceKind.USER,)))
    for role in config.access_roles:
        for field, values, kinds in (("networks", role.networks, (CPReferenceKind.HOST, CPReferenceKind.NETWORK, CPReferenceKind.ADDRESS_RANGE, CPReferenceKind.ADDRESS)), ("users", role.users, (CPReferenceKind.USER,)), ("groups", role.groups, (CPReferenceKind.USER_GROUP,))):
            for value in values:
                result = references.resolve(value, owner=role, expected_kinds=kinds, source_field=field)
                if isinstance(result, CPResolvedReference): roles.append(CPAccessRoleRelationship(role, field, result.reference, result.target, result.kind))
                else: roles.append(CPAccessRoleRelationship(role, field, result.reference, None, None, result)); issues.append(result)
    issues.extend(edge.issue for edge in memberships if edge.issue)
    return CPIdentityRelationships(tuple(admins), tuple(memberships), tuple(roles), tuple(issues))


def _membership_edges(owner, field, values, references, kinds):
    result = []
    for value in values or ():
        resolution = references.resolve(value, owner=owner, expected_kinds=kinds, source_field=field)
        if isinstance(resolution, CPResolvedReference): result.append(CPMembership(owner, field, resolution.reference, resolution.target, resolution.kind, resolution.scope))
        else: result.append(CPMembership(owner, field, resolution.reference, None, None, resolution.scope, resolution.status, resolution))
    return result


def _user_edges(user, references):
    return _membership_edges(user, "groups", user.groups, references, (CPReferenceKind.USER_GROUP,))


__all__ = ["CPAccessRoleRelationship", "CPAdministratorPermissionRelationship", "CPIdentityRelationships", "build_identity_relationships"]
