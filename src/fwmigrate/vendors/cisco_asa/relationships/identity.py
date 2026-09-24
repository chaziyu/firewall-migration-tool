"""ASA local identity and AAA relationships; external selectors stay source selectors."""

from dataclasses import dataclass
from typing import Any

from .references import ASAReferenceIndex


@dataclass(frozen=True, slots=True)
class ASAIdentityRelationship:
    source: Any
    server_group: Any = None
    interface: Any = None
    acl: Any = None
    local_user: Any = None
    user_group: Any = None
    selector_status: str | None = None


@dataclass(frozen=True, slots=True)
class ASAIdentityRelationships:
    relationships: tuple[ASAIdentityRelationship, ...] = ()
    issues: tuple[Any, ...] = ()


def build_identity_relationships(config: Any, references: ASAReferenceIndex) -> ASAIdentityRelationships:
    from .references import ASAReferenceIssue, ASAReferenceKind, ASAReferenceStatus
    rows = []; issues = []
    for item in (*tuple(config.aaa_server_hosts), *tuple(config.aaa_authentication_rules), *tuple(config.aaa_authorization_rules), *tuple(config.aaa_accounting_rules)):
        ctx = getattr(item, "source_context", None)
        def ref(kind, name, field):
            if not name: return None
            result = references.resolve(ctx, kind, name)
            if result.status is not ASAReferenceStatus.RESOLVED:
                issues.append(ASAReferenceIssue(ctx, kind, item.name, name, result.status, f"Unresolved {kind.value} reference", field))
            return result.target
        group = ref(ASAReferenceKind.AAA_SERVER_GROUP, getattr(item, "group_name", None) or getattr(item, "server_group", None), "aaa-server-group")
        interface = ref(ASAReferenceKind.INTERFACE, getattr(item, "interface", None), "aaa-interface")
        acl = ref(ASAReferenceKind.ACL, getattr(item, "acl_reference", None), "aaa-acl")
        selector = getattr(item, "user_identity", None)
        user = None; user_group = None; status = None
        if selector:
            result = references.resolve(ctx, ASAReferenceKind.LOCAL_USER, selector)
            user = result.target
            if result.status is ASAReferenceStatus.UNRESOLVED:
                group_result = references.resolve(ctx, ASAReferenceKind.USER_GROUP, selector)
                user_group = group_result.target
                status = group_result.status.value if group_result.status is not ASAReferenceStatus.UNRESOLVED else "SOURCE_SELECTOR"
            else:
                status = result.status.value
        rows.append(ASAIdentityRelationship(item, group, interface, acl, user, user_group, status))
    return ASAIdentityRelationships(tuple(rows), tuple(issues))
