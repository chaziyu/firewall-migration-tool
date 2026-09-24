"""ASA-native ClassMap -> PolicyMap -> ServicePolicy relationships."""

from dataclasses import dataclass
from typing import Any

from .references import ASAReferenceIndex


@dataclass(frozen=True, slots=True)
class ASAClassMapRelationship:
    class_map: Any
    targets: tuple[Any, ...] = ()


@dataclass(frozen=True, slots=True)
class ASAPolicyMapRelationship:
    policy_map: Any
    classes: tuple[tuple[Any, Any], ...] = ()
    tcp_maps: tuple[tuple[Any, Any], ...] = ()
    inspection_policies: tuple[tuple[Any, Any], ...] = ()


@dataclass(frozen=True, slots=True)
class ASAServicePolicyRelationship:
    service_policy: Any
    policy_map: Any = None
    interface: Any = None


@dataclass(frozen=True, slots=True)
class ASAMPFRelationships:
    class_maps: tuple[ASAClassMapRelationship, ...] = ()
    policy_maps: tuple[ASAPolicyMapRelationship, ...] = ()
    service_policies: tuple[ASAServicePolicyRelationship, ...] = ()
    issues: tuple[Any, ...] = ()


def build_mpf_relationships(config: Any, references: ASAReferenceIndex) -> ASAMPFRelationships:
    from .references import ASAReferenceIssue, ASAReferenceKind, ASAReferenceStatus
    issues = []
    def resolve(context, kind, source, name, field):
        if not name: return None
        result = references.resolve(context, kind, name)
        if result.status is not ASAReferenceStatus.RESOLVED:
            issues.append(ASAReferenceIssue(context, kind, source, name, result.status, f"Unresolved {kind.value} reference", field))
        return result.target
    class_maps = []
    for item in config.class_maps:
        targets = []
        for match in item.matches:
            if match.match_type == "access_list" and match.acl_name:
                target = resolve(item.source_context, ASAReferenceKind.ACL, item.name, match.acl_name, "class-map")
                if target is not None: targets.append(target)
            elif match.match_type == "class_map" and match.class_map_name:
                target = resolve(item.source_context, ASAReferenceKind.CLASS_MAP, item.name, match.class_map_name, "nested-class-map")
                if target is not None: targets.append(target)
        class_maps.append(ASAClassMapRelationship(item, tuple(targets)))
    policy_maps = []
    for item in config.policy_maps:
        classes = []; tcp_maps = []; inspections = []
        for section in getattr(item, "classes", ()):
            if section.class_name != "class-default":
                target = resolve(item.source_context, ASAReferenceKind.CLASS_MAP, item.name, section.class_name, "policy-class")
                if target is not None: classes.append((section, target))
            if section.tcp_map:
                target = resolve(item.source_context, ASAReferenceKind.TCP_MAP, item.name, section.tcp_map, "tcp-map")
                if target is not None: tcp_maps.append((section, target))
            for action in getattr(section, "inspect_actions", ()):
                if action.policy_name:
                    target = resolve(item.source_context, ASAReferenceKind.INSPECTION_POLICY_MAP, item.name, action.policy_name, "inspect-policy")
                    if target is not None: inspections.append((action, target))
        for section in getattr(item, "inspection_sections", ()):
            if section.kind == "class" and section.class_name:
                target = resolve(item.source_context, ASAReferenceKind.CLASS_MAP, item.name, section.class_name, "inspection-class")
                if target is not None: classes.append((section, target))
        policy_maps.append(ASAPolicyMapRelationship(item, tuple(classes), tuple(tcp_maps), tuple(inspections)))
    services = []
    for item in config.service_policies:
        policy = resolve(item.source_context, ASAReferenceKind.POLICY_MAP, item.name, item.policy_name, "service-policy")
        interface = resolve(item.source_context, ASAReferenceKind.INTERFACE, item.name, item.interface, "service-policy") if item.scope == "interface" else None
        services.append(ASAServicePolicyRelationship(item, policy, interface))
    return ASAMPFRelationships(tuple(class_maps), tuple(policy_maps), tuple(services), tuple(issues))
