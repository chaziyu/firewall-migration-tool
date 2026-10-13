"""ASA NAT source operands, without effective NAT evaluation."""

from dataclasses import dataclass
from typing import Any

from .references import ASAReferenceIndex


@dataclass(frozen=True, slots=True)
class ASANATRelationship:
    source_context: str | None
    rule: Any
    owning_object: Any = None
    source_interface: Any = None
    destination_interface: Any = None
    real_source: Any = None
    mapped_source: Any = None
    real_destination: Any = None
    mapped_destination: Any = None
    pat_pool: Any = None
    original_service: Any = None
    translated_service: Any = None
    service_operand_1: Any = None
    service_operand_2: Any = None
    access_list: Any = None
    issues: tuple[Any, ...] = ()


@dataclass(frozen=True, slots=True)
class ASANATRelationships:
    rules: tuple[ASANATRelationship, ...] = ()
    issues: tuple[Any, ...] = ()


def build_nat_relationships(config: Any, references: ASAReferenceIndex) -> ASANATRelationships:
    from .references import ASAReferenceIssue, ASAReferenceKind, ASAReferenceStatus
    rows = []; all_issues = []
    for rule in config.nat_rules:
        context = getattr(rule, "source_context", None); issues = []
        def one(kind, name, field, *, required=False):
            if not name: return None
            result = references.resolve(context, kind, name)
            if result.status is not ASAReferenceStatus.RESOLVED and required:
                issues.append(ASAReferenceIssue(context, kind, rule.name, name, result.status, "Unresolved NAT reference", field))
            return result.target
        def address(name, field):
            if not name or name.lower() in {"interface", "any", "original", "translated"}: return None
            try:
                from ipaddress import ip_network
                ip_network(name, strict=False); return None
            except ValueError: pass
            obj = one(ASAReferenceKind.NETWORK_OBJECT, name, field)
            if obj is not None: return obj
            return one(ASAReferenceKind.NETWORK_GROUP, name, field, required=True)
        owner = one(ASAReferenceKind.NETWORK_OBJECT, rule.owning_object, "owning-object", required=True)
        source_if = one(ASAReferenceKind.INTERFACE, rule.source_interface, "source-interface", required=True) if rule.source_interface and rule.source_interface.casefold() != "any" else None
        dest_if = one(ASAReferenceKind.INTERFACE, rule.destination_interface, "destination-interface", required=True) if rule.destination_interface and rule.destination_interface.casefold() != "any" else None
        real_s = address(rule.real_source, "real-source"); mapped_s = address(rule.mapped_source, "mapped-source")
        real_d = address(rule.real_destination, "real-destination"); mapped_d = address(rule.mapped_destination, "mapped-destination")
        pat = address(rule.pat_pool, "pat-pool")
        def service(name, field):
            if not name: return None
            value = one(ASAReferenceKind.SERVICE_OBJECT, name, field)
            return value if value is not None else one(ASAReferenceKind.SERVICE_GROUP, name, field, required=True)
        original = service(rule.original_service, "original-service"); translated = service(rule.translated_service, "translated-service")
        operand_1 = service(getattr(rule, "service_operand_1", None), "service-operand-1")
        operand_2 = service(getattr(rule, "service_operand_2", None), "service-operand-2")
        acl = one(ASAReferenceKind.ACL, rule.access_list, "access-list", required=True)
        row = ASANATRelationship(context, rule, owner, source_if, dest_if, real_s, mapped_s, real_d, mapped_d, pat, original, translated, operand_1, operand_2, acl, tuple(issues))
        rows.append(row); all_issues.extend(issues)
    return ASANATRelationships(tuple(rows), tuple(all_issues))
