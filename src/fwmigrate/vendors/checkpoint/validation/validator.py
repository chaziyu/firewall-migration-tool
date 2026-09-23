"""Read-only Check Point source validation."""

from __future__ import annotations

from ipaddress import ip_network
from typing import Any

from fwmigrate.extraction.sanitize import REDACTED_PLACEHOLDER, is_sensitive_key

from ..derived import CheckPointDerivedViews
from ..model.common import CheckPointSourceObject
from ..model.gaia import CPGaiaStaticRoute
from ..model.policy import CPAutoNATRule, CPNATRule
from ..model.source import CheckPointConfig
from ..models import CollectionStatus, ScopeSelectionResult
from .models import CheckPointValidationIssue, CheckPointValidationResult


def validate_checkpoint_config(
    config: CheckPointConfig,
    derived: CheckPointDerivedViews,
    *,
    collection: tuple = (),
    scope: ScopeSelectionResult | None = None,
    source_inventory: tuple = (),
) -> CheckPointValidationResult:
    """Report issues from explicit source and already-derived evidence."""
    issues = []
    for check in (
        _validate_collection(collection or derived.collection_incomplete),
        _validate_scope(scope),
        _validate_duplicates(config),
        _validate_references(derived),
        _validate_policy_structure(derived),
        _validate_inline_layers(config, derived),
        _validate_nat(config, derived),
        _validate_interface_topology(derived),
        _validate_vpn_topology(derived),
        _validate_gaia(config, source_inventory),
        _validate_secret_safety(config, source_inventory),
        _validate_unsupported_selected_areas(collection, source_inventory),
    ):
        issues.extend(check)
    unique = {}
    for issue in issues:
        identity = (issue.code, issue.domain_uid or issue.domain, issue.object_uid or issue.object_name,
                    issue.field, issue.reference)
        unique.setdefault(identity, issue)
    return CheckPointValidationResult(tuple(unique.values()))


def _issue(code: str, category: str, message: str, *, severity: str = "warning",
           source: Any = None, field: str | None = None, reference: str | None = None,
           domain: str | None = None, domain_uid: str | None = None,
           package: str | None = None, package_uid: str | None = None,
           layer: str | None = None, layer_uid: str | None = None, gateway: str | None = None,
           object_type: str | None = None, object_uid: str | None = None,
           object_name: str | None = None, command: str | None = None) -> CheckPointValidationIssue:
    return CheckPointValidationIssue(
        code=code, severity=severity, category=category, message=message,
        domain=domain or getattr(source, "domain", None),
        domain_uid=domain_uid or getattr(source, "domain_uid", None),
        package=package or getattr(source, "package", None),
        package_uid=package_uid or getattr(source, "package_uid", None),
        layer=layer or getattr(source, "layer", None),
        layer_uid=layer_uid or getattr(source, "layer_uid", None),
        gateway=gateway or getattr(source, "gateway", None),
        object_type=object_type or (type(source).__name__ if source is not None else None),
        object_uid=object_uid or getattr(source, "uid", None),
        object_name=object_name or getattr(source, "name", None),
        field=field, command=command or getattr(source, "command", None), reference=reference,
    )


def _validate_collection(items):
    result = []
    for item in items:
        if item.complete and item.status != CollectionStatus.UNSUPPORTED_COMMAND:
            continue
        error = item.status in {CollectionStatus.API_ERROR, CollectionStatus.TRANSPORT_ERROR,
                                CollectionStatus.PERMISSION_DENIED, CollectionStatus.ERROR}
        code = "selected_area_unsupported" if item.status == CollectionStatus.UNSUPPORTED_COMMAND else "collection_incomplete"
        result.append(_issue(code, "unsupported" if not error else "collection",
            item.error or (f"Unsupported collection command: {item.command}" if code == "selected_area_unsupported"
                           else f"Collection incomplete: {item.command}"),
            severity="error" if error else "warning", command=item.command,
            field="collection", domain=item.domain, package=item.package,
            layer=item.layer, gateway=item.gateway))
    return result


def _validate_scope(scope):
    if not scope or not scope.ambiguous:
        return []
    return [_issue("scope_ambiguous", "scope", f"Source scope is ambiguous: {reason}.", field="scope")
            for reason in (scope.reasons or ["unspecified"])]


def _domain(item):
    return item.domain_uid or item.domain or "global"


def _validate_duplicates(config):
    result = []
    seen_uids, seen_names = {}, {}
    for field_name in config.model_fields:
        objects = getattr(config, field_name)
        if not isinstance(objects, list):
            continue
        for item in objects:
            if not isinstance(item, CheckPointSourceObject):
                continue
            scope = _domain(item)
            if item.uid:
                key = (scope, item.uid)
                seen_uids.setdefault(key, []).append(item)
            if item.name:
                key = (scope, type(item), item.name)
                seen_names.setdefault(key, []).append(item)
    for (domain, value), objects in seen_uids.items():
        if len(objects) > 1:
            result.append(_issue("duplicate_uid", "duplicate", f"Duplicate UID within domain: {value}.",
                source=objects[0], reference=value, domain_uid=objects[0].domain_uid or None,
                domain=domain if domain != "global" else None))
    for (_, kind, value), objects in seen_names.items():
        if len(objects) > 1:
            result.append(_issue("duplicate_name", "duplicate", f"Duplicate {kind.__name__} name within domain: {value}.",
                source=objects[0], reference=value))
    return result


def _validate_references(derived):
    result = []
    codes = {"missing": "reference_missing", "ambiguous": "reference_ambiguous",
             "wrong_type": "reference_wrong_type", "cross_scope": "reference_cross_scope",
             "conflicting_relationship": "reference_conflicting_relationship"}
    for item in derived.broken_references:
        source = item.source
        result.append(_issue(codes.get(item.status, "reference_missing"), "reference",
            item.message or f"Check Point reference {item.status}: {item.reference}", source=source,
            field=item.source_field, reference=item.reference,
            command=getattr(source, "command", None)))
    return result


def _validate_policy_structure(derived):
    result = []
    for relation in derived.policy_structure.package_layers:
        if relation.issue:
            result.append(_issue("package_layer_missing",
                "policy_structure", relation.issue.message or "Package references a missing access layer.",
                source=relation.package, field=relation.source_field, reference=relation.issue.reference))
    for section in derived.policy_structure.sections:
        if section.layer is None:
            result.append(_issue("policy_section_orphan", "policy_structure",
                "Section cannot be associated with an access layer.", source=section.section, field="layer_uid"))
    for layer in derived.policy_structure.sections:
        section = layer.section
        if section.layer_uid and layer.layer and section.layer_uid != layer.layer.uid:
            result.append(_issue("policy_section_owner_mismatch", "policy_structure",
                "Section layer ownership conflicts with its resolved layer.", source=section,
                field="layer_uid", reference=section.layer_uid))
    for rule in derived.policy_structure.rules:
        owner_layer = next((item.layer for item in derived.policy_structure.package_layers if item.layer and
                            (item.layer.uid == (rule.layer_uid or rule.parent_layer_uid) if rule.layer_uid or rule.parent_layer_uid else item.layer.name == rule.layer)), None)
        if rule.layer_uid and not owner_layer:
            result.append(_issue("policy_rule_layer_mismatch", "policy_structure",
                "Rule layer ownership does not resolve to a package layer.", source=rule,
                field="layer_uid", reference=rule.layer_uid))
        if rule.parent_layer_uid and owner_layer and owner_layer.uid != rule.parent_layer_uid:
            result.append(_issue("policy_parent_layer_invalid", "policy_structure",
                "Rule parent layer UID does not match its owning layer.", source=rule,
                field="parent_layer_uid", reference=rule.parent_layer_uid))
    owned_layers = {}
    for relation in derived.policy_structure.package_layers:
        if relation.layer:
            owned_layers.setdefault(id(relation.layer), []).append(relation.package)
    for layer_id, relations in owned_layers.items():
        if len({id(item) for item in relations}) > 1:
            relation_layer = next(item.layer for item in derived.policy_structure.package_layers if item.layer and id(item.layer) == layer_id)
            result.append(_issue("policy_duplicate_ownership", "policy_structure",
                "Access layer is structurally owned by multiple packages.", source=relation_layer,
                field="package_uid"))
    for issue in derived.policy_traversal.issues:
        result.append(_issue("policy_traversal_cycle" if "cycle" in issue.message.lower() else "policy_traversal_invalid",
            "policy_structure", issue.message, object_type="CPAccessRule", object_uid=issue.rule_uid,
            field="inline_layer", reference=issue.reference))
    return result


def _validate_inline_layers(config, derived):
    result = []
    for relation in derived.policy_structure.inline_layers:
        if relation.inline_layer is None:
            issue = relation.issue
            status = issue.status if issue else "missing"
            code = {"wrong_type": "inline_layer_wrong_type", "ambiguous": "inline_layer_ambiguous"}.get(status, "inline_layer_missing")
            result.append(_issue(code, "policy_structure", issue.message if issue else "Inline layer is missing.",
                source=relation.parent_rule, field="inline_layer", reference=issue.reference if issue else relation.parent_rule.inline_layer))
            continue
        child = relation.inline_layer
        rule = relation.parent_rule
        if child.parent_rule_uid and child.parent_rule_uid != rule.uid:
            result.append(_issue("inline_layer_parent_rule_mismatch", "policy_structure",
                "Inline layer parent rule does not match its referencing rule.", source=rule,
                field="parent_rule_uid", reference=child.parent_rule_uid))
        if relation.parent_layer and child.parent_layer_uid and child.parent_layer_uid != relation.parent_layer.uid:
            result.append(_issue("inline_layer_parent_mismatch", "policy_structure",
                "Inline layer parent does not match the referencing rule layer.", source=child,
                field="parent_layer_uid", reference=child.parent_layer_uid))
    return result


def _validate_nat(config, derived):
    result = []
    for rule in config.nat_rules:
        if isinstance(rule, CPNATRule):
            if any((rule.translated_source, rule.translated_destination, rule.translated_service)) and not any(
                (rule.original_source, rule.original_destination, rule.original_service)
            ):
                result.append(_issue("nat_structure_incomplete", "nat",
                    "Manual NAT translation is present without original match fields.", source=rule,
                    field="original_source"))
            for field in ("original_source", "original_destination", "original_service"):
                if field in rule.explicit_fields and not getattr(rule, field):
                    result.append(_issue("nat_structure_incomplete", "nat", f"Manual NAT has an explicitly empty {field}.", source=rule, field=field))
            if rule.method and not any((rule.translated_source, rule.translated_destination, rule.translated_service)):
                result.append(_issue("nat_translation_missing", "nat", "NAT method is set but translated fields are empty.", source=rule, field="translated_source"))
            if rule.order is not None and rule.order < 0:
                result.append(_issue("nat_order_malformed", "nat", "NAT rule ordering value is invalid.", source=rule, field="order"))
        if isinstance(rule, CPAutoNATRule) and not any((rule.translated_source, rule.translated_destination, rule.translated_service)):
            result.append(_issue("nat_structure_incomplete", "nat", "Automatic NAT rule has no translated fields.", source=rule, field="translated_source"))
    for item in derived.nat.issues:
        result.append(_issue("nat_structure_incomplete", "nat", item.message,
            domain=item.domain, object_uid=item.source_uid, object_name=item.source_name,
            field=item.source_field, reference=item.reference))
    return result


def _validate_interface_topology(derived):
    result = []
    for item in derived.interface_topology.issues:
        result.append(_issue("zone_reference_missing" if item.status == "missing" else f"zone_reference_{item.status}",
            "interface_topology", item.message or f"Zone reference is {item.status}.", source=item.source,
            field=item.source_field, reference=item.reference))
    for item in derived.interface_views.issues:
        if "ambigu" in item.message.lower() or "correlation" in item.message.lower():
            result.append(_issue("interface_correlation_ambiguous", "interface_topology", item.message,
                object_type="interface", object_uid=item.device_uid, object_name=item.interface_name))
    return result


def _validate_vpn_topology(derived):
    result = []
    for item in derived.vpn_topology.issues:
        result.append(_issue("vpn_member_missing" if item.status == "missing" else f"vpn_reference_{item.status}",
            "vpn_topology", item.message or f"VPN relationship is {item.status}.", source=item.source,
            field=item.source_field, reference=item.reference))
    for relation in derived.vpn_topology.vtis:
        if len(relation.matching_communities) > 1:
            result.append(_issue("vpn_community_ambiguous", "vpn_topology",
                "VTI matches multiple VPN communities.", source=relation.vti,
                field="matching_communities", reference=getattr(relation.vti, "name", None)))
    return result


def _validate_gaia(config, inventory):
    result = []
    for route in config.gaia_static_routes:
        family = (route.address_family or "").lower()
        if family not in {"ipv4", "ipv6"}:
            result.append(_issue("gaia_route_malformed", "gaia", "Static route address family is invalid.", source=route, field="address_family"))
        if family == "ipv4" and route.ipv6_destination or family == "ipv6" and route.ipv4_destination:
            result.append(_issue("gaia_route_malformed", "gaia", "Static route destination conflicts with its address family.", source=route, field="destination"))
        if route.blackhole is True and route.reject is True:
            result.append(_issue("gaia_route_malformed", "gaia", "Static route cannot be both blackhole and reject.", source=route, field="blackhole"))
        for field in ("priority", "rank"):
            value = getattr(route, field)
            if value is not None and value < 0:
                result.append(_issue("gaia_route_malformed", "gaia", f"Static route {field} must not be negative.", source=route, field=field))
        destination = route.ipv4_destination or route.ipv6_destination
        if not destination and getattr(route, "default", False) is not True:
            result.append(_issue("gaia_route_malformed", "gaia", "Static route destination is missing.", source=route, field="destination"))
        if route.blackhole is not True and route.reject is not True and not (route.next_hop or route.outgoing_interface):
            result.append(_issue("gaia_route_malformed", "gaia", "Static route has no next hop or outgoing interface.", source=route, field="next_hop"))
    for server in config.gaia_dhcp_servers:
        result.extend(_dhcp_issues(server))
    for item in inventory:
        values = getattr(item, "values", {}) or {}
        if getattr(item, "source_plane", None) == "gaia" and "dhcp" in str(getattr(item, "command", "")).lower():
            if not values.get("subnet") and not values.get("name"):
                result.append(_issue("gaia_dhcp_malformed", "gaia", "DHCP source record has no explicit subnet identity.",
                    command=getattr(item, "command", None), field="subnet", domain=getattr(item, "domain", None)))
    return result


def _dhcp_issues(server):
    result = []
    for subnet in server.subnets:
        try:
            if subnet.subnet:
                ip_network(f"{subnet.subnet}/{subnet.prefix}" if subnet.prefix is not None else subnet.subnet, strict=False)
            elif subnet.prefix is not None:
                raise ValueError
        except ValueError:
            result.append(_issue("gaia_dhcp_malformed", "gaia", "DHCP subnet address or prefix is malformed.", source=subnet, field="subnet"))
        for group_name in ("included_pools", "excluded_pools"):
            for pool in getattr(subnet, group_name):
                if bool(pool.start) != bool(pool.end):
                    result.append(_issue("gaia_dhcp_malformed", "gaia", "DHCP pool must provide both start and end.", source=pool, field=group_name))
                elif pool.start and pool.end:
                    try:
                        if ip_network(f"{pool.start}/32", strict=False).network_address > ip_network(f"{pool.end}/32", strict=False).network_address:
                            raise ValueError
                    except ValueError:
                        result.append(_issue("gaia_dhcp_malformed", "gaia", "DHCP pool range is malformed or reversed.", source=pool, field=group_name))
    return result


def _validate_secret_safety(config, inventory):
    result = []
    def scan(value, path):
        if hasattr(value, "model_dump"):
            value = value.model_dump(mode="python")
        if isinstance(value, dict):
            for key, child in value.items():
                child_path = f"{path}.{key}" if path else str(key)
                safe_metadata = str(key).lower().replace("-", "_").endswith(("_configured", "_present")) and child in (True, "yes", "configured")
                if is_sensitive_key(str(key)) and not safe_metadata and child not in (None, False, "", REDACTED_PLACEHOLDER, "[configured]"):
                    result.append(_issue("secret_material_detected", "secret_safety",
                        "Secret-bearing source material survived sanitization.", field=child_path))
                else:
                    scan(child, child_path)
        elif isinstance(value, (list, tuple)):
            for index, child in enumerate(value):
                scan(child, f"{path}[{index}]")
    scan(config, "config")
    scan(inventory, "source_inventory")
    return result


def _validate_unsupported_selected_areas(collection, inventory):
    # Unsupported command diagnostics are reported by _validate_collection;
    # inventory-only unsupported objects retain their source identity here.
    result = []
    for item in inventory:
        object_type = getattr(item, "object_type", None) or getattr(item, "type", None)
        if object_type and str(object_type).lower() in {"unsupported", "unknown"}:
            result.append(_issue("selected_area_unsupported", "unsupported",
                f"Source object type is unsupported: {object_type}.", command=getattr(item, "command", None),
                domain=getattr(item, "domain", None), object_uid=getattr(item, "uid", None),
                object_name=getattr(item, "name", None), object_type=str(object_type)))
    return result


__all__ = ["validate_checkpoint_config"]
