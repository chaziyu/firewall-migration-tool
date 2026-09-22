"""PAN-OS read-only reporting views and compatibility exports."""

from __future__ import annotations

from .source_builder import build_panos_config
from .model.source import PANOSConfig
from .source_model import (
    PANOSDerivedViews,
    pan_scope_identity,
)
from .xml_loader import load_pan_source
from .relationships import build_interface_topology, build_policy_order, build_reference_index, build_scope_hierarchy
from .relationships.references import resolve_references
from .transform.nat import transform_nat
from .validation import PANOSValidationIssue, PANOSValidationResult, validate_panos_config


def build_derived_views(config: PANOSConfig) -> PANOSDerivedViews:
    counts = {
        "address": len(config.addresses),
        "address-group": len(config.address_groups),
        "service": len(config.services),
        "service-group": len(config.service_groups),
        "schedule": len(config.schedules),
        "security_rule": len(config.security_rules),
        "default_security_rule": len(config.default_security_rules),
        "interface": len(config.interfaces),
        "interface-unit": len(config.interface_units),
        "interface-import": len(config.interface_imports),
        "nat": len(config.nat_rules),
        "zone": len(config.zones),
        "route": len(config.static_routes),
        "virtual-router": len(config.virtual_routers),
        "logical-router": len(config.logical_routers),
    }
    hierarchy = build_scope_hierarchy(config.scopes)
    index = build_reference_index(config)
    resolutions, shadowing = resolve_references(config, index)
    topology = build_interface_topology(config)
    policy_order = build_policy_order(config, hierarchy)
    return PANOSDerivedViews(
        counts=counts,
        scope_identities=tuple(pan_scope_identity(scope) for scope in config.scopes),
        unresolved_references=tuple(f"{item.owner_name}.{item.owner_field}: {item.reference_name}" for item in resolutions if item.status == "UNRESOLVED"),
        scope_hierarchy=hierarchy,
        reference_index=index,
        reference_resolutions=resolutions,
        shadowing=shadowing,
        interface_topology=topology,
        policy_order=policy_order,
        nat=transform_nat(config.nat_rules),
        relationship_issues=tuple(hierarchy.issues) + tuple(issue for item in topology for issue in item.issues),
    )


__all__ = ["build_derived_views", "build_panos_config", "load_pan_source", "validate_panos_config"]
