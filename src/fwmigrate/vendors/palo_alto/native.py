"""PAN-OS read-only reporting views and compatibility exports."""

from __future__ import annotations

from .source_builder import build_panos_config
from .model.source import PANOSConfig
from .source_model import (
    PANOSDerivedViews,
    PANOSValidationIssue,
    PANOSValidationResult,
    pan_scope_identity,
)
from .xml_loader import load_pan_source


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
        "route": len(config.static_routes),
        "virtual-router": len(config.virtual_routers),
        "logical-router": len(config.logical_routers),
    }
    return PANOSDerivedViews(
        counts=counts,
        scope_identities=tuple(pan_scope_identity(scope) for scope in config.scopes),
        unresolved_references=(),
    )


def validate_panos_config(config: PANOSConfig, derived: PANOSDerivedViews) -> PANOSValidationResult:
    issues: list[PANOSValidationIssue] = []
    if not config.source_inventory:
        issues.append(PANOSValidationIssue("warning", "source", "PAN-OS XML contains no entry records."))
    if not config.scopes:
        issues.append(PANOSValidationIssue("warning", "scope", "PAN-OS XML contains no explicit device, VSYS, or device-group scope."))
    return PANOSValidationResult(tuple(issues))


__all__ = ["build_derived_views", "build_panos_config", "load_pan_source", "validate_panos_config"]
