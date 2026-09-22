"""PAN-OS read-only reporting views and compatibility exports."""

from __future__ import annotations

from collections import Counter

from .source_builder import build_panos_config
from .source_model import (
    PANOSConfig,
    PANOSDerivedViews,
    PANOSValidationIssue,
    PANOSValidationResult,
    pan_scope_identity,
)
from .xml_loader import load_pan_source


def build_derived_views(config: PANOSConfig) -> PANOSDerivedViews:
    counts = dict(Counter(record.kind for record in config.records))
    return PANOSDerivedViews(
        counts=counts,
        scope_identities=tuple(pan_scope_identity(scope) for scope in config.scopes),
    )


def validate_panos_config(config: PANOSConfig, derived: PANOSDerivedViews) -> PANOSValidationResult:
    issues: list[PANOSValidationIssue] = []
    if not config.records:
        issues.append(PANOSValidationIssue("warning", "source", "PAN-OS XML contains no entry records."))
    if not config.scopes:
        issues.append(PANOSValidationIssue("warning", "scope", "PAN-OS XML contains no explicit device, VSYS, or device-group scope."))
    return PANOSValidationResult(tuple(issues))


__all__ = ["build_derived_views", "build_panos_config", "load_pan_source", "validate_panos_config"]
