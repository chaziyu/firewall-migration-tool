from __future__ import annotations

from ..derived import (
    DerivedViews,
    build_derived_views,
)
from ..model.source import FGConfig
from ..relationships.references import (
    BrokenReference,
    DuplicateObject,
)

from .models import (
    ValidationIssue,
    ValidationResult,
    ValidationSeverity,
)


def validate_config(
    config: FGConfig,
    *,
    derived: DerivedViews | None = None,
) -> ValidationResult:
    """
    Validate extracted FortiGate source objects and derived views.

    Validation responsibilities:
        - duplicate migration-relevant source objects
        - broken source references
        - unresolved interface/VPN topology
        - service-normalization issues
        - NAT derivation issues
        - normalized policy-name collisions
        - VPN selector normalization issues

    Validation does not:
        - mutate FGConfig
        - mutate DerivedViews
        - apply FortiOS defaults
        - silently repair configuration
        - generate target-vendor configuration
    """

    if derived is None:
        derived = build_derived_views(
            config
        )

    issues: list[ValidationIssue] = []

    # --------------------------------------------------------------
    # Reference index integrity
    # --------------------------------------------------------------

    for duplicate in derived.references.duplicates:
        issues.append(
            _duplicate_object_issue(
                duplicate
            )
        )

    # --------------------------------------------------------------
    # Broken references
    # --------------------------------------------------------------

    for broken in derived.broken_references:
        issues.append(
            _broken_reference_issue(
                broken
            )
        )

    # --------------------------------------------------------------
    # Interface topology
    # --------------------------------------------------------------

    for interface in derived.topology.interfaces:
        for message in interface.issues:
            issues.append(
                ValidationIssue(
                    severity=(
                        ValidationSeverity.WARNING
                    ),
                    domain="interface_topology",
                    vdom=interface.vdom,
                    object_name=interface.name,
                    field="interface",
                    message=message,
                )
            )

    # --------------------------------------------------------------
    # VPN topology
    # --------------------------------------------------------------

    for vpn in derived.topology.vpns:
        for message in vpn.issues:
            issues.append(
                ValidationIssue(
                    severity=(
                        ValidationSeverity.WARNING
                    ),
                    domain="vpn_topology",
                    vdom=vpn.vdom,
                    object_name=vpn.name,
                    field="interface",
                    message=message,
                )
            )

    # --------------------------------------------------------------
    # Service transformation
    # --------------------------------------------------------------

    for issue in derived.services.issues:
        issues.append(
            ValidationIssue(
                severity=(
                    ValidationSeverity.WARNING
                ),
                domain="service",
                vdom=issue.vdom,
                object_name=issue.service,
                field=None,
                message=issue.message,
            )
        )

    # --------------------------------------------------------------
    # NAT transformation
    # --------------------------------------------------------------

    for nat in derived.nat:
        object_name = (
            nat.policy_name
            or (
                str(nat.policy_id)
                if nat.policy_id is not None
                else None
            )
        )

        for message in nat.issues:
            issues.append(
                ValidationIssue(
                    severity=(
                        ValidationSeverity.WARNING
                    ),
                    domain="nat",
                    vdom=nat.vdom,
                    object_name=object_name,
                    field="nat",
                    message=message,
                )
            )

    # --------------------------------------------------------------
    # Load-balancing VIP backends
    # --------------------------------------------------------------

    for vip in config.vips:
        if (vip.type or "").lower() not in {
            "load-balance",
            "server-load-balance",
        }:
            continue

        usable_backends = sum(
            bool((backend.ip or "").strip() or (backend.address or "").strip())
            for backend in vip.realservers
        )
        if usable_backends > 0:
            continue

        issues.append(
            ValidationIssue(
                severity=ValidationSeverity.WARNING,
                domain="vip",
                vdom=vip.vdom,
                object_name=vip.name,
                field="realservers",
                message=(
                    "Load-balancing VIP has no configured real-server "
                    "backend with an IP or address."
                ),
            )
        )

    # --------------------------------------------------------------
    # VPN Phase-2 selector transformation
    # --------------------------------------------------------------

    for issue in derived.vpn.issues:
        issues.append(
            ValidationIssue(
                severity=(
                    ValidationSeverity.WARNING
                ),
                domain="vpn_phase2",
                vdom=issue.vdom,
                object_name=issue.phase2,
                field=issue.selector,
                message=issue.message,
            )
        )

    return ValidationResult(
        issues=_deduplicate_issues(
            issues
        )
    )


def _duplicate_object_issue(
    duplicate: DuplicateObject,
) -> ValidationIssue:
    return ValidationIssue(
        severity=ValidationSeverity.ERROR,
        domain=duplicate.kind.value,
        vdom=duplicate.vdom,
        object_name=duplicate.name,
        field="name",
        message=(
            "Multiple explicit objects with this name were extracted in "
            "the same VDOM and object type; source identity is ambiguous."
        ),
    )


def _broken_reference_issue(
    broken: BrokenReference,
) -> ValidationIssue:
    expected = ", ".join(
        kind.value
        for kind in broken.expected_kinds
    )

    return ValidationIssue(
        severity=ValidationSeverity.ERROR,
        domain=broken.source_kind,
        vdom=broken.source_vdom,
        object_name=broken.source_name,
        field=broken.source_field,
        message=(
            f"Reference {broken.reference!r} "
            "could not be resolved in the same "
            f"VDOM. Expected: {expected}."
        ),
    )


def _deduplicate_issues(
    issues: list[ValidationIssue],
) -> list[ValidationIssue]:
    """
    Remove duplicate diagnostics while preserving deterministic order.

    Some failures can be discovered through more than one derived path.
    """

    result: list[ValidationIssue] = []

    seen: set[
        tuple[
            ValidationSeverity,
            str,
            str,
            str | None,
            str | None,
            str,
        ]
    ] = set()

    for issue in issues:
        key = (
            issue.severity,
            issue.domain,
            issue.vdom,
            issue.object_name,
            issue.field,
            issue.message,
        )

        if key in seen:
            continue

        seen.add(key)
        result.append(issue)

    return result
