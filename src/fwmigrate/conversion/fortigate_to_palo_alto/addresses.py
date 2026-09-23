"""Deterministic FortiGate address mappings for Palo Alto."""

from typing import Any

from .models import (
    MigrationIssue,
    MigrationSourceRef,
    PANMigrationStatus,
    PlannedAddress,
    PlannedAddressGroup,
)


def plan_addresses(source: Any, options: Any) -> tuple[tuple[PlannedAddress, ...], tuple[PlannedAddressGroup, ...], tuple[MigrationIssue, ...]]:
    addresses = []
    groups = []
    issues = []
    for address in getattr(source, "addresses", ()):
        item, issue = _plan_address(address, options)
        addresses.append(item)
        if issue:
            issues.append(issue)
    for group in getattr(source, "address_groups", ()):
        item, issue = _plan_group(group, options)
        groups.append(item)
        if issue:
            issues.append(issue)
    return tuple(addresses), tuple(groups), tuple(issues)


def _scope(source: Any, options: Any) -> tuple[PANMigrationStatus, tuple[str, ...], MigrationIssue | None]:
    vdom = getattr(source, "vdom", "root")
    mapping = getattr(options, "vdoms", {}).get(vdom)
    if mapping is not None and getattr(mapping, "vsys", None):
        return PANMigrationStatus.SUPPORTED, (), None
    warning = f"missing Palo Alto vsys mapping for VDOM {vdom!r}"
    ref = MigrationSourceRef(vdom, "address", getattr(source, "name", None))
    return (
        PANMigrationStatus.MANUAL_REVIEW,
        (warning,),
        MigrationIssue("missing_vsys_mapping", warning, source=ref),
    )


def _plan_address(source: Any, options: Any):
    status, warnings, issue = _scope(source, options)
    value = None
    address_type = None
    if getattr(source, "subnet", None):
        address_type, value = "ip-netmask", source.subnet
    elif getattr(source, "start_ip", None) and getattr(source, "end_ip", None):
        address_type, value = "ip-range", f"{source.start_ip}-{source.end_ip}"
    elif getattr(source, "fqdn", None):
        address_type, value = "fqdn", source.fqdn
    elif getattr(source, "wildcard", None):
        address_type, value = "ip-wildcard", source.wildcard
    elif getattr(source, "wildcard_fqdn", None):
        status = PANMigrationStatus.UNSUPPORTED
        warnings = (*warnings, "wildcard FQDN requires manual target semantics")
    else:
        status = PANMigrationStatus.UNSUPPORTED
        warnings = (*warnings, "address has no supported explicit value")
    return (
        PlannedAddress(
            source_vdom=getattr(source, "vdom", None),
            source_kind="address",
            source_object_type="address",
            source_name=getattr(source, "name", None),
            status=status,
            warnings=warnings,
            address_type=address_type,
            value=value,
        ),
        issue,
    )


def _plan_group(source: Any, options: Any):
    status, warnings, issue = _scope(source, options)
    excluded = bool(getattr(source, "exclude", None) or getattr(source, "exclude_members", ()))
    if excluded:
        status = PANMigrationStatus.MANUAL_REVIEW
        warnings = (*warnings, "address-group exclusions are not represented by a static PAN group")
    return (
        PlannedAddressGroup(
            source_vdom=getattr(source, "vdom", None),
            source_kind="address_group",
            source_object_type="address_group",
            source_name=getattr(source, "name", None),
            status=status,
            warnings=warnings,
            members=tuple(getattr(source, "members", ())),
        ),
        issue,
    )
