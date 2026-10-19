"""Deterministic FortiGate address mappings for Palo Alto."""

from typing import Any

from fwmigrate.conversion.fortigate_to_palo_alto.models import (
    MigrationIssue,
    MigrationSourceRef,
    PANMigrationStatus,
    PlannedAddress,
    PlannedAddressGroup,
)
from fwmigrate.conversion.fortigate_to_palo_alto.planning.routing import _normalize_subnet
from .vips import vip_translation


def explicit_all_vdoms(source):
    return {item.vdom or "root"
            for family in ("addresses", "address_groups", "vips", "vip_groups")
            for item in getattr(source, family, ()) if item.name == "all"}


def address_references(source, vdom, names, *, explicit_all=None):
    """Map only the IPv4 built-in all; explicit objects keep their identity."""
    names = tuple(names)
    if "all" not in names:
        return names
    has_explicit_all = ((vdom or "root") in explicit_all if explicit_all is not None else
                        any(item.name == "all" and (item.vdom or "root") == (vdom or "root")
                            for family in ("addresses", "address_groups", "vips", "vip_groups")
                            for item in getattr(source, family, ())))
    return tuple("0.0.0.0/0" if name == "all" and not has_explicit_all else name for name in names)


def vip_group_addresses(source, vdom, names):
    """Flatten only complete, unambiguous flat VIP groups in policy destinations."""
    result, warnings = [], []
    for name in names:
        groups = [group for group in source.vip_groups if (group.vdom or 'root') == (vdom or 'root') and group.name == name]
        if not groups:
            result.append(name)
            continue
        group = groups[0]
        members = [vip for member in group.members for vip in source.vips if (vip.vdom or 'root') == (vdom or 'root') and vip.name == member]
        conflicting = any(item.name in {name, *group.members} and (item.vdom or 'root') == (vdom or 'root')
            for family in ('addresses', 'address_groups') for item in getattr(source, family, ()))
        if (len(groups) != 1 or not group.members or len(group.members) > 256 or conflicting
                or len(members) != len(group.members) or set(group.raw_extra) - {'color'}
                or any(sum(vip.name == member for vip in members) != 1 for member in group.members)
                or any(group.interface not in {None, 'any', vip.extintf} for vip in members)):
            warnings.append(f'VIP group {name!r} has incomplete, ambiguous or unsupported membership/settings')
            result.append(name)
        else:
            result.extend(group.members)
    return tuple(dict.fromkeys(result)), tuple(warnings)


def plan_addresses(source: Any, options: Any, derived=None) -> tuple[tuple[PlannedAddress, ...], tuple[PlannedAddressGroup, ...], tuple[MigrationIssue, ...]]:
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
    for vip in getattr(source, "vips", ()):
        ext, _, warnings = vip_translation(vip, derived)
        status, scope_warnings, issue = _scope(vip, options)
        warnings = [*scope_warnings, *warnings]
        if warnings:
            status = PANMigrationStatus.MANUAL_REVIEW
        addresses.append(PlannedAddress(
            source_vdom=vip.vdom, source_kind="vip", source_object_type="address", source_name=vip.name,
            target_vsys=_target_vsys(vip, options), target_name=vip.name, status=status,
            warnings=tuple(warnings), address_type="ip-netmask", value=f"{ext}/32" if ext else None))
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


def _target_vsys(source: Any, options: Any) -> str | None:
    mapping = getattr(options, "vdoms", {}).get(getattr(source, "vdom", "root"))
    return getattr(mapping, "vsys", None)


def _plan_address(source: Any, options: Any):
    status, warnings, issue = _scope(source, options)
    value = None
    address_type = None
    representations = {
        "ipmask": bool(getattr(source, "subnet", None)),
        "iprange": bool(getattr(source, "start_ip", None) or getattr(source, "end_ip", None)),
        "fqdn": bool(getattr(source, "fqdn", None)),
        "wildcard": bool(getattr(source, "wildcard", None)),
        "wildcard-fqdn": bool(getattr(source, "wildcard_fqdn", None)),
    }
    selected = getattr(source, "type", None)
    if selected is None:
        candidates = [kind for kind, present in representations.items() if present]
        selected = candidates[0] if len(candidates) == 1 else None
    if selected == "ipmask" and representations["ipmask"]:
        value = _normalize_subnet(source.subnet)
        if value:
            address_type = "ip-netmask"
        else:
            status = PANMigrationStatus.UNSUPPORTED
            warnings = (*warnings, "address subnet is not a valid explicit IPv4 subnet")
    elif selected == "iprange" and getattr(source, "start_ip", None) and getattr(source, "end_ip", None):
        address_type, value = "ip-range", f"{source.start_ip}-{source.end_ip}"
    elif selected == "fqdn" and representations["fqdn"]:
        address_type, value = "fqdn", source.fqdn
    elif selected == "wildcard" and representations["wildcard"]:
        address_type, value = "ip-wildcard", source.wildcard
    elif selected == "wildcard-fqdn":
        status = PANMigrationStatus.UNSUPPORTED
        warnings = (*warnings, "wildcard FQDN requires manual target semantics")
    else:
        status = PANMigrationStatus.UNSUPPORTED
        warnings = (*warnings, "address type/value is missing, ambiguous or unsupported")
    unknown = set(getattr(source, "raw_extra", {})) - {"uuid", "color"}
    if (unknown or getattr(source, "associated_interface", None) not in {None, "any"}
            or getattr(source, "allow_routing", None) not in {None, "disable"}):
        status = PANMigrationStatus.UNSUPPORTED
        warnings = (*warnings, "address settings require manual target semantics"
                    + (": " + ", ".join(sorted(unknown)) if unknown else ""))
    if getattr(source, "address_family", None) == "ipv6" or getattr(source, "ip6", None) is not None:
        status = PANMigrationStatus.UNSUPPORTED
        warnings = (*warnings, "IPv6 address semantics require manual design")
    return (
        PlannedAddress(
            source_vdom=getattr(source, "vdom", None),
            source_kind="address",
            source_object_type="address",
            source_name=getattr(source, "name", None),
            target_vsys=_target_vsys(source, options), target_name=getattr(source, "name", None),
            status=status,
            warnings=warnings,
            address_type=address_type,
            value=value,
        ),
        issue,
    )


def _plan_group(source: Any, options: Any):
    status, warnings, issue = _scope(source, options)
    unknown = set(getattr(source, "raw_extra", {})) - {"uuid", "color"}
    if (getattr(source, "type", None) not in {None, "default"} or unknown
            or getattr(source, "category", None) is not None
            or getattr(source, "allow_routing", None) not in {None, "disable"}):
        status = PANMigrationStatus.UNSUPPORTED
        warnings = (*warnings, "address-group type/settings require manual target semantics")
    if getattr(source, "address_family", None) == "ipv6":
        status = PANMigrationStatus.UNSUPPORTED
        warnings = (*warnings, "IPv6 address-group semantics require manual design")
    exclude = getattr(source, "exclude", None)
    exclude_value = str(exclude).strip().lower() if exclude is not None else None
    excluded_members = getattr(source, "exclude_members", None)
    active_exclusion = exclude_value in {"enable", "enabled", "yes", "true", "1"}
    ambiguous_exclusion = (exclude is not None and exclude_value not in {
        "enable", "enabled", "yes", "true", "1", "disable", "disabled", "no", "false", "0"
    }) or (exclude is None and bool(excluded_members))
    if active_exclusion or ambiguous_exclusion or bool(excluded_members) and exclude_value not in {"disable", "disabled", "no", "false", "0"}:
        status = PANMigrationStatus.MANUAL_REVIEW
        warnings = (*warnings, "address-group exclusions are not represented by a static PAN group")
    if source.members is None:
        status = PANMigrationStatus.MANUAL_REVIEW
        warnings = (*warnings, "address-group membership is not explicit in the source")
    return (
        PlannedAddressGroup(
            source_vdom=getattr(source, "vdom", None),
            source_kind="address_group",
            source_object_type="address_group",
            source_name=getattr(source, "name", None),
            target_vsys=_target_vsys(source, options), target_name=getattr(source, "name", None),
            status=status,
            warnings=warnings,
            members=tuple(source.members or ()),
        ),
        issue,
    )
