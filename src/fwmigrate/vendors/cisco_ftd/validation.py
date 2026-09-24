"""Validation for FTD source reporting."""

from dataclasses import dataclass
from datetime import datetime, time
from ipaddress import ip_address

from .derived import FTDDerivedViews
from .model import CiscoFTDConfig


@dataclass(frozen=True)
class FTDValidationIssue:
    severity: str
    category: str
    message: str
    source_plane: str
    source_object: str | None = None


@dataclass(frozen=True)
class FTDValidationResult:
    issues: tuple[FTDValidationIssue, ...] = ()


def validate_ftd_config(config: CiscoFTDConfig, derived: FTDDerivedViews) -> FTDValidationResult:
    issues = [FTDValidationIssue("error",
        "ambiguous-reference" if item.status == "AMBIGUOUS" else
        "wrong-kind-reference" if item.status == "WRONG_KIND" else "unresolved-reference",
        f"{item.reason.replace('-', ' ').capitalize()} FTD reference {item.reference} in {item.field}; "
        f"expected {' | '.join(item.expected_kinds)}; found {' | '.join(item.found_kinds) or 'none'} "
        f"in domain/scope {item.domain_id or item.scope or 'source'}",
        item.source_plane, item.owner) for item in derived.unresolved_references]
    issues.extend(FTDValidationIssue("warning", "unsupported", str(item.get("reason", "Unsupported source evidence")),
                                     config.source_plane, str(item.get("source_path", "")))
                  for item in config.unsupported_evidence)
    issues.extend(FTDValidationIssue("warning", item.category, item.message, config.source_plane, item.interface)
                  for item in derived.interface_topology.issues)
    issues.extend(FTDValidationIssue("warning", "invalid-route", item.issue or "Invalid FTD static route",
                                     config.source_plane, item.source_name)
                  for item in derived.normalized_routes if item.issue)
    issues.extend(FTDValidationIssue("warning", "intrusion-rule-group-conflict",
        f"Intrusion rule {item.rule_id or item.source_id} differs between policy behavior and rule-group evidence",
        item.source_plane, item.name) for item in config.intrusion_rule_behaviors
        if item.source_attributes.get("conflicting_group_payload"))

    intrusion_policies_by_id = {item.source_id: item for item in config.intrusion_policies if item.source_id}
    parts = config.collection_metadata.parts
    if any(part.name == "access_policies" and part.status == "SUCCESS" for part in parts):
        for policy in config.access_control_policies:
            if not any(part.name == f"accesspolicies/{policy.source_id}/default_actions" for part in parts):
                issues.append(FTDValidationIssue("warning", "missing-acp-default-action-collection",
                    f"Access policy {policy.name} has no collected default-action child response",
                    policy.source_plane, policy.name))

    for override in config.intrusion_rule_overrides:
        linked_policy = intrusion_policies_by_id.get(override.parent_policy_id)
        known_behaviors = {item.rule_id or item.source_id for item in config.intrusion_rule_behaviors
                           if item.parent_policy_id == override.parent_policy_id}
        if linked_policy is None or (derived.source_plane_completeness.get("intrusion_rule_behaviors") in {"present", "known-empty"}
                and override.rule_id and override.rule_id not in known_behaviors):
            issues.append(FTDValidationIssue("warning", "unlinked-intrusion-rule-override",
                f"Intrusion override {override.rule_id or override.name} cannot be linked to its policy/rule",
                override.source_plane, override.name))

    for policy in config.nat_policies:
        for rule in policy.unclassified_manual_rules or ():
            issues.append(FTDValidationIssue("warning", "unknown-nat-manual-section",
                f"Manual NAT rule {rule.name} has an unclassified source section",
                rule.source_plane, rule.name))

    positions = {}
    for route in config.policy_based_routes:
        if route.position is None:
            continue
        key = (route.device_id or route.source_attributes.get("device_id"),
               route.source_attributes.get("virtual_router_id"), route.position)
        positions.setdefault(key, []).append(route)
    for (_, _, position), routes in positions.items():
        if len(routes) > 1:
            issues.append(FTDValidationIssue("warning", "duplicate-pbr-position",
                f"Policy-based routes share explicit position {position} within one device/virtual router",
                routes[0].source_plane, routes[0].name))

    servers_by_device = {item.device_id or item.source_attributes.get("device_id") for item in config.dhcp_servers}
    relay_devices = {item.device_id or item.source_attributes.get("device_id") for item in config.dhcp_relay_settings}
    for device_id in servers_by_device & relay_devices:
        issues.append(FTDValidationIssue("error", "dhcp-server-relay-conflict",
            f"Device {device_id or 'source'} has both DHCP server and DHCP relay source configuration",
            config.source_plane, str(device_id) if device_id else None))

    identity_collections = (
        ("realm user", config.realm_users), ("realm group", config.realm_user_groups),
        ("local realm user", config.local_realm_users), ("FMC user", config.fmc_users),
    )
    for label, records in identity_collections:
        seen_ids = set()
        for item in records:
            if item.source_id and item.source_id in seen_ids:
                issues.append(FTDValidationIssue("error", "duplicate-identity-id",
                    f"Duplicate {label} ID {item.source_id} in the same source domain",
                    item.source_plane, item.name))
            seen_ids.add(item.source_id)

    by_realm_name = set()
    for item in (*config.realm_users, *config.realm_user_groups, *config.local_realm_users):
        realm = item.realm
        if realm is None or not (realm.source_id or realm.name):
            continue
        identity_name = getattr(item, "username", None) or item.name
        key = (item.domain_id, type(item), realm.source_id or realm.name, identity_name.casefold())
        if key in by_realm_name:
            issues.append(FTDValidationIssue("warning", "ambiguous-identity-name",
                f"Identity {identity_name} is duplicated within Realm {realm.name or realm.source_id}",
                item.source_plane, item.name))
        by_realm_name.add(key)

    for role in config.fmc_user_roles:
        for field in ("menu_permissions", "system_permissions", "other_permissions"):
            value = getattr(role, field)
            if value is not None and not isinstance(value, (dict, list)):
                issues.append(FTDValidationIssue("warning", "unknown-role-permission-shape",
                    f"FMC role {role.name} has an unrecognized {field.replace('_', ' ')} structure",
                    role.source_plane, role.name))

    for pool in config.address_pools:
        if not pool.start_address and not pool.end_address:
            continue
        try:
            start, end = ip_address(pool.start_address), ip_address(pool.end_address)
            valid = (start.version == end.version == (4 if pool.address_family == "IPv4" else 6)
                     and start <= end)
        except (ValueError, TypeError):
            valid = False
        if not valid:
            issues.append(FTDValidationIssue("warning", "invalid-ra-address-pool",
                f"Address pool {pool.name} has an invalid explicit range or address family",
                pool.source_plane, pool.name))

    def valid_iso(parser, value) -> bool:
        try:
            parser(value)
            return True
        except (TypeError, ValueError):
            return False

    weekdays = {"MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"}
    for item in config.time_ranges:
        for field, label in (("absolute_start_date_time", "start"), ("absolute_end_date_time", "end")):
            value = getattr(item, field)
            if field in item.explicit_fields and not valid_iso(datetime.fromisoformat, value):
                issues.append(FTDValidationIssue("warning", "invalid-time-range",
                    f"Time range {item.name} has an invalid explicit absolute {label} date/time",
                    item.source_plane, item.name))
        if "recurrence_entries" in item.explicit_fields:
            source_entries = item.raw_extra.get("recurrenceList")
            typed_count = len(item.recurrence_entries or ())
            if not isinstance(source_entries, list) or typed_count != len(source_entries):
                issues.append(FTDValidationIssue("warning", "invalid-time-range",
                    f"Time range {item.name} has a malformed recurrence list entry",
                    item.source_plane, item.name))
        for index, entry in enumerate(item.recurrence_entries or (), 1):
            prefix = f"Time range {item.name} recurrence {index}"
            if entry.recurrence_type == "DAILY_INTERVAL":
                required = ("days", "daily_start_time", "daily_end_time")
                time_fields = ("daily_start_time", "daily_end_time")
                day_fields = ("days",)
            elif entry.recurrence_type == "RANGE":
                required = ("range_start_day", "range_start_time", "range_end_day", "range_end_time")
                time_fields = ("range_start_time", "range_end_time")
                day_fields = ("range_start_day", "range_end_day")
            else:
                issues.append(FTDValidationIssue("warning", "invalid-time-range",
                    f"{prefix} has a missing or unsupported recurrence type",
                    item.source_plane, item.name))
                continue
            for field in required:
                if field not in entry.explicit_fields:
                    issues.append(FTDValidationIssue("warning", "invalid-time-range",
                        f"{prefix} is missing required {field.replace('_', ' ')}",
                        item.source_plane, item.name))
            for field in time_fields:
                value = getattr(entry, field)
                if field in entry.explicit_fields and not valid_iso(time.fromisoformat, value):
                    issues.append(FTDValidationIssue("warning", "invalid-time-range",
                        f"{prefix} has an invalid {field.replace('_', ' ')}",
                        item.source_plane, item.name))
            for field in day_fields:
                value = getattr(entry, field)
                days = value if isinstance(value, list) else [value]
                if field in entry.explicit_fields and any(not isinstance(day, str) or day not in weekdays for day in days):
                    issues.append(FTDValidationIssue("warning", "invalid-time-range",
                        f"{prefix} has an invalid day selection in {field.replace('_', ' ')}",
                        item.source_plane, item.name))
    return FTDValidationResult(tuple(issues))


__all__ = ["FTDValidationIssue", "FTDValidationResult", "validate_ftd_config"]
