"""Dependency and field validation for FortiGate to PAN-OS plans."""

from dataclasses import dataclass

from .models import MigrationIssue, MigrationSourceRef, PANMigrationPlan, PANMigrationStatus


ItemKey = tuple[str | None, str | None, str | None]


@dataclass(frozen=True, slots=True)
class MigrationValidationResult:
    issues: tuple[MigrationIssue, ...] = ()
    plan: PANMigrationPlan | None = None
    renderable_item_keys: frozenset[ItemKey] = frozenset()

    @property
    def counts(self):
        result = {status.value.lower(): 0 for status in PANMigrationStatus}
        for item in _items(self.plan):
            result[item.status.value.lower()] += 1
        return result

    @property
    def has_errors(self):
        return any(issue.status is PANMigrationStatus.UNSUPPORTED for issue in self.issues)


def validate_plan(plan: PANMigrationPlan) -> MigrationValidationResult:
    """Return a non-mutating, transitive renderability assessment for a plan."""
    issues = list(plan.issues)
    families = {
        "addresses": _index(plan.addresses),
        "address_groups": _index(plan.address_groups),
        "services": _index(plan.services),
        "service_groups": _index(plan.service_groups),
        "schedules": _index(plan.schedules),
        "zones": _index(plan.zones),
    }
    errors: set[ItemKey] = set()
    seen: set[ItemKey] = set()
    issue_keys: set[tuple[ItemKey, str, str]] = set()

    def add(code: str, message: str, item) -> None:
        marker = (_key(item), code, message)
        if marker not in issue_keys:
            issues.append(_issue(code, message, item))
            issue_keys.add(marker)
        errors.add(_key(item))

    for item in _items(plan):
        key = _key(item)
        for warning in item.warnings:
            issues.append(MigrationIssue("planned_item_warning", warning, PANMigrationStatus.MANUAL_REVIEW, _ref(item)))
        if item.source_name and key in seen:
            add("duplicate_target_name", "duplicate target name", item)
        seen.add(key)

        if item.source_object_type == "address":
            if not getattr(item, "address_type", None) or not getattr(item, "value", None):
                add("missing_address_value", "address has no supported explicit value", item)
        elif item.source_object_type == "service":
            if not getattr(item, "protocol", None) or not getattr(item, "destination_port", None):
                add("missing_service_value", "service has no supported protocol or destination port", item)
        elif item.source_object_type == "schedule":
            schedule_type = getattr(item, "schedule_type", None)
            if (schedule_type == "recurring" and not getattr(item, "weekly", ())) or (
                schedule_type == "one-time" and not getattr(item, "non_recurring", ())
            ) or schedule_type not in {"recurring", "one-time"}:
                add("missing_schedule_value", "schedule has no supported explicit entries", item)
        elif item.source_object_type == "static_route":
            if not getattr(item, "virtual_router", None):
                add("missing_virtual_router", "missing target virtual-router mapping", item)
            if not getattr(item, "destination", None):
                add("missing_route_destination", "route has no explicit destination", item)
            if getattr(item, "nexthop_type", None) not in {None, "ip-address", "discard"} or (not item.nexthop and item.nexthop_type != "discard"):
                add("unsupported_route_nexthop", "route has no supported nexthop", item)
            if getattr(item, "interface", None) is None and any("interface mapping" in warning for warning in item.warnings):
                add("missing_route_interface", "missing target interface mapping", item)
        elif item.source_object_type == "nat_rule":
            if not item.target_vsys:
                add("missing_target_vsys", "missing target VSYS mapping", item)
            if not item.from_zones or not item.to_zones:
                add("missing_nat_zone", "NAT rule is missing a required from or to zone", item)
            if item.source_kind == "source_nat":
                if not item.source_addresses or not item.destination_addresses:
                    add("missing_nat_address", "NAT rule is missing source or destination match", item)
                if not item.service:
                    add("missing_nat_service", "NAT rule has no explicit service match", item)
                if not item.to_interface:
                    add("missing_nat_interface", "NAT rule has no mapped target interface", item)
                if not item.source_translation_type or (
                    not item.source_interface_address and not item.translated_addresses
                ):
                    add("missing_snat_translation", "SNAT translation is missing", item)
        elif item.source_object_type != "static_route" and not item.target_vsys:
            add("missing_target_vsys", "missing target VSYS mapping", item)

    # A base item is eligible only when its own status and required fields are valid.
    renderable = {
        _key(item) for item in _items(plan)
        if item.status is PANMigrationStatus.SUPPORTED and _key(item) not in errors
    }

    def find(families_to_search, name, vsys):
        for family in families_to_search:
            item = families[family].get((vsys, name))
            if item is not None:
                return item
        return None

    def require_reference(owner, name, accepted_families, *, code="missing_reference"):
        if name == "any":
            return
        dependency = find(accepted_families, name, owner.target_vsys)
        if dependency is None:
            add(code, f"reference {name!r} is not in the target VSYS", owner)
        elif _key(dependency) not in renderable:
            add("dependency_not_renderable", f"dependency {name!r} is not renderable", owner)

    # Resolve each dependency in the owner's target VSYS. Repeating this pass
    # propagates failures through arbitrarily nested groups and rules.
    changed = True
    while changed:
        changed = False
        for group, members, member_families in (
            *((group, group.members, ("addresses", "address_groups")) for group in plan.address_groups),
            *((group, group.members, ("services", "service_groups")) for group in plan.service_groups),
        ):
            if _key(group) not in renderable:
                continue
            before = _key(group) in renderable
            if not members:
                add("missing_group_member", "group has no members", group)
            for member in members:
                dependency = find(member_families, member, group.target_vsys)
                if dependency is None:
                    add("missing_group_member", f"group member {member!r} is not planned in this target VSYS", group)
                elif _key(dependency) not in renderable:
                    add("dependency_not_renderable", f"group member {member!r} is not renderable", group)
            if before and _key(group) in errors:
                renderable.remove(_key(group))
                changed = True

        for rule in plan.security_rules:
            if _key(rule) not in renderable:
                continue
            before = _key(rule) in renderable
            for field, values, accepted in (
                ("from_zones", rule.from_zones, ("zones",)),
                ("to_zones", rule.to_zones, ("zones",)),
                ("sources", rule.sources, ("addresses", "address_groups")),
                ("destinations", rule.destinations, ("addresses", "address_groups")),
                ("services", rule.services, ("services", "service_groups")),
            ):
                if not values:
                    add("missing_rule_field", f"security rule missing {field}", rule)
                for value in values:
                    require_reference(rule, value, accepted)
            if rule.schedule:
                require_reference(rule, rule.schedule, ("schedules",), code="missing_schedule")
            if not rule.action:
                add("missing_action", "security rule has no action", rule)
            if before and _key(rule) in errors:
                renderable.remove(_key(rule))
                changed = True

        for rule in plan.nat_rules:
            if _key(rule) not in renderable:
                continue
            before = _key(rule) in renderable
            if rule.source_kind == "source_nat":
                for field, values in (("from_zones", rule.from_zones), ("to_zones", rule.to_zones)):
                    if not values:
                        add("missing_nat_zone", f"NAT rule missing {field}", rule)
                    for value in values:
                        require_reference(rule, value, ("zones",))
                if not rule.source_addresses or not rule.destination_addresses:
                    add("missing_nat_address", "NAT rule is missing source or destination match", rule)
                for value in (*rule.source_addresses, *rule.destination_addresses):
                    require_reference(rule, value, ("addresses", "address_groups"))
                if not rule.service:
                    add("missing_nat_service", "NAT rule has no explicit service match", rule)
                else:
                    require_reference(rule, rule.service, ("services", "service_groups"))
                if not rule.to_interface:
                    add("missing_nat_interface", "NAT rule has no mapped target interface", rule)
            if rule.source_kind != "source_nat" and rule.source_translation_type and not (rule.source_interface_address or rule.translated_addresses):
                add("missing_snat_translation", "SNAT translation is missing", rule)
            if rule.source_kind != "source_nat" and not rule.source_translation_type and not rule.destination_translated_address:
                add("missing_dnat_translation", "DNAT translated address is missing", rule)
            if before and _key(rule) in errors:
                renderable.remove(_key(rule))
                changed = True

    result = frozenset(renderable)
    return MigrationValidationResult(tuple(issues), plan, result)


def _index(items):
    return {(item.target_vsys, item.target_name or item.source_name): item for item in items
            if item.target_name or item.source_name}


def _key(item) -> ItemKey:
    return (item.source_object_type, item.target_vsys, item.target_name or item.source_name)


def _ref(item):
    return MigrationSourceRef(item.source_vdom, item.source_kind, item.source_name, item.source_policy_id)


def _issue(code, message, item):
    return MigrationIssue(code, message, PANMigrationStatus.UNSUPPORTED, _ref(item))


def _items(plan):
    if plan is None:
        return
    for name in ("addresses", "address_groups", "services", "service_groups", "schedules", "zones", "static_routes", "security_rules", "nat_rules"):
        yield from getattr(plan, name)
