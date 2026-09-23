"""Target-side validation for FortiGate to Palo Alto plans."""

from dataclasses import dataclass

from .models import MigrationIssue, MigrationSourceRef, PANMigrationPlan, PANMigrationStatus


@dataclass(frozen=True, slots=True)
class MigrationValidationResult:
    issues: tuple[MigrationIssue, ...] = ()
    plan: PANMigrationPlan | None = None
    renderable_item_keys: frozenset[tuple[str | None, str | None, str | None]] = frozenset()

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
    issues = list(plan.issues)
    indexes = {name: {item.target_name or item.source_name: item for item in getattr(plan, name)}
               for name in ("addresses", "address_groups", "services", "service_groups", "schedules", "zones")}
    all_names = {key for values in indexes.values() for key in values if key}
    errors = set()
    seen = set()
    for item in _items(plan):
        key = _key(item)
        for warning in item.warnings:
            issues.append(MigrationIssue("planned_item_warning", warning, PANMigrationStatus.MANUAL_REVIEW, _ref(item)))
        if item.source_name and key in seen:
            issues.append(_issue("duplicate_target_name", "duplicate target name", item)); errors.add(key)
        seen.add(key)
        if not item.target_vsys:
            issues.append(_issue("missing_target_vsys", "missing target VSYS mapping", item)); errors.add(key)
    for group in (*plan.address_groups, *plan.service_groups):
        for member in group.members:
            if member not in all_names and member != "any":
                issues.append(_issue("missing_group_member", f"group member {member!r} is not renderable", group)); errors.add(_key(group))
    for rule in plan.security_rules:
        for field, values, family in (("from_zones", rule.from_zones, "zones"), ("to_zones", rule.to_zones, "zones"),
                                      ("sources", rule.sources, "addresses"), ("destinations", rule.destinations, "addresses"),
                                      ("services", rule.services, "services")):
            if not values:
                issues.append(_issue("missing_rule_field", f"security rule missing {field}", rule)); errors.add(_key(rule))
            for value in values:
                if value != "any" and value not in indexes[family]:
                    issues.append(_issue("missing_reference", f"security rule references unknown {value!r}", rule)); errors.add(_key(rule))
        if not rule.action:
            issues.append(_issue("missing_action", "security rule has no action", rule)); errors.add(_key(rule))
    for rule in plan.nat_rules:
        if rule.source_translation_type and not (rule.source_interface_address or rule.translated_addresses):
            issues.append(_issue("missing_snat_translation", "SNAT translation is missing", rule)); errors.add(_key(rule))
        if not rule.source_translation_type and not rule.destination_translated_address:
            issues.append(_issue("missing_dnat_translation", "DNAT translated address is missing", rule)); errors.add(_key(rule))
    renderable = frozenset(_key(item) for item in _items(plan)
                            if item.status is PANMigrationStatus.SUPPORTED and _key(item) not in errors)
    return MigrationValidationResult(tuple(issues), plan, renderable)


def _key(item):
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
