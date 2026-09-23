"""Validation of pair-specific FortiGate to Palo Alto plans."""

from dataclasses import dataclass

from .models import MigrationIssue, MigrationSourceRef, PANMigrationPlan, PANMigrationStatus


@dataclass(frozen=True, slots=True)
class MigrationValidationResult:
    issues: tuple[MigrationIssue, ...] = ()
    plan: PANMigrationPlan | None = None

    @property
    def counts(self):
        result = {status.value.lower(): 0 for status in PANMigrationStatus}
        for item in _items(self.plan) if self.plan is not None else ():
            result[item.status.value.lower()] += 1
        return result


def validate_plan(plan: PANMigrationPlan) -> MigrationValidationResult:
    issues = list(plan.issues)
    seen = set()
    for item in _items(plan):
        key = (item.source_object_type, item.source_name, item.source_vdom)
        if item.source_name and key in seen:
            issues.append(MigrationIssue(
                "duplicate_source_name", f"duplicate planned source name {item.source_name!r}",
                source=MigrationSourceRef(item.source_vdom, item.source_kind, item.source_name, item.source_policy_id),
            ))
        seen.add(key)
        issues.extend(MigrationIssue(
            "planned_item_warning", warning, PANMigrationStatus.MANUAL_REVIEW,
            MigrationSourceRef(item.source_vdom, item.source_kind, item.source_name, item.source_policy_id),
        ) for warning in item.warnings if warning)
    return MigrationValidationResult(tuple(issues), plan)


def _items(plan):
    for name in ("addresses", "address_groups", "services", "service_groups", "schedules", "zones", "static_routes", "security_rules", "nat_rules"):
        yield from getattr(plan, name)
