"""Read-only checks against the selected FortiOS 7.4.6 CLI reference."""
from ..model.source import FGConfig
from .models import ValidationIssue, ValidationSeverity


def validate_cli_constraints(config: FGConfig) -> list[ValidationIssue]:
    issues = []
    # Bounds are version-specific; no defaults are supplied for absent fields.
    for objects, domain, constraints in (
        (config.ip_pools, "ip_pool", (("startport", 5117, 65533), ("endport", 5117, 65533))),
        (config.one_time_schedules, "schedule_onetime", (("expiration_days", 0, 100),)),
    ):
        for item in objects:
            for field, minimum, maximum in constraints:
                value = getattr(item, field)
                if field in item.explicit_fields and value is not None and not minimum <= value <= maximum:
                    issues.append(ValidationIssue(
                        severity=ValidationSeverity.WARNING, domain=domain,
                        vdom=item.vdom, object_name=item.name, field=field,
                        message=f"FortiOS 7.4.6: {field.replace('_', '-')} must be {minimum}–{maximum}; explicit value is {value}.",
                    ))

    allowed_days = {"sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "none"}
    for item in config.recurring_schedules:
        invalid = [day for day in item.days if day not in allowed_days]
        if "days" in item.explicit_fields and invalid:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING, domain="schedule_recurring",
                vdom=item.vdom, object_name=item.name, field="day",
                message=f"FortiOS 7.4.6: invalid recurring schedule day values: {', '.join(invalid)}.",
            ))
    return issues
