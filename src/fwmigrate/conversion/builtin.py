"""Registration of built-in pair-specific migration planners."""

from fwmigrate.conversion.fortigate_to_palo_alto import FortiGateToPaloAltoPlanner

from .registry import migration_planners


_BUILTIN_PLANNERS = (FortiGateToPaloAltoPlanner(),)


def register_builtin_migration_planners() -> None:
    for planner in _BUILTIN_PLANNERS:
        try:
            migration_planners.get(planner.source_vendor, planner.target_vendor)
        except KeyError:
            migration_planners.register(planner)


__all__ = ["register_builtin_migration_planners"]
