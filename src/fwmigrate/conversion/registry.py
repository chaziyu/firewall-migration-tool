"""Lookup structure reserved for future pair-specific migration planners."""

from .contracts import PairMigrationPlanner


class MigrationPlannerRegistry:
    """Register and look up directional migration planners when pairs exist."""

    def __init__(self) -> None:
        self._planners: dict[tuple[str, str], PairMigrationPlanner] = {}

    def register(self, planner: PairMigrationPlanner) -> PairMigrationPlanner:
        key = (planner.source_vendor.casefold(), planner.target_vendor.casefold())
        if key in self._planners:
            raise ValueError(f"Planner '{key[0]}_to_{key[1]}' is already registered")
        self._planners[key] = planner
        return planner

    def get(self, source_vendor: str, target_vendor: str) -> PairMigrationPlanner:
        key = (source_vendor.strip().casefold(), target_vendor.strip().casefold())
        try:
            return self._planners[key]
        except KeyError as exc:
            raise KeyError(
                f"Planner '{key[0]}_to_{key[1]}' is not implemented"
            ) from exc


migration_planners = MigrationPlannerRegistry()
