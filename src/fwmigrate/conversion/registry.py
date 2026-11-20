"""Registry for implemented directional pair-specific migration planners."""

from collections.abc import Callable

from .contracts import PairMigrationPlanner


class MigrationPlannerRegistry:
    """Register and look up directional migration planners."""

    def __init__(self) -> None:
        self._planners: dict[tuple[str, str], PairMigrationPlanner] = {}
        self._loaders: dict[tuple[str, str], Callable[[], PairMigrationPlanner]] = {}

    def register(
        self,
        planner: PairMigrationPlanner,
        *,
        loader: Callable[[], PairMigrationPlanner] | None = None,
    ) -> PairMigrationPlanner:
        key = (planner.source_vendor.casefold(), planner.target_vendor.casefold())
        if key in self._planners:
            raise ValueError(f"Planner '{key[0]}_to_{key[1]}' is already registered")
        self._planners[key] = planner
        if loader is not None:
            self._loaders[key] = loader
        return planner

    def has(self, source_vendor: str, target_vendor: str) -> bool:
        key = (source_vendor.strip().casefold(), target_vendor.strip().casefold())
        return key in self._planners

    def get(self, source_vendor: str, target_vendor: str) -> PairMigrationPlanner:
        key = (source_vendor.strip().casefold(), target_vendor.strip().casefold())
        try:
            planner = self._planners[key]
        except KeyError as exc:
            raise KeyError(
                f"Planner '{key[0]}_to_{key[1]}' is not implemented"
            ) from exc
        loader = self._loaders.get(key)
        return loader() if loader is not None else planner


migration_planners = MigrationPlannerRegistry()
