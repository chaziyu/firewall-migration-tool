"""Structural contracts for future directional migration planners.

These protocols deliberately do not define a shared firewall model or any
vendor mapping. Concrete pairs own those decisions when planning resumes.
"""

from typing import Any, Protocol


class VendorSourceConfig(Protocol):
    """Opaque source-native vendor configuration."""


class VendorDerivedViews(Protocol):
    """Opaque source-native derived views used by a migration planner."""


class PairMigrationPlanner(Protocol):
    """Plans supported migration work for one directional vendor pair."""

    source_vendor: str
    target_vendor: str

    def plan(
        self,
        source: VendorSourceConfig,
        derived: VendorDerivedViews,
        **options: Any,
    ) -> Any:
        """Return a pair-specific migration plan."""
        ...


class MigrationPlanValidator(Protocol):
    """Validates a pair-specific migration plan."""

    def validate(self, plan: Any) -> Any:
        ...


class MigrationPlanRenderer(Protocol):
    """Renders a validated pair-specific migration plan."""

    def render(self, plan: Any, **options: Any) -> Any:
        ...
