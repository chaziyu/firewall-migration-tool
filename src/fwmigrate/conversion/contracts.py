"""Structural contracts for future directional converters.

These protocols deliberately do not define a shared firewall model or any
vendor mapping. Concrete pairs own those decisions when conversion resumes.
"""

from typing import Any, Protocol


class VendorSourceConfig(Protocol):
    """Opaque source-native vendor configuration."""


class VendorDerivedViews(Protocol):
    """Opaque source-native derived views used by a converter."""


class TargetVendorConfig(Protocol):
    """Opaque target-native vendor configuration."""


class TargetValidator(Protocol):
    """Validates a target-native configuration."""

    def validate(self, config: Any) -> Any:
        ...


class TargetRenderer(Protocol):
    """Renders a validated target-native configuration."""

    def render(self, config: Any, **options: Any) -> Any:
        ...


class PairConverter(Protocol):
    """Future source/target-specific conversion boundary."""

    source_vendor: str
    target_vendor: str

    def convert(
        self,
        source: VendorSourceConfig,
        derived: VendorDerivedViews,
    ) -> TargetVendorConfig:
        """Return a target-native configuration for this vendor pair."""
        ...
