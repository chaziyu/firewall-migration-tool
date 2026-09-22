"""Disabled legacy source-to-target conversion entry point."""

from typing import Any


MIGRATION_UNAVAILABLE_MESSAGE = (
    "Configuration conversion is temporarily unavailable while the pair-specific "
    "conversion architecture is being implemented."
)


class MigrationUnavailableError(RuntimeError):
    """Raised while legacy IR-based conversion is disabled."""

    def __init__(self) -> None:
        super().__init__(MIGRATION_UNAVAILABLE_MESSAGE)


class MigrationPipeline:
    """Compatibility shell; no legacy IR conversion is available."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        del args, kwargs

    def analyze(self, request: Any) -> None:
        del request
        raise MigrationUnavailableError()

    def run(self, request: Any) -> None:
        del request
        raise MigrationUnavailableError()


__all__ = [
    "MIGRATION_UNAVAILABLE_MESSAGE",
    "MigrationPipeline",
    "MigrationUnavailableError",
]
