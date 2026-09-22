"""Dispatch for vendor-native source reporters."""

from fwmigrate.source_reporting.contracts import SourceReporter


class SourceReportRegistrationError(ValueError):
    """Raised when a source reporter registration is invalid or ambiguous."""


def _vendor_id(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Source reporter vendor identifiers must be non-empty strings")
    return value.strip().casefold()


def _extension(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Source reporter extensions must be non-empty strings")
    normalized = value.strip().casefold()
    return normalized if normalized.startswith(".") else f".{normalized}"


class SourceReportRegistry:
    """Registry and vendor/extension dispatcher for source reporters."""

    def __init__(self) -> None:
        self._reporters: dict[str, SourceReporter] = {}

    def register(self, reporter: SourceReporter) -> SourceReporter:
        vendor_id = _vendor_id(reporter.vendor_id)
        extensions = tuple(_extension(value) for value in reporter.supported_extensions)
        if not extensions:
            raise SourceReportRegistrationError(
                f"Source reporter '{vendor_id}' must declare supported extensions"
            )
        existing = self._reporters.get(vendor_id)
        if existing is not None and existing is not reporter:
            raise SourceReportRegistrationError(
                f"Source reporter '{vendor_id}' is already registered"
            )
        self._reporters[vendor_id] = reporter
        return reporter

    def get(self, vendor_id: str) -> SourceReporter:
        normalized = _vendor_id(vendor_id)
        try:
            return self._reporters[normalized]
        except KeyError as exc:
            raise KeyError(
                f"Source reporter '{vendor_id}' is not registered. "
                f"Available: {list(self._reporters)}"
            ) from exc

    def for_extension(self, extension: str) -> tuple[SourceReporter, ...]:
        normalized = _extension(extension)
        return tuple(
            reporter
            for reporter in self._reporters.values()
            if normalized in {_extension(value) for value in reporter.supported_extensions}
        )

    def list(self) -> list[SourceReporter]:
        return list(self._reporters.values())


source_reporters = SourceReportRegistry()
