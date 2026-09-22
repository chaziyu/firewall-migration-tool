"""Small vendor-native source-reporting contract.

The values crossing this boundary intentionally remain opaque to shared code.
"""

from typing import Any, Protocol, Sequence


class SourceReporter(Protocol):
    """Vendor implementation for source analysis and report generation."""

    @property
    def vendor_id(self) -> str:
        """Stable vendor identifier used by source-report dispatch."""
        ...

    @property
    def supported_extensions(self) -> Sequence[str]:
        """File extensions accepted by this reporter."""
        ...

    def analyze_source(self, source: Any, **options: Any) -> Any:
        """Return a vendor-specific analysis result."""
        ...

    def build_preview(self, analysis: Any, **options: Any) -> Any:
        """Return a vendor-specific preview result."""
        ...

    def export_excel(self, analysis: Any, output: Any, **options: Any) -> Any:
        """Write a vendor-specific Excel report to the supplied output."""
        ...
