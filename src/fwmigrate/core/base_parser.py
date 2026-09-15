from abc import ABC, abstractmethod
from typing import Dict, List, Optional
from fwmigrate.ir import IRConfig
from fwmigrate.extraction.models import ExtractionResult

class BaseSourceParser(ABC):
    """Abstract base class for offline configuration file parsers."""

    @property
    @abstractmethod
    def vendor_id(self) -> str:
        """Unique vendor identifier (e.g. 'fortigate', 'cisco_asa')."""
        ...

    @property
    @abstractmethod
    def display_name(self) -> str:
        """Human-readable display name (e.g. 'Fortinet FortiGate')."""
        ...

    @property
    @abstractmethod
    def supported_extensions(self) -> List[str]:
        """Supported file extensions (e.g. ['.conf', '.cfg', '.txt'])."""
        ...

    def parse(self, content: str, zone_mapping: Optional[Dict[str, str]] = None) -> IRConfig:
        """Compatibility projection of the authoritative extraction result."""
        return self.extract(content, zone_mapping=zone_mapping).canonical_ir

    @abstractmethod
    def extract(
        self,
        content: str,
        zone_mapping: Optional[Dict[str, str]] = None,
    ) -> ExtractionResult:
        """Extract configuration text into a fully accounted result."""
        ...
