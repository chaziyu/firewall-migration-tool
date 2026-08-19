from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from fg2pan.ir.core import IRConfig

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

    @abstractmethod
    def parse(self, content: str, zone_mapping: Optional[Dict[str, str]] = None) -> IRConfig:
        """Parse raw configuration text into a canonical vendor-neutral IRConfig."""
        ...
