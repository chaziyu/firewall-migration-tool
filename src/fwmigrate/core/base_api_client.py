from abc import ABC, abstractmethod
from typing import List, Dict, Any
from fwmigrate.ir.core import IRConfig

class BaseAPIClient(ABC):
    """Abstract base class for live device/management API clients."""

    @classmethod
    @abstractmethod
    def vendor_id_class(cls) -> str:
        """Unique vendor identifier for this API client class."""
        ...

    @property
    @abstractmethod
    def vendor_id(self) -> str:
        """Unique vendor identifier."""
        ...

    @property
    @abstractmethod
    def display_name(self) -> str:
        """Human-readable display name."""
        ...

    @classmethod
    @abstractmethod
    def get_field_definitions(cls) -> List[Dict[str, Any]]:
        """Return descriptors of the form fields required for live API connection in UI/CLI."""
        ...

    @abstractmethod
    def validate_connection(self) -> bool:
        """Test authentication and connectivity to the live target."""
        ...

    @abstractmethod
    def extract_config(self) -> IRConfig:
        """Extract live configuration and return a canonical vendor-neutral IRConfig."""
        ...
