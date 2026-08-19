from abc import ABC, abstractmethod
from typing import List, Literal, Optional
from pydantic import BaseModel
from fwmigrate.ir.core import IRConfig

class MigrationArtifact(BaseModel):
    filename: str
    content: str
    format: Literal["xml", "set", "terraform", "json", "txt", "csv", "xlsx", "cli"]

class BaseGenerator(ABC):
    """Base interface for generating artifacts."""

    @abstractmethod
    def generate(self, ir: IRConfig) -> List[MigrationArtifact]:
        """Generate migration artifacts from the vendor-neutral IR."""
        ...

class BaseTargetGenerator(BaseGenerator):
    """Abstract base class for target vendor plugins."""

    @property
    @abstractmethod
    def vendor_id(self) -> str:
        """Unique target vendor identifier (e.g. 'palo_alto', 'fortigate')."""
        ...

    @property
    @abstractmethod
    def display_name(self) -> str:
        """Human-readable display name (e.g. 'Palo Alto Networks (PAN-OS)')."""
        ...

    @property
    @abstractmethod
    def supported_formats(self) -> List[str]:
        """Supported output formats (e.g. ['xml', 'terraform', 'cli'])."""
        ...

    @abstractmethod
    def generate(self, ir: IRConfig, format: Optional[str] = None) -> List[MigrationArtifact]:
        """Generate migration artifacts from the vendor-neutral IR."""
        ...
