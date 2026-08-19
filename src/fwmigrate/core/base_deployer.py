from abc import ABC, abstractmethod
from typing import Generator, Dict, Any, List
from pathlib import Path
from fwmigrate.core.base_generator import MigrationArtifact

class BaseDeployer(ABC):
    """Abstract base class for live deployment execution engines."""

    @property
    @abstractmethod
    def deployer_id(self) -> str:
        """Unique deployer identifier (e.g. 'terraform_panos', 'rest_push')."""
        ...

    @property
    @abstractmethod
    def display_name(self) -> str:
        """Human-readable display name."""
        ...

    @abstractmethod
    def prepare(self, artifacts: List[MigrationArtifact], target_params: Dict[str, Any]) -> Path:
        """Prepare execution sandbox environment."""
        ...

    @abstractmethod
    def plan(self) -> tuple[bool, str, Dict[str, Any]]:
        """Perform dry-run preview (e.g. terraform plan)."""
        ...

    @abstractmethod
    def apply_stream(self) -> Generator[Dict[str, Any], None, None]:
        """Stream live execution events (Server-Sent Events payload)."""
        ...

    @abstractmethod
    def destroy_stream(self) -> Generator[Dict[str, Any], None, None]:
        """Stream rollback execution events."""
        ...
