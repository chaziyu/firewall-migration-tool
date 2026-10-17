"""Metadata registry for implemented directional migration workflows."""

from dataclasses import dataclass, field
from typing import Callable


@dataclass(frozen=True, slots=True)
class MigrationWorkflowRegistration:
    pair_id: str
    source_vendor: str
    target_vendor: str
    display_name: str
    api_prefix: str
    supported_formats: tuple[str, ...]
    export_available: bool
    destination_aware_available: bool
    deployment_available: bool
    cli_application: Callable[..., object] | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        source = self.source_vendor.strip().casefold()
        target = self.target_vendor.strip().casefold()
        if not source or not target:
            raise ValueError("Migration workflow vendor identifiers are required")
        if self.pair_id != f"{source}_to_{target}":
            raise ValueError("Migration workflow pair_id must match its directional vendor identifiers")
        object.__setattr__(self, "source_vendor", source)
        object.__setattr__(self, "target_vendor", target)
        object.__setattr__(self, "supported_formats", tuple(value.casefold() for value in self.supported_formats))

    def public_metadata(self) -> dict:
        return {
            "pair_id": self.pair_id,
            "source_vendor": self.source_vendor,
            "target_vendor": self.target_vendor,
            "display_name": self.display_name,
            "api_prefix": self.api_prefix,
            "supported_formats": list(self.supported_formats),
            "export_available": self.export_available,
            "destination_aware_available": self.destination_aware_available,
            "deployment_available": self.deployment_available,
        }


class MigrationWorkflowRegistry:
    """Look up public workflow metadata and optional pair-owned CLI handlers."""

    def __init__(self) -> None:
        self._workflows: dict[tuple[str, str], MigrationWorkflowRegistration] = {}

    def register(self, workflow: MigrationWorkflowRegistration) -> MigrationWorkflowRegistration:
        key = (workflow.source_vendor.casefold(), workflow.target_vendor.casefold())
        if key in self._workflows:
            raise ValueError(f"Workflow '{key[0]}_to_{key[1]}' is already registered")
        self._workflows[key] = workflow
        return workflow

    def get(self, source_vendor: str, target_vendor: str) -> MigrationWorkflowRegistration:
        key = (source_vendor.strip().casefold(), target_vendor.strip().casefold())
        try:
            return self._workflows[key]
        except KeyError as exc:
            raise KeyError(f"Workflow '{key[0]}_to_{key[1]}' is not implemented") from exc

    def list(self) -> tuple[MigrationWorkflowRegistration, ...]:
        return tuple(self._workflows[key] for key in sorted(self._workflows))


migration_workflows = MigrationWorkflowRegistry()
