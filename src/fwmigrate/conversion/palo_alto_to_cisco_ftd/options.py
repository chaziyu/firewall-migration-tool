"""Explicit Cisco FMC management and target choices."""

from dataclasses import dataclass


def _text(value: str | None, label: str) -> str | None:
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    if not isinstance(value, str) or any(ord(char) < 32 for char in value):
        raise ValueError(f"{label} must be a non-empty text value")
    return value.strip()


@dataclass(frozen=True, slots=True)
class FTDMigrationOptions:
    source_scope: str | None = None
    manager_target: str | None = None
    domain_id: str | None = None
    domain_name: str | None = None
    fmc_api_version: str | None = "7.7.0"
    policy_name: str | None = None
    target_device_id: str | None = None
    target_device_name: str | None = None
    target_mode: str = "new"

    def __post_init__(self) -> None:
        if self.target_mode not in {"new", "existing"}:
            raise ValueError("target_mode must be new or existing")
        for field in (
            "source_scope", "manager_target", "domain_id", "domain_name",
            "fmc_api_version", "policy_name", "target_device_id", "target_device_name",
        ):
            object.__setattr__(self, field, _text(getattr(self, field), field))

    def to_dict(self) -> dict[str, object]:
        return {
            "source_scope": self.source_scope,
            "manager_target": self.manager_target,
            "domain_id": self.domain_id,
            "domain_name": self.domain_name,
            "fmc_api_version": self.fmc_api_version,
            "policy_name": self.policy_name,
            "target_device_id": self.target_device_id,
            "target_device_name": self.target_device_name,
            "target_mode": self.target_mode,
        }
