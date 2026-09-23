"""Check Point validation finding and result models."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CheckPointValidationIssue:
    code: str
    severity: str
    category: str
    message: str
    domain: str | None = None
    domain_uid: str | None = None
    package: str | None = None
    package_uid: str | None = None
    layer: str | None = None
    layer_uid: str | None = None
    gateway: str | None = None
    object_type: str | None = None
    object_uid: str | None = None
    object_name: str | None = None
    field: str | None = None
    command: str | None = None
    reference: str | None = None
    expected_kinds: tuple[str, ...] = ()
    scope: str | None = None


@dataclass(frozen=True)
class CheckPointValidationResult:
    issues: tuple[CheckPointValidationIssue, ...] = ()

    @property
    def errors(self) -> tuple[CheckPointValidationIssue, ...]:
        return tuple(item for item in self.issues if item.severity == "error")

    @property
    def warnings(self) -> tuple[CheckPointValidationIssue, ...]:
        return tuple(item for item in self.issues if item.severity == "warning")


__all__ = ["CheckPointValidationIssue", "CheckPointValidationResult"]
