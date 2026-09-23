"""Check Point validation finding and result models."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CheckPointValidationIssue:
    severity: str
    category: str
    message: str
    command: str | None = None
    reference: str | None = None


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
