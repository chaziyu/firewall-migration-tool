from __future__ import annotations

from dataclasses import dataclass

from ..source_model import PANScope


@dataclass(frozen=True, slots=True)
class PANOSValidationIssue:
    severity: str
    domain: str
    message: str
    source_path: str | None = None
    source_name: str | None = None
    field: str | None = None
    source_scope: PANScope | None = None
    scope_identity: str | None = None
    object_type: str | None = None


@dataclass(frozen=True, slots=True)
class PANOSValidationResult:
    issues: tuple[PANOSValidationIssue, ...] = ()

    @property
    def errors(self) -> tuple[PANOSValidationIssue, ...]:
        return tuple(issue for issue in self.issues if issue.severity == "error")

    @property
    def warnings(self) -> tuple[PANOSValidationIssue, ...]:
        return tuple(issue for issue in self.issues if issue.severity == "warning")

    @property
    def infos(self) -> tuple[PANOSValidationIssue, ...]:
        return tuple(issue for issue in self.issues if issue.severity == "info")
