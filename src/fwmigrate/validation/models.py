from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ValidationIssue:
    severity: str
    category: str
    source_object: str
    message: str
    blocking: bool
    target_object: Optional[str] = None
    recommended_action: Optional[str] = None


@dataclass
class ValidationResult:
    issues: List[ValidationIssue] = field(default_factory=list)

    @property
    def blocking_issues(self) -> List[ValidationIssue]:
        return [issue for issue in self.issues if issue.blocking]

    @property
    def blocking_reasons(self) -> List[str]:
        return [issue.message for issue in self.blocking_issues]
