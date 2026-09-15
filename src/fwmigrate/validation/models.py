from dataclasses import dataclass, field
from typing import List

from fwmigrate.jobs.models import MigrationIssue


@dataclass
class ValidationResult:
    issues: List[MigrationIssue] = field(default_factory=list)

    @property
    def blocking_issues(self) -> List[MigrationIssue]:
        return [issue for issue in self.issues if issue.blocking]

    @property
    def blocking_reasons(self) -> List[str]:
        return [issue.message for issue in self.blocking_issues]
