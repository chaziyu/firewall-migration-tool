"""Read-only lookup helpers for Check Point validation findings."""

from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from .models import CheckPointValidationIssue


class CheckPointValidationIndex:
    def __init__(self, issues: Iterable[CheckPointValidationIssue] = ()) -> None:
        self.issues = tuple(issues)
        self._objects = defaultdict(list)
        self._uids = defaultdict(list)
        self._references = defaultdict(list)
        self._categories = defaultdict(list)
        for issue in self.issues:
            if issue.object_type and issue.object_name:
                self._objects[(issue.object_type, issue.object_name)].append(issue)
            if issue.object_uid:
                self._uids[issue.object_uid].append(issue)
            if issue.reference:
                self._references[issue.reference].append(issue)
            self._categories[issue.category].append(issue)

    def issues_for_object(self, object_type: str, object_name: str) -> tuple[CheckPointValidationIssue, ...]:
        return tuple(self._objects.get((object_type, object_name), ()))

    def issues_for_uid(self, uid: str) -> tuple[CheckPointValidationIssue, ...]:
        return tuple(self._uids.get(uid, ()))

    def issues_for_reference(self, reference: str) -> tuple[CheckPointValidationIssue, ...]:
        return tuple(self._references.get(reference, ()))

    def issues_for_category(self, category: str) -> tuple[CheckPointValidationIssue, ...]:
        return tuple(self._categories.get(category, ()))


__all__ = ["CheckPointValidationIndex"]
