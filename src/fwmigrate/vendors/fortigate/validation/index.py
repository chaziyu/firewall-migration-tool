from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from .models import ValidationIssue, ValidationResult


class ValidationIssueIndex:
    """Read-only lookup index over validation issues."""

    def __init__(self, validation: ValidationResult) -> None:
        self._issues_by_object: dict[tuple[str, str], tuple[tuple[int, ValidationIssue], ...]] = {}
        self._issues_by_domain_object: dict[
            tuple[str, str, str], tuple[tuple[int, ValidationIssue], ...]
        ] = {}
        self._issues_by_vdom: dict[str, tuple[tuple[int, ValidationIssue], ...]] = {}

        by_object: defaultdict[tuple[str, str], list[tuple[int, ValidationIssue]]]
        by_domain_object: defaultdict[tuple[str, str, str], list[tuple[int, ValidationIssue]]]
        by_vdom: defaultdict[str, list[tuple[int, ValidationIssue]]]
        by_object = defaultdict(list)
        by_domain_object = defaultdict(list)
        by_vdom = defaultdict(list)

        for position, issue in enumerate(validation.issues):
            indexed = (position, issue)
            by_vdom[issue.vdom].append(indexed)
            if issue.object_name is None:
                continue

            name = str(issue.object_name)
            by_object[(issue.vdom, name)].append(indexed)
            by_domain_object[(issue.domain, issue.vdom, name)].append(indexed)

        self._issues_by_object = {
            key: tuple(items) for key, items in by_object.items()
        }
        self._issues_by_domain_object = {
            key: tuple(items) for key, items in by_domain_object.items()
        }
        self._issues_by_vdom = {
            key: tuple(items) for key, items in by_vdom.items()
        }

    def issues_for(
        self,
        vdom: str,
        names: Iterable[object],
        domains: Iterable[str] | None = None,
    ) -> list[ValidationIssue]:
        wanted_names = tuple(
            dict.fromkeys(
                str(name)
                for name in names
                if name not in (None, "")
            )
        )
        wanted_domains = set(domains or ())

        if not wanted_names:
            candidates = self._issues_by_vdom.get(vdom, ())
        elif wanted_domains:
            candidates = tuple(
                indexed
                for name in wanted_names
                for domain in wanted_domains
                for indexed in self._issues_by_domain_object.get(
                    (domain, vdom, name),
                    (),
                )
            )
        else:
            candidates = tuple(
                indexed
                for name in wanted_names
                for indexed in self._issues_by_object.get((vdom, name), ())
            )

        return [
            issue
            for _, issue in sorted(candidates, key=lambda item: item[0])
            if not wanted_domains or issue.domain in wanted_domains
        ]
