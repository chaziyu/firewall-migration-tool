from fwmigrate.vendors.fortigate.validation.index import ValidationIssueIndex
from fwmigrate.vendors.fortigate.validation.models import (
    ValidationIssue,
    ValidationResult,
    ValidationSeverity,
)


def issue(domain: str, vdom: str, name: str, message: str) -> ValidationIssue:
    return ValidationIssue(
        severity=ValidationSeverity.WARNING,
        domain=domain,
        vdom=vdom,
        object_name=name,
        message=message,
    )


def test_lookup_is_scoped_by_vdom_and_domain():
    validation = ValidationResult(
        issues=[
            issue("address", "root", "same", "root address"),
            issue("address", "tenant", "same", "tenant address"),
            issue("policy", "root", "same", "root policy"),
        ]
    )
    index = ValidationIssueIndex(validation)

    assert [item.message for item in index.issues_for("root", ["same"])] == [
        "root address",
        "root policy",
    ]
    assert [
        item.message
        for item in index.issues_for("root", ["same"], domains=["policy"])
    ] == ["root policy"]
    assert [item.message for item in index.issues_for("tenant", ["same"])] == [
        "tenant address",
    ]


def test_lookup_preserves_issue_order_for_multiple_names_and_duplicates():
    validation = ValidationResult(
        issues=[
            issue("policy", "root", "second", "second one"),
            issue("address", "root", "first", "first one"),
            issue("policy", "root", "first", "first two"),
            issue("policy", "root", "second", "second two"),
        ]
    )
    index = ValidationIssueIndex(validation)

    assert [item.message for item in index.issues_for("root", ["first", "second"])] == [
        "second one",
        "first one",
        "first two",
        "second two",
    ]


def test_lookup_without_names_returns_all_vdom_issues():
    validation = ValidationResult(
        issues=[
            issue("address", "root", "one", "one"),
            issue("address", "tenant", "two", "two"),
            issue("policy", "root", "three", "three"),
        ]
    )
    index = ValidationIssueIndex(validation)

    assert [item.message for item in index.issues_for("root", [])] == [
        "one",
        "three",
    ]


def test_lookup_returns_empty_for_unknown_object_or_domain():
    index = ValidationIssueIndex(
        ValidationResult(
            issues=[issue("address", "root", "known", "known")]
        )
    )

    assert index.issues_for("root", ["missing"]) == []
    assert index.issues_for("root", ["known"], domains=["policy"]) == []
