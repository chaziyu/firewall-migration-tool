"""Read-only Check Point NAT migration views."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any

from ..model.common import CheckPointObjectReference, CheckPointSourceObject
from ..model.policy import CPAutoNATRule, CPNATRule
from ..model.source import CheckPointConfig
from ..relationships.references import CPReferenceIndex, CPReferenceKind, CPResolvedReference


@dataclass(frozen=True, slots=True)
class CPNATReference:
    reference: str
    uid: str | None = None
    name: str | None = None
    resolved_uid: str | None = None
    resolved_name: str | None = None
    status: str = "source_only"


@dataclass(frozen=True, slots=True)
class CPNATTransformIssue:
    message: str
    source_uid: str | None
    source_name: str | None
    domain: str | None
    source_field: str | None = None
    reference: str | None = None
    relationship_status: str | None = None


@dataclass(frozen=True, slots=True)
class CPNATMigrationView:
    source_kind: str
    source_uid: str | None
    source_name: str | None
    domain: str | None
    rule_order: int | None
    enabled: bool | None
    original_source: tuple[CPNATReference, ...] = ()
    original_destination: tuple[CPNATReference, ...] = ()
    original_service: tuple[CPNATReference, ...] = ()
    translated_source: tuple[CPNATReference, ...] | None = ()
    translated_destination: tuple[CPNATReference, ...] = ()
    translated_service: tuple[CPNATReference, ...] = ()
    translation_method: str | None = None
    owner_uid: str | None = None
    owner_name: str | None = None
    owner_kind: str | None = None
    install_on: tuple[CPNATReference, ...] = ()
    issues: tuple[CPNATTransformIssue, ...] = ()


@dataclass(frozen=True, slots=True)
class CPNATTransformResult:
    views: tuple[CPNATMigrationView, ...] = ()
    issues: tuple[CPNATTransformIssue, ...] = ()


def _reference(value: Any, owner: CheckPointSourceObject, field: str, index: CPReferenceIndex) -> CPNATReference:
    if isinstance(value, CheckPointObjectReference):
        key, uid, name = value.uid or value.name or "", value.uid, value.name
    elif isinstance(value, dict):
        uid, name = value.get("uid"), value.get("name")
        key = uid or name or ""
    else:
        key, uid, name = str(value or ""), None, str(value) if value else None
    expected = {
        "original_source": (CPReferenceKind.HOST, CPReferenceKind.NETWORK, CPReferenceKind.ADDRESS_RANGE, CPReferenceKind.ADDRESS, CPReferenceKind.GROUP, CPReferenceKind.GROUP_WITH_EXCLUSION),
        "original_destination": (CPReferenceKind.HOST, CPReferenceKind.NETWORK, CPReferenceKind.ADDRESS_RANGE, CPReferenceKind.ADDRESS, CPReferenceKind.GROUP, CPReferenceKind.GROUP_WITH_EXCLUSION),
        "translated_source": (CPReferenceKind.HOST, CPReferenceKind.NETWORK, CPReferenceKind.ADDRESS_RANGE, CPReferenceKind.ADDRESS, CPReferenceKind.GROUP, CPReferenceKind.GROUP_WITH_EXCLUSION),
        "translated_destination": (CPReferenceKind.HOST, CPReferenceKind.NETWORK, CPReferenceKind.ADDRESS_RANGE, CPReferenceKind.ADDRESS, CPReferenceKind.GROUP, CPReferenceKind.GROUP_WITH_EXCLUSION),
        "original_service": (CPReferenceKind.SERVICE, CPReferenceKind.SERVICE_GROUP),
        "translated_service": (CPReferenceKind.SERVICE, CPReferenceKind.SERVICE_GROUP),
        "install_on": (CPReferenceKind.GATEWAY, CPReferenceKind.CLUSTER),
    }.get(field, ())
    result = index.resolve(value, owner=owner, expected_kinds=expected, source_field=field)
    if isinstance(result, CPResolvedReference):
        target = result.target
        return CPNATReference(
            key, uid, name,
            target.uid if target else None,
            target.name if target else None,
            result.status,
        )
    return CPNATReference(key, uid, name, status=result.status)


def _references(values: Any, owner: CheckPointSourceObject, field: str, index: CPReferenceIndex) -> tuple[CPNATReference, ...]:
    return tuple(_reference(value, owner, field, index) for value in values or ())


def _reference_issues(view: CPNATMigrationView) -> tuple[CPNATTransformIssue, ...]:
    result = []
    for field in (
        "original_source", "original_destination", "original_service",
        "translated_source", "translated_destination", "translated_service", "install_on",
    ):
        for reference in getattr(view, field) or ():
            if reference.status in {"resolved", "source_only"}:
                continue
            result.append(CPNATTransformIssue(
                f"NAT {field} reference {reference.reference!r} is {reference.status}.",
                view.source_uid, view.source_name, view.domain,
                field, reference.reference, reference.status,
            ))
    return tuple(result)


def transform_nat(config: CheckPointConfig, references: CPReferenceIndex) -> CPNATTransformResult:
    views: list[CPNATMigrationView] = []
    issues: list[CPNATTransformIssue] = []

    for rule in config.nat_rules:
        if isinstance(rule, CPNATRule):
            view = CPNATMigrationView(
                "manual_rule", rule.uid, rule.name, rule.domain_uid or rule.domain,
                rule.order, rule.enabled,
                _references(rule.original_source, rule, "original_source", references),
                _references(rule.original_destination, rule, "original_destination", references),
                _references(rule.original_service, rule, "original_service", references),
                _references(rule.translated_source, rule, "translated_source", references),
                _references(rule.translated_destination, rule, "translated_destination", references),
                _references(rule.translated_service, rule, "translated_service", references),
                rule.method, install_on=_references(rule.install_on, rule, "install_on", references),
            )
            view_issues = _reference_issues(view)
            view = replace(view, issues=view_issues)
            views.append(view)
            issues.extend(view_issues)
        elif isinstance(rule, CPAutoNATRule):
            view = CPNATMigrationView(
                "returned_automatic_rule", rule.uid, rule.name, rule.domain_uid or rule.domain,
                rule.order, getattr(rule, "enabled", None),
                _references(rule.original_source, rule, "original_source", references),
                _references(rule.original_destination, rule, "original_destination", references),
                _references(rule.original_service, rule, "original_service", references),
                _references(rule.translated_source, rule, "translated_source", references),
                _references(rule.translated_destination, rule, "translated_destination", references),
                _references(rule.translated_service, rule, "translated_service", references),
            )
            view_issues = _reference_issues(view)
            view = replace(view, issues=view_issues)
            views.append(view)
            issues.extend(view_issues)

    owners = (*config.hosts, *config.networks, *config.address_ranges, *config.gateways, *config.clusters)
    for owner in owners:
        settings = owner.nat_settings
        if not isinstance(settings, dict) or settings.get("auto-rule") is not True:
            continue
        method = settings.get("method")
        translated_value = settings.get("ipv4-address") or settings.get("ipv6-address")
        owner_ref = CPNATReference(owner.uid or owner.name or "", owner.uid, owner.name, owner.uid, owner.name, "source_owner")
        owner_issues = []
        if not method:
            owner_issues.append(CPNATTransformIssue(
                "Automatic NAT translation method is not explicit in the source settings.",
                owner.uid, owner.name, owner.domain_uid or owner.domain,
                "nat_settings.method",
            ))
        if not translated_value:
            issue = CPNATTransformIssue(
                "Automatic NAT translation address is not explicit in the source settings.",
                owner.uid, owner.name, owner.domain_uid or owner.domain, "nat_settings.ipv4-address/ipv6-address",
            )
            owner_issues.append(issue)
        translated = (CPNATReference(str(translated_value)),) if translated_value else ()
        owner_issues = tuple(owner_issues)
        issues.extend(owner_issues)
        views.append(CPNATMigrationView(
            "automatic_object_settings", owner.uid, owner.name, owner.domain_uid or owner.domain,
            owner.order, None, original_source=(owner_ref,), translated_source=translated or None,
            translation_method=str(method) if method is not None else None,
            owner_uid=owner.uid, owner_name=owner.name, owner_kind=type(owner).__name__, issues=owner_issues,
        ))

    return CPNATTransformResult(tuple(views), tuple(issues))


__all__ = ["CPNATMigrationView", "CPNATReference", "CPNATTransformIssue", "CPNATTransformResult", "transform_nat"]
