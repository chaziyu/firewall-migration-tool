from __future__ import annotations

import ipaddress
from typing import Any, Iterable

from fwmigrate.extraction.models import DependencyRecord

from .predefined_services import PAN_RULE_SERVICE_BUILTINS
from .source_model import PANScope


def _is_literal(value: str) -> bool:
    value = value.strip()
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        pass
    if value.count("-") != 1:
        return False
    first, last = (part.strip() for part in value.split("-", 1))
    try:
        start, end = ipaddress.ip_address(first), ipaddress.ip_address(last)
    except ValueError:
        return False
    return start.version == end.version and int(start) <= int(end)


def _values(value: Any) -> Iterable[str]:
    values = value if isinstance(value, list) else ([] if value is None else [value])
    return (str(item).strip() for item in values if str(item).strip())


def _scope_for_rule(rule) -> PANScope:
    attrs = rule.source_attributes
    kind = attrs.get("pan_scope_kind") or "shared"
    name = attrs.get("pan_scope_name") or "shared"
    serial = attrs.get("pan_device_serial")
    return PANScope(
        kind=kind,
        name=name,
        device_serial=serial,
        vsys=name if kind == "vsys" else None,
    )


def _interface_scope(scope: PANScope) -> PANScope | None:
    if scope.kind == "device":
        return scope
    if scope.kind == "vsys" and (scope.device_serial or scope.device_name):
        return PANScope(
            kind="device",
            name=scope.device_name or scope.device_serial or scope.name,
            device_name=scope.device_name,
            device_serial=scope.device_serial,
        )
    return None


def build_pan_nat_dependencies(extraction, resolver) -> list[DependencyRecord]:
    dependencies: list[DependencyRecord] = []

    def add(rule, scope, field: str, reference: str, expected: str, namespace: str, *, interface: bool = False) -> None:
        if not reference or reference.lower() == "any":
            return
        resolution_scope = _interface_scope(scope) if interface else scope
        if interface and resolution_scope is None:
            result = "CONTEXT_DEPENDENT"
            target = None
            reason = "PAN interface reference requires a managed-device context."
        else:
            target = resolver.resolve(reference, namespace, resolution_scope)
            result = "RESOLVED" if target is not None else "UNRESOLVED"
            reason = None if target is not None else "Reference was not found in the PAN-OS scope chain."
        dependencies.append(DependencyRecord(
            source_context=rule.source_context,
            source_path="nat-rules",
            source_object=rule.name,
            source_field=field,
            reference=reference,
            expected_type=expected,
            result=result,
            target_path=target.source_path if target is not None else None,
            target_name=(target.canonical_name or target.name) if target is not None else None,
            reason=reason,
        ))

    for rule in extraction.canonical_ir.nat_rules:
        attrs = rule.source_attributes
        scope = _scope_for_rule(rule)
        for field, values, expected, namespace in (
            ("from-zone", attrs.get("pan_from"), "zone", "zone"),
            ("to-zone", attrs.get("pan_to"), "zone", "zone"),
        ):
            for reference in _values(values):
                add(rule, scope, field, reference, expected, namespace)

        for field, values, expected, namespace in (
            ("source", attrs.get("pan_source"), "address/address-group", "address-reference"),
            ("destination", attrs.get("pan_destination"), "address/address-group", "address-reference"),
        ):
            for reference in _values(values):
                if not _is_literal(reference):
                    add(rule, scope, field, reference, expected, namespace)

        service = attrs.get("pan_service")
        if service and str(service).lower() not in PAN_RULE_SERVICE_BUILTINS:
            add(rule, scope, "service", str(service), "service/service-group", "service-reference")

        to_interface = attrs.get("pan_to_interface")
        if to_interface:
            add(rule, scope, "to-interface", str(to_interface), "interface", "interface", interface=True)

        for key, field in (
            ("pan_translated_source_values", "translated-source"),
            ("pan_translated_destination_values", "translated-destination"),
        ):
            for item in attrs.get(key, []):
                if not isinstance(item, dict) or item.get("classification") not in {"object-reference", "unresolved-reference"}:
                    continue
                reference = str(item.get("value") or "")
                if reference and reference.lower() != "any":
                    add(rule, scope, field, reference, "address/address-group", "address-reference")

        primary = attrs.get("pan_interface_address_details")
        if isinstance(primary, dict) and primary.get("interface"):
            add(rule, scope, "source-translation-interface", primary["interface"], "interface", "interface", interface=True)

        fallback = attrs.get("pan_source_translation_fallback_details")
        fallback_details = fallback.get("interface_address") if isinstance(fallback, dict) else None
        if isinstance(fallback_details, dict) and fallback_details.get("interface"):
            add(rule, scope, "source-translation-fallback-interface", fallback_details["interface"], "interface", "interface", interface=True)

    return dependencies
