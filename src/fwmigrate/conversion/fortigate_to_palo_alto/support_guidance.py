"""Actionable, report-only guidance for blocked pair-specific migration items."""

from dataclasses import dataclass
import json
import re

from .decisions import PANMigrationDecisionSet, make_decision_key


@dataclass(frozen=True, slots=True)
class PANSupportGuidance:
    source_vdom: str | None
    source_kind: str | None
    source_name: str | None
    source_policy_id: int | None
    status: str
    code: str
    resolution_type: str
    title: str
    why: str
    next_action: str
    becomes_supported_when: str
    decision_key: str | None = None

    def to_dict(self) -> dict:
        return {
            "source_vdom": self.source_vdom, "source_kind": self.source_kind,
            "source_name": self.source_name, "source_policy_id": self.source_policy_id,
            "status": self.status, "code": self.code, "resolution_type": self.resolution_type,
            "title": self.title, "why": self.why, "next_action": self.next_action,
            "becomes_supported_when": self.becomes_supported_when,
            "decision_key": self.decision_key,
        }


def _decision_key(decisions, vdom, name, field, kinds=("interface", "zone")):
    if not name:
        return None
    keys = {item.key for item in decisions.decisions}
    return next((make_decision_key(vdom or "root", kind, name, field) for kind in kinds
                 if make_decision_key(vdom or "root", kind, name, field) in keys), None)


def _guidance(item, code, resolution_type, title, why, next_action, becomes, decision_key=None):
    return PANSupportGuidance(
        getattr(item, "source_vdom", None), getattr(item, "source_kind", None),
        getattr(item, "source_name", None), getattr(item, "source_policy_id", None),
        getattr(getattr(item, "status", None), "value", getattr(item, "status", "MANUAL_REVIEW")),
        code, resolution_type, title, why, next_action, becomes, decision_key,
    )


def _warning_guidance(item, warning, decisions):
    lower = warning.lower()
    vdom = getattr(item, "source_vdom", None) or "root"
    match = re.search(r"for ['\"]([^'\"]+)", warning)
    name = match.group(1) if match else None
    if "missing target zone mapping" in lower:
        return _guidance(item, "MISSING_TARGET_ZONE", "MISSING_MAPPING", "Missing target zone",
                         warning, f"Confirm a target zone for {name or 'the referenced interface'}.",
                         "the target zone decision is confirmed", _decision_key(decisions, vdom, name, "target_zone"))
    if "missing target interface mapping" in lower:
        return _guidance(item, "MISSING_TARGET_INTERFACE", "MISSING_MAPPING", "Missing target interface",
                         warning, f"Confirm a target interface for {name or 'the referenced interface'}.",
                         "the target interface decision is confirmed", _decision_key(decisions, vdom, name, "target_interface", ("interface",)))
    if "missing target virtual-router mapping" in lower:
        return _guidance(item, "MISSING_VIRTUAL_ROUTER", "MISSING_MAPPING", "Missing virtual router",
                         warning, f"Confirm a virtual router for VDOM {vdom}.",
                         "the VDOM virtual-router decision is confirmed",
                         _decision_key(decisions, vdom, vdom, "virtual_router", ("vdom",)))
    if "missing target vsys mapping" in lower:
        return _guidance(item, "MISSING_VSYS", "MISSING_MAPPING", "Missing target VSYS",
                         warning, f"Confirm a target VSYS for VDOM {vdom}.",
                         "the VDOM VSYS decision is confirmed",
                         _decision_key(decisions, vdom, vdom, "vsys", ("vdom",)))
    if "multiple possible egress interfaces" in lower:
        return _guidance(item, "AMBIGUOUS_NAT_EGRESS", "AMBIGUOUS_SOURCE", "Ambiguous NAT egress",
                         warning, "Determine the intended egress interface before rendering NAT.",
                         "one deterministic egress interface is selected")
    feature_map = (
        ("internet service", "INTERNET_SERVICE_UNSUPPORTED", "Converter feature", "Provide an explicit PAN-OS representation for Internet Service matching."),
        ("schedule group", "SCHEDULE_GROUP_UNSUPPORTED", "Converter feature", "Implement verified schedule-group translation or redesign it manually."),
        ("service negation", "SERVICE_NEGATION_UNSUPPORTED", "Converter feature", "Redesign the negated service match as explicit PAN-OS rules."),
        ("user and group", "USER_GROUP_UNSUPPORTED", "Manual target design", "Define the PAN-OS user/group representation and matching behavior."),
        ("inspection settings", "INSPECTION_UNSUPPORTED", "Manual target design", "Define equivalent PAN-OS security profiles and attach them explicitly."),
        ("unsupported service protocol", "SERVICE_UNSUPPORTED", "Converter feature", "Use a supported service protocol/port or create the target service manually."),
        ("unsupported source or dynamic routing", "ROUTE_SEMANTICS_UNSUPPORTED", "Converter feature", "Redesign the route using supported static-route semantics."),
        ("vip type or load-balancing", "VIP_SEMANTICS_UNSUPPORTED", "Manual target design", "Resolve the target NAT/load-balancing design manually."),
        ("vip requires", "VIP_MAPPING_REQUIRED", "MISSING_MAPPING", "Confirm one external and one mapped address for the VIP."),
    )
    for needle, code, resolution, action in feature_map:
        if needle in lower:
            resolution_type = "CONVERTER_FEATURE" if resolution == "Converter feature" else "MANUAL_TARGET_DESIGN"
            if resolution == "MISSING_MAPPING":
                resolution_type = "MISSING_MAPPING"
            return _guidance(item, code, resolution_type, resolution, warning, action,
                             "the required target semantics are explicitly supported or redesigned")
    return _guidance(item, "MIGRATION_REVIEW", "CONVERTER_FEATURE", "Migration review required",
                     warning, "Review the item and choose an explicit supported target design.",
                     "the item has deterministic supported target semantics")


def build_support_guidance(plan, validation, decisions, target_findings=()):
    result = []
    for item in _items(plan):
        for warning in getattr(item, "warnings", ()):
            result.append(_warning_guidance(item, warning, decisions))
    for issue in getattr(validation, "issues", ()) if validation else ():
        ref = issue.source
        item = next((candidate for candidate in _items(plan)
                     if getattr(candidate, "source_vdom", None) == ref.source_vdom
                     and getattr(candidate, "source_name", None) == ref.source_name), None)
        if item is None:
            continue
        if issue.code in {"missing_target_vsys", "missing_virtual_router", "missing_route_interface"}:
            result.append(_warning_guidance(item, issue.message, decisions))
        elif issue.message not in {entry.why for entry in result}:
            result.append(_warning_guidance(item, issue.message, decisions))
    for finding in target_findings:
        try:
            source_vdom, source_kind, source_name, _ = json.loads(finding.decision_key)
        except (TypeError, ValueError, json.JSONDecodeError):
            source_vdom = source_kind = source_name = None
        item = next((candidate for candidate in _items(plan)
                     if getattr(candidate, "source_vdom", None) == source_vdom
                     and getattr(candidate, "source_name", None) == source_name), None)
        if item is None:
            continue
        result.append(_guidance(item, finding.code, "TARGET_CONFLICT", "Target evidence conflict", finding.message,
                                "Review the confirmed mapping against the selected target evidence.",
                                "the confirmed value matches the selected target or the target design is intentionally changed",
                                finding.decision_key))
    unique = {}
    for entry in result:
        unique[(entry.source_vdom, entry.source_kind, entry.source_name, entry.code, entry.decision_key)] = entry
    return tuple(unique.values())


def _items(plan):
    if plan is None:
        return
    for name in ("addresses", "address_groups", "services", "service_groups", "schedules", "zones", "static_routes", "security_rules", "nat_rules"):
        yield from getattr(plan, name)


__all__ = ["PANSupportGuidance", "build_support_guidance"]
