"""Shared, presentation-only contract for the source report UI."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

REPORT_SECTIONS = (
    "interfaces", "addresses", "address_groups", "services", "service_groups",
    "schedules", "policies", "nat", "routes", "vpn_tunnels", "vpn_phase2",
    "validation", "unresolved_references",
)


def empty_report_sections() -> dict[str, list[Any]]:
    return {name: [] for name in REPORT_SECTIONS}


def _nested(report: dict[str, Any], *path: str) -> Any:
    value: Any = report
    for key in path:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def normalize_web_report(report: dict[str, Any], vendor_id: str) -> dict[str, Any]:
    """Add the shared UI shape without changing vendor-native report data."""
    if not isinstance(report, dict):
        raise TypeError("Source reporter previews must be objects")
    result = deepcopy(report)
    summary = result.setdefault("summary", {})
    if not isinstance(summary, dict):
        raise TypeError("Source reporter summary must be an object")
    sections = result.setdefault("sections", {})
    if not isinstance(sections, dict):
        raise TypeError("Source reporter sections must be an object")
    aliases = {
        "interfaces": (("interface_topology",), ("interfaces",), ("relationships", "interfaces"), ("derived", "interfaces")),
        "addresses": (("source", "addresses"), ("source", "network_objects"), ("source", "network_addresses")),
        "address_groups": (("source", "address_groups"), ("source", "network_groups")),
        "services": (("source", "services"), ("source", "service_objects"), ("source", "protocol_port_objects")),
        "service_groups": (("source", "service_groups"), ("source", "port_object_groups")),
        "schedules": (("source", "schedules"), ("source", "time_ranges")),
        "policies": (("source", "acl_rules"), ("source", "access_control_policies"), ("relationships", "policies"), ("derived", "policy_traversal")),
        "nat": (("source", "nat_rules"), ("derived", "nat"), ("relationships", "nat"), ("normalized_nat",)),
        "routes": (("source", "routes"), ("source", "static_routes"), ("normalized_routes",), ("relationships", "routing")),
        "vpn_tunnels": (("derived", "vpn"), ("vpn_relationships",), ("relationships", "vpn")),
        "vpn_phase2": (("vpn_phase2",),),
        "validation": (("validation",),),
        "unresolved_references": (("unresolved_references",), ("derived", "unresolved_references"), ("relationships", "unresolved_references")),
    }
    for name in REPORT_SECTIONS:
        if name in sections:
            sections[name] = list(sections[name] or ())
            continue
        for alias in aliases[name]:
            value = _nested(result, *alias)
            if isinstance(value, (list, tuple)):
                sections[name] = list(value)
                break
        else:
            sections[name] = []
    objects = summary.setdefault("objects", {})
    if not isinstance(objects, dict):
        objects = summary["objects"] = {}
    for name in REPORT_SECTIONS:
        if name not in {"schedules", "validation", "unresolved_references", "vpn_phase2"}:
            objects.setdefault(name, len(sections[name]))
    validation = summary.setdefault("validation", {})
    if not isinstance(validation, dict):
        validation = summary["validation"] = {}
    severity_counts = validation.setdefault("severity_counts", {})
    if not isinstance(severity_counts, dict):
        severity_counts = validation["severity_counts"] = {}
    if not severity_counts:
        for row in sections["validation"]:
            if isinstance(row, dict) and row.get("severity"):
                key = str(row["severity"]).lower()
                severity_counts[key] = severity_counts.get(key, 0) + 1
    summary.setdefault("scopes", result.get("scopes", result.get("contexts", [])))
    summary.setdefault("vendor", vendor_id)
    return result


def validate_web_report_payload(report: dict[str, Any]) -> None:
    if not isinstance(report, dict) or not isinstance(report.get("summary"), dict):
        raise TypeError("Web report requires a summary object")
    sections = report.get("sections")
    if not isinstance(sections, dict) or any(name not in sections for name in REPORT_SECTIONS):
        raise TypeError("Web report is missing required sections")
