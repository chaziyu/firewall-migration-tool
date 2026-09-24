"""Junos source preview serialization."""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from enum import Enum
from typing import Any

from fwmigrate.extraction.sanitize import sanitize_source_attributes
from .validation import JuniperValidationIssueIndex


def _project(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="python")
    elif is_dataclass(value):
        value = asdict(value)
    if isinstance(value, dict):
        return sanitize_source_attributes({str(key): _project(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return [_project(item) for item in value]
    return value


def build_juniper_preview(result: Any) -> dict[str, Any]:
    config = result.config
    issue_index = JuniperValidationIssueIndex(result.validation.issues)
    return {
        "vendor": "juniper_srx",
        "hostname": config.hostname,
        "source_format": result.source_format,
        "summary": {"contexts": len(config.contexts), "groups": len(config.configuration_groups),
                     "unsupported": len(config.unsupported_commands),
                     "source_sections": len(result.source_sections),
                     "extracted_sections": sum(item.status.value == "EXTRACTED" for item in result.source_sections),
                     "partial_sections": sum(item.status.value == "PARTIAL" for item in result.source_sections),
                     "source_only_sections": sum(item.status.value == "SOURCE_ONLY" for item in result.source_sections),
                     "unsupported_sections": sum(item.status.value == "UNSUPPORTED" for item in result.source_sections),
                     "parse_error_sections": sum(item.status.value == "PARSE_ERROR" for item in result.source_sections),
                     "validation_errors": len(result.validation.errors),
                     "validation_warnings": len(result.validation.warnings),
                     "interfaces": len(result.derived.interface_topology),
                     "policies": len(result.derived.policies), "nat_rule_sets": len(result.derived.nat_rule_sets),
                     "dhcp_objects": len(result.derived.dhcp), "apbr_objects": len(result.derived.apbr),
                     "remote_access_objects": len(result.derived.remote_access)},
        "contexts": [{"name": item.name, "type": item.context_type} for item in config.iter_contexts()],
        "source": {"hostname": config.hostname, "version": config.version, "time_zone": config.time_zone},
        "source_sections": _project(result.source_sections),
        "inventory": _project(result.inventory_items),
        "unsupported": _project(result.unsupported_items),
        "review_required": _project(result.review_required),
        "extraction_coverage": _project(result.source_sections),
        "relationships": _project({"interfaces": result.derived.interface_topology,
                           "zones": result.derived.zone_memberships,
                           "routing_instances": result.derived.routing_instances,
                           "policies": result.derived.policies,
                           "nat": result.derived.nat_rule_sets,
                           "vpn": result.derived.vpn_relationships,
                           "dhcp": result.derived.dhcp,
                           "access_profiles": result.derived.access_profiles,
                           "firewall_users": result.derived.firewall_users,
                           "apbr": result.derived.apbr,
                           "remote_access": result.derived.remote_access,
                           "interface_topology": result.derived.interface_topology,
                           "policy_relationships": result.derived.policy_relationships,
                           "nat_usage": result.derived.nat_usage,
                           "nat_pool_usage": result.derived.nat_pool_usage,
                           "vpn_graph": result.derived.vpn_graph,
                           "secure_connect_graph": result.derived.secure_connect_graph,
                           "apbr_graph": result.derived.apbr_graph,
                           "inheritance": result.derived.inheritance,
                           "inheritance_view": result.derived.inheritance_view,
                           "activation_directives": result.derived.activation_directives}),
        "validation": _project(result.validation.issues),
        "semantic_validation": _project(tuple(issue for issue in result.validation.issues
                                               if issue.category != "extraction-coverage")),
        "extraction_review": _project(tuple(issue for issue in result.validation.issues
                                             if issue.category == "extraction-coverage")),
        "validation_summary": {"errors": len(result.validation.errors),
                               "warnings": len(result.validation.warnings)},
        "validation_by_context": {context: _project(issues)
                                  for context, issues in sorted(issue_index.by_context.items())},
    }


__all__ = ["build_juniper_preview"]
