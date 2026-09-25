from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.extraction.sanitize import sanitize_source_attributes

from .excel_schema import SHEET_HEADERS, SHEET_ORDER


def _value(value: Any) -> Any:
    if isinstance(value, bool):
        return "Yes" if value else "No"
    return str(value) if isinstance(value, (list, tuple, dict)) else value


def _inheritance_rows(view: dict) -> tuple[dict, ...]:
    rows = [{"record_type": "statement", **item}
            for item in view.get("effective_statements", ())]
    for item in view.get("candidates", ()):
        provenance = item.get("provenance") or {}
        context = provenance.get("source_context") or {}
        rows.append({"record_type": "candidate", "context": str(context.get("name") or context.get("context_type") or "root"),
                     "origin": provenance.get("provenance_kind", "group"), "status": item.get("status"),
                     "target_path": item.get("target_path") or provenance.get("target_path"),
                     "source_path": provenance.get("source_path"),
                     "source_group": provenance.get("source_group_name"),
                     "group_chain": provenance.get("source_group_chain", ()),
                     "source_order": item.get("source_order"), "active": item.get("effective"),
                     "value": item.get("value")})
    rows.extend({"record_type": "issue", "context": item.get("context"), "origin": "group",
                 "status": item.get("status"), "target_path": item.get("target_path"),
                 "source_order": item.get("source_order"), "active": False}
                for item in view.get("issues", ()))
    return tuple(rows)


def _additional_settings(value: Any, context: str, path: tuple[str, ...] = ()) -> list[tuple[Any, ...]]:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    rows = []
    if isinstance(value, dict):
        for key, child in value.items():
            if key in {"raw_extra", "settings", "source_attributes"} and isinstance(child, dict):
                for setting, setting_value in child.items():
                    safe = sanitize_source_attributes({setting: setting_value})[setting]
                    rows.append((context, ".".join(path[:-1]), path[-1] if path else "source",
                                 setting, json.dumps(safe, sort_keys=True, ensure_ascii=False, default=str)))
            elif key not in {"field_candidate_history", "non_effective_candidate_history", "field_provenance"}:
                rows.extend(_additional_settings(child, context, (*path, str(key))))
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            rows.extend(_additional_settings(child, context, (*path, str(index))))
    return rows


def _coverage_row(section: Any, inventory: dict[str, Any]) -> tuple[Any, ...]:
    commands = inventory.get(section.path).commands if section.path in inventory else ()
    counts = {status: sum(command.status == status for command in commands)
              for status in ExtractionStatus}
    return (section.source_context, section.path, len(commands), counts[ExtractionStatus.EXTRACTED],
            counts[ExtractionStatus.PARTIAL], counts[ExtractionStatus.SOURCE_ONLY],
            counts[ExtractionStatus.UNSUPPORTED], counts[ExtractionStatus.UNKNOWN], counts[ExtractionStatus.IGNORED],
            counts[ExtractionStatus.PARSE_ERROR],
            section.unresolved_dependencies, section.status.value, section.status != ExtractionStatus.EXTRACTED)


def _unresolved_reference_row(item: Any) -> dict[str, Any]:
    context_type, _, context_name = (item.source_context or "").partition(" ")
    return {"context_type": context_type or None, "context": context_name or item.source_context,
            "source_path": item.source_path, "source_object": item.source_object,
            "source_field": item.source_field, "reference": item.reference,
            "expected_type": item.expected_type, "resolution": item.result,
            "reason": item.notes or item.reason}


def export_juniper_excel(result: Any, output: Any) -> Any:
    from openpyxl import Workbook
    from openpyxl.styles import Alignment

    workbook = Workbook()
    workbook.remove(workbook.active)
    views = result.derived
    rows = {"Interfaces": views.interface_topology, "Zones": views.zone_memberships,
            "Routing Instances": views.routing_instances, "Address Books": views.address_books,
            "Applications": views.applications, "Policies": views.policies, "NAT": views.nat_rule_sets,
            "VPN": views.vpn_relationships,
            "DHCP Local Servers": tuple(item for item in views.dhcp if item["kind"] == "local-server"),
            "DHCP Relay Groups": tuple(item for item in views.dhcp if item["kind"] == "relay-group"),
            "DHCP Pools": tuple(item for item in views.dhcp if item["kind"] == "address-assignment-pool"),
            "Access Profiles": views.access_profiles, "Firewall Users": views.firewall_users,
            "APBR": views.apbr, "Remote Access": views.remote_access,
            "Policy Relationships": tuple(row for item in views.policy_relationships
                                           for group in item["zone_policy_sets"] for row in group["policies"])
                                  + tuple(row for item in views.policy_relationships for row in item["global_policies"]),
            "Policy Reference Relationships": tuple(edge for item in views.policy_relationships
                                                      for edge in item["edges"]),
            "NAT Usage": views.nat_usage, "NAT Pool Usage": views.nat_pool_usage, "VPN Relationships": views.vpn_graph,
            "Secure Connect": views.secure_connect_graph, "APBR Relationships": views.apbr_graph,
            "Inheritance": _inheritance_rows(views.inheritance_view),
            "Review Required": result.review_required,
            "Unresolved References": tuple(_unresolved_reference_row(item) for item in views.dependencies
                                           if item.result == "UNRESOLVED")}
    inventory_by_path = {item.source_path: item for item in result.inventory_items}
    additional = []
    for context in result.config.iter_contexts():
        scope = "root" if context.context_type == "root" else f"{context.context_type} {context.name}"
        additional.extend(_additional_settings(context, scope, (context.name,)))
    additional.extend(_additional_settings(result.config.model_dump(
        mode="json", exclude={"contexts", "configuration_groups", "field_provenance",
                               "field_candidate_history", "non_effective_candidate_history",
                               "activation_directives", "unsupported_commands"}), "root"))
    rows["Additional Settings"] = tuple(additional)
    for name in SHEET_ORDER:
        sheet = workbook.create_sheet(name)
        if name == "Summary":
            sheet.append(("Field", "Value"))
            sheet.append(("Vendor", "Juniper SRX"))
            sheet.append(("Hostname", result.config.hostname))
            sheet.append(("Source Format", result.source_format))
            sheet.append(("Contexts", len(result.config.contexts)))
            sheet.append(("Configuration Groups", len(result.config.configuration_groups)))
            sheet.append(("Source Sections", len(result.source_sections)))
            sheet.append(("Partial Sections", sum(item.status == ExtractionStatus.PARTIAL for item in result.source_sections)))
            sheet.append(("Source Only Sections", sum(item.status == ExtractionStatus.SOURCE_ONLY for item in result.source_sections)))
            sheet.append(("Unsupported Sections", sum(item.status == ExtractionStatus.UNSUPPORTED for item in result.source_sections)))
            sheet.append(("Parse Errors", sum(item.status == ExtractionStatus.PARSE_ERROR for item in result.source_sections)))
            sheet.append(("Validation Errors", len(result.validation.errors)))
            sheet.append(("Validation Warnings", len(result.validation.warnings)))
            sheet.append(("Unresolved References", sum(item.result == "UNRESOLVED" for item in views.dependencies)))
            sheet.append(("Interfaces", len(views.interface_topology)))
            sheet.append(("Zones", len(views.zone_memberships)))
            sheet.append(("Policies", len(views.policies)))
            sheet.append(("NAT Rule Sets", len(views.nat_rule_sets)))
            sheet.append(("Routes", sum(len(context.routes) for context in result.config.iter_contexts())))
            sheet.append(("DHCP Objects", len(views.dhcp)))
            sheet.append(("VPNs", len(views.vpn_relationships)))
            sheet.append(("Remote Access Profiles", len(result.config.contexts) and sum(len(context.remote_access.profiles) for context in result.config.iter_contexts())))
            sheet.append(("APBR SLA Rules", sum(len(context.apbr.sla_rules) for context in result.config.iter_contexts())))
            continue
        if name == "Source Inventory":
            sheet.append(("Domain", "Source Path", "Context", "Status", "Review Required", "Commands"))
            for item in result.inventory_items:
                sheet.append((item.domain, item.source_path, item.source_context, item.status.value,
                              item.requires_manual_review, len(item.commands)))
            continue
        if name == "Validation":
            sheet.append(SHEET_HEADERS[name])
            for issue in result.validation.issues:
                sheet.append((issue.code, issue.severity, issue.category, issue.message, issue.context_type,
                              issue.context, issue.source_path, issue.object_type, issue.object_name,
                              issue.field, issue.reference, issue.expected_type))
            continue
        if name == "Extraction Coverage":
            sheet.append(SHEET_HEADERS[name])
            for section in result.source_sections:
                sheet.append(_coverage_row(section, inventory_by_path))
            continue
        if name == "Unsupported Source":
            sheet.append(SHEET_HEADERS[name])
            for item in result.unsupported_items:
                sheet.append((item.source_context, item.source_path, item.source_name, item.reason, item.raw_capture))
            continue
        sheet.append(SHEET_HEADERS[name])
        for item in rows[name]:
            if isinstance(item, tuple):
                sheet.append(tuple(_value(value) for value in item))
                continue
            if hasattr(item, "model_dump"):
                item = item.model_dump(mode="python")
            elif hasattr(item, "__dict__"):
                item = item.__dict__
            sheet.append(tuple(_value(item.get(header.lower().replace(" ", "_"))) for header in SHEET_HEADERS[name]))
    for sheet in workbook.worksheets:
        sheet.freeze_panes = "A2"
        sheet.auto_filter.ref = sheet.dimensions
        for column in sheet.columns:
            letter = column[0].column_letter
            sheet.column_dimensions[letter].width = min(48, max(12, max(len(str(cell.value or "")) for cell in column) + 2))
            for cell in column:
                cell.alignment = cell.alignment + Alignment(wrap_text=True, vertical="top")
    if hasattr(output, "write"):
        workbook.save(output)
        return output
    path = Path(output)
    workbook.save(path)
    return path


__all__ = ["export_juniper_excel"]
