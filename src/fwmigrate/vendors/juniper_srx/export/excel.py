from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.extraction.sanitize import sanitize_source_attributes
from ....source_reporting.options import ExcelExportProfile
from ....source_reporting.excel_style import append_report_row, finish_report_workbook

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


def _context_scope(context: Any) -> str:
    return "root" if context.context_type == "root" else f"{context.context_type} {context.name}"


def _native_source_rows(config: Any) -> dict[str, tuple[dict[str, Any], ...]]:
    rows: dict[str, list[dict[str, Any]]] = {
        "Addresses": [], "Address Sets": [], "Application Sets": [], "Schedulers": [],
        "Policy Details": [], "NAT Pools": [], "NAT Rules": [],
        "IKE Proposals": [], "IKE Policies": [], "IKE Gateways": [],
        "IPsec Proposals": [], "IPsec Policies": [], "IPsec VPNs": [],
        "Traffic Selectors": [], "Static Routes": [],
    }
    for context in config.iter_contexts():
        scope = _context_scope(context)

        for book in context.address_books.values():
            for item in book.addresses.values():
                rows["Addresses"].append({
                    "context": scope, "address_book": book.name, "name": item.name, "type": item.type,
                    "prefix": item.prefix, "fqdn": item.fqdn, "range_start": item.range_start,
                    "range_end": item.range_end, "wildcard": item.wildcard, "zone": item.zone,
                    "description": item.description,
                })
            for item in book.address_sets.values():
                rows["Address Sets"].append({
                    "context": scope, "address_book": book.name, "name": item.name,
                    "members": [member.name for member in item.members],
                    "member_types": [member.member_type for member in item.members],
                    "zone": item.zone, "description": item.description,
                })

        for item in context.application_sets.values():
            rows["Application Sets"].append({
                "context": scope, "name": item.name, "applications": list(item.applications),
                "description": item.description,
            })

        for item in context.schedulers.values():
            rows["Schedulers"].append({
                "context": scope, "name": item.name, "start_date": item.start_date,
                "stop_date": item.stop_date, "daily": list(item.daily),
                "weekdays": dict(item.weekdays), "daily_windows": list(item.daily_windows),
                "weekday_windows": dict(item.weekday_windows), "exclusions": list(item.exclusions),
                "description": item.description,
            })

        for item in (*context.policies, *context.global_policies):
            rows["Policy Details"].append({
                "context": scope, "policy_scope": item.policy_scope, "name": item.name,
                "order": item.sequence, "from_zones": list(item.from_zones),
                "to_zones": list(item.to_zones), "source_addresses": list(item.source_addresses),
                "destination_addresses": list(item.destination_addresses),
                "applications": list(item.applications),
                "dynamic_applications": list(item.dynamic_applications),
                "source_identities": list(item.source_identities), "scheduler": item.scheduler_name,
                "action": item.action, "log_session_init": item.log_session_init,
                "log_session_close": item.log_session_close,
                "application_services": list(item.application_services),
                "security_profile_references": dict(item.security_profile_references),
                "description": item.description,
            })

        for nat_type, pools in (("source", context.nat.source_pools), ("destination", context.nat.destination_pools)):
            for item in pools.values():
                rows["NAT Pools"].append({
                    "context": scope, "nat_type": nat_type, "name": item.name,
                    "routing_instance": item.routing_instance, "addresses": list(item.addresses),
                    "address_ranges": list(item.address_ranges), "ports": list(item.ports),
                    "options": dict(item.options),
                })

        for nat_type, rule_sets in (
            ("source", context.nat.source_rule_sets),
            ("destination", context.nat.destination_rule_sets),
            ("static", context.nat.static_rule_sets),
        ):
            for rule_set in rule_sets.values():
                to_context = rule_set.to_context
                for item in rule_set.rules:
                    rows["NAT Rules"].append({
                        "context": scope, "nat_type": nat_type, "rule_set": rule_set.name,
                        "rule": item.name, "order": item.sequence,
                        "from_zones": list(rule_set.from_context.zones),
                        "from_interfaces": list(rule_set.from_context.interfaces),
                        "from_routing_instances": list(rule_set.from_context.routing_instances),
                        "to_zones": list(to_context.zones) if to_context else [],
                        "to_interfaces": list(to_context.interfaces) if to_context else [],
                        "to_routing_instances": list(to_context.routing_instances) if to_context else [],
                        "source_addresses": list(item.match.source_addresses),
                        "destination_addresses": list(item.match.destination_addresses),
                        "source_address_names": list(item.match.source_address_names),
                        "destination_address_names": list(item.match.destination_address_names),
                        "source_ports": list(item.match.source_ports),
                        "destination_ports": list(item.match.destination_ports),
                        "protocols": list(item.match.protocols), "applications": list(item.match.applications),
                        "action": dict(item.action), "disabled": item.disabled, "description": item.description,
                    })

        vpn = context.vpn
        rows["IKE Proposals"].extend({
            "context": scope, "name": item.name, "authentication_method": item.authentication_method,
            "dh_group": item.dh_group, "authentication_algorithm": item.authentication_algorithm,
            "encryption_algorithm": item.encryption_algorithm,
            "digital_signature_scheme": item.digital_signature_scheme, "prf_algorithm": item.prf_algorithm,
            "signature_hash_algorithm": item.signature_hash_algorithm,
            "lifetime_seconds": item.lifetime_seconds, "description": item.description,
        } for item in vpn.ike_proposals.values())
        rows["IKE Policies"].extend({
            "context": scope, "name": item.name, "mode": item.mode, "proposal_set": item.proposal_set,
            "proposals": list(item.proposals), "pre_shared_key_configured": item.has_pre_shared_key,
            "certificate_reference": item.certificate_reference, "local_certificate": item.local_certificate,
        } for item in vpn.ike_policies.values())
        rows["IKE Gateways"].extend({
            "context": scope, "name": item.name, "ike_policy": item.ike_policy, "address": item.address,
            "external_interface": item.external_interface, "version": item.version,
            "local_address": item.local_address, "local_identity": item.local_identity,
            "remote_identity": item.remote_identity, "nat_traversal": item.nat_traversal,
            "dpd": dict(item.dpd), "certificate_reference": item.certificate_reference,
        } for item in vpn.ike_gateways.values())
        rows["IPsec Proposals"].extend({
            "context": scope, "name": item.name, "protocol": item.protocol,
            "authentication_algorithm": item.authentication_algorithm,
            "encryption_algorithm": item.encryption_algorithm, "lifetime_seconds": item.lifetime_seconds,
            "lifetime_kilobytes": item.lifetime_kilobytes, "description": item.description,
        } for item in vpn.ipsec_proposals.values())
        rows["IPsec Policies"].extend({
            "context": scope, "name": item.name, "proposal_set": item.proposal_set,
            "proposals": list(item.proposals), "pfs_group": item.pfs_group,
        } for item in vpn.ipsec_policies.values())
        for item in vpn.ipsec_vpns.values():
            rows["IPsec VPNs"].append({
                "context": scope, "name": item.name, "bind_interface": item.bind_interface,
                "ike_gateway": item.ike_gateway, "ipsec_policy": item.ipsec_policy,
                "establish_tunnels": item.establish_tunnels,
                "vpn_monitor_destination": item.vpn_monitor.destination_ip if item.vpn_monitor else None,
                "vpn_monitor_source_interface": item.vpn_monitor.source_interface if item.vpn_monitor else None,
            })
            for selector in item.traffic_selectors.values():
                rows["Traffic Selectors"].append({
                    "context": scope, "vpn": item.name, "name": selector.name, "term": None,
                    "local_ip": list(selector.local_ip), "remote_ip": list(selector.remote_ip),
                    "protocol": selector.protocol, "local_port": list(selector.local_port),
                    "remote_port": list(selector.remote_port),
                })
                for term in selector.terms.values():
                    rows["Traffic Selectors"].append({
                        "context": scope, "vpn": item.name, "name": selector.name, "term": term.name,
                        "local_ip": list(term.local_ip), "remote_ip": list(term.remote_ip),
                        "protocol": term.protocol, "local_port": list(term.local_port),
                        "remote_port": list(term.remote_port),
                    })

        for item in context.routes:
            hops = item.next_hops or (None,)
            for hop in hops:
                rows["Static Routes"].append({
                    "context": scope, "routing_instance": item.routing_instance, "rib": item.rib,
                    "destination": item.destination, "next_hop": hop.value if hop else None,
                    "qualified": hop.qualified if hop else None, "next_table": item.next_table,
                    "route_preference": item.preference, "route_metric": item.metric, "route_tag": item.tag,
                    "next_hop_preference": hop.preference if hop else None,
                    "next_hop_metric": hop.metric if hop else None, "next_hop_tag": hop.tag if hop else None,
                    "action": item.action, "retain": item.retain, "installation": item.installation,
                    "disabled": item.disabled,
                })
    return {name: tuple(values) for name, values in rows.items()}


def export_juniper_excel(result: Any, output: Any, *, profile: ExcelExportProfile | str = ExcelExportProfile.FULL) -> Any:
    from openpyxl import Workbook

    profile = ExcelExportProfile(profile)
    workbook = Workbook(write_only=profile is ExcelExportProfile.FAST)
    if not workbook.write_only:
        workbook.remove(workbook.active)
    views = result.derived
    rows = {"Interfaces": views.interface_topology, "Zones": views.zone_memberships,
            "Routing Instances": views.routing_instances, "Address Books": views.address_books,
            "Applications": views.applications, "Policies": views.policies, "NAT": views.nat_rule_sets,
            "VPN": views.vpn_relationships, **_native_source_rows(result.config),
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
        if profile is ExcelExportProfile.FAST and name in {"Source Inventory", "Extraction Coverage"}:
            continue
        sheet = workbook.create_sheet(name)
        if name == "Summary":
            append_report_row(sheet, ("Field", "Value"))
            append_report_row(sheet, ("Vendor", "Juniper SRX"))
            append_report_row(sheet, ("Hostname", result.config.hostname))
            append_report_row(sheet, ("Source Format", result.source_format))
            append_report_row(sheet, ("Contexts", len(result.config.contexts)))
            append_report_row(sheet, ("Configuration Groups", len(result.config.configuration_groups)))
            append_report_row(sheet, ("Source Sections", len(result.source_sections)))
            append_report_row(sheet, ("Partial Sections", sum(item.status == ExtractionStatus.PARTIAL for item in result.source_sections)))
            append_report_row(sheet, ("Source Only Sections", sum(item.status == ExtractionStatus.SOURCE_ONLY for item in result.source_sections)))
            append_report_row(sheet, ("Unsupported Sections", sum(item.status == ExtractionStatus.UNSUPPORTED for item in result.source_sections)))
            append_report_row(sheet, ("Parse Errors", sum(item.status == ExtractionStatus.PARSE_ERROR for item in result.source_sections)))
            append_report_row(sheet, ("Validation Errors", len(result.validation.errors)))
            append_report_row(sheet, ("Validation Warnings", len(result.validation.warnings)))
            append_report_row(sheet, ("Unresolved References", sum(item.result == "UNRESOLVED" for item in views.dependencies)))
            append_report_row(sheet, ("Interfaces", len(views.interface_topology)))
            append_report_row(sheet, ("Zones", len(views.zone_memberships)))
            append_report_row(sheet, ("Policies", len(views.policies)))
            append_report_row(sheet, ("NAT Rule Sets", len(views.nat_rule_sets)))
            append_report_row(sheet, ("Routes", sum(len(context.routes) for context in result.config.iter_contexts())))
            append_report_row(sheet, ("DHCP Objects", len(views.dhcp)))
            append_report_row(sheet, ("VPNs", len(views.vpn_relationships)))
            append_report_row(sheet, ("Remote Access Profiles", len(result.config.contexts) and sum(len(context.remote_access.profiles) for context in result.config.iter_contexts())))
            append_report_row(sheet, ("APBR SLA Rules", sum(len(context.apbr.sla_rules) for context in result.config.iter_contexts())))
            continue
        if name == "Source Inventory":
            append_report_row(sheet, ("Domain", "Source Path", "Context", "Line", "Operation", "Key",
                                      "Values", "Status", "Handler", "Review Required"))
            for item in result.inventory_items:
                if not item.commands:
                    append_report_row(sheet, (item.domain, item.source_path, item.source_context, None, None, None,
                                              None, item.status.value, None, item.requires_manual_review))
                    continue
                for command in item.commands:
                    append_report_row(sheet, (
                        item.domain, item.source_path, command.source_context or item.source_context,
                        command.line_number, command.operation, command.key, _value(command.values),
                        command.status.value if command.status else None, command.parser_handler,
                        command.requires_manual_review,
                    ))
            continue
        if name == "Validation":
            append_report_row(sheet, SHEET_HEADERS[name])
            for issue in result.validation.issues:
                append_report_row(sheet, (issue.code, issue.severity, issue.category, issue.message, issue.context_type,
                              issue.context, issue.source_path, issue.object_type, issue.object_name,
                              issue.field, issue.reference, issue.expected_type))
            continue
        if name == "Extraction Coverage":
            append_report_row(sheet, SHEET_HEADERS[name])
            for section in result.source_sections:
                append_report_row(sheet, _coverage_row(section, inventory_by_path))
            continue
        if name == "Unsupported Source":
            append_report_row(sheet, SHEET_HEADERS[name])
            for item in result.unsupported_items:
                append_report_row(sheet, (item.source_context, item.source_path, item.source_name, item.reason, item.raw_capture))
            continue
        append_report_row(sheet, SHEET_HEADERS[name])
        for item in rows[name]:
            if isinstance(item, tuple):
                append_report_row(sheet, tuple(_value(value) for value in item))
                continue
            if hasattr(item, "model_dump"):
                item = item.model_dump(mode="python")
            elif hasattr(item, "__dict__"):
                item = item.__dict__
            append_report_row(sheet, tuple(_value(item.get(header.lower().replace(" ", "_"))) for header in SHEET_HEADERS[name]))
    finish_report_workbook(workbook)
    if hasattr(output, "write"):
        workbook.save(output)
        return output
    path = Path(output)
    workbook.save(path)
    return path


__all__ = ["export_juniper_excel"]
