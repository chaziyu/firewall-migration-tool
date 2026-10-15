"""Deterministic Palo Alto set-command rendering."""

import json
import hashlib
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from . import cli_paths
from fwmigrate.conversion.fortigate_to_palo_alto.models import PANMigrationPlan, PANMigrationStatus
from fwmigrate.conversion.fortigate_to_palo_alto.target.target_plan_validation import PANRenderDisposition, item_key
from fwmigrate.conversion.fortigate_to_palo_alto.validation import MigrationValidationResult, validate_plan


@dataclass(frozen=True, slots=True)
class RenderedMigration:
    commands: tuple[str, ...]
    report: dict


def _v(value):
    text = "" if value is None else str(value)
    if re.fullmatch(r"[A-Za-z0-9_./:@+-]+", text):
        return text
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'


class PANSetRenderer:
    def render(self, plan: PANMigrationPlan, validation: MigrationValidationResult | None = None, *,
               dispositions=None, render_blockers=None, decision_keys=None,
               configure_paths=None, virtual_router_names=()) -> RenderedMigration:
        actual_validation = validate_plan(plan)
        if validation is not None and validation != actual_validation:
            raise ValueError("validation result does not match this migration plan")
        validation = actual_validation
        allowed = validation.renderable_item_keys
        dispositions = dispositions or {}
        render_blockers = render_blockers or {}
        decision_keys = decision_keys or {}
        disposition = lambda item: dispositions.get(item_key(item), PANRenderDisposition.CREATE
            if item.status is PANMigrationStatus.SUPPORTED else PANRenderDisposition.BLOCK)
        can_create = lambda item: disposition(item) in {PANRenderDisposition.CREATE, PANRenderDisposition.CONFIGURE}
        def paths_for(item, factory):
            if disposition(item) is PANRenderDisposition.CONFIGURE:
                paths = (configure_paths or {}).get(item_key(item), ())
                if not paths:
                    raise ValueError("CONFIGURE requires validated additive command paths")
                return paths
            return factory(item)
        commands = []
        management_profiles = [(item, cli_paths.management_profile(item)) for item in plan.management_profiles
            if item.status is PANMigrationStatus.SUPPORTED and _key(item) in allowed and can_create(item)]
        interface_items = [
            (item, paths_for(item, cli_paths.interface))
            for item in plan.interfaces
            if item.status is PANMigrationStatus.SUPPORTED and _key(item) in allowed and can_create(item)
        ]
        interface_items.sort(key=lambda entry: bool(entry[0].parent))
        interface_pre = [
            (item, [path for path in paths if path[0] == "device_pre"])
            for item, paths in interface_items
        ]
        interface_pre = [(item, paths) for item, paths in interface_pre if paths]
        interface_imports = [
            (item, [path for path in paths if path[0] == "vsys"])
            for item, paths in interface_items
        ]
        interface_imports = [(item, paths) for item, paths in interface_imports if paths]
        interface_post = [
            (item, [path for path in paths if path[0] == "device_post"])
            for item, paths in interface_items
        ]
        interface_post = [(item, paths) for item, paths in interface_post if paths]

        scopes = (("addresses", cli_paths.address), ("address_groups", cli_paths.address_group),
                  ("services", cli_paths.service), ("service_groups", cli_paths.service_group),
                  ("schedules", cli_paths.schedule), ("zones", cli_paths.zone),
                  ("nat_rules", cli_paths.nat_rule), ("security_rules", cli_paths.security_rule))
        vsys_items = [*interface_imports, *[
            (item, paths_for(item, path)) for name, path in scopes for item in getattr(plan, name)
            if item.status is PANMigrationStatus.SUPPORTED and _key(item) in allowed and can_create(item)
        ]]
        vsys_commands = []
        item_commands = {
            _key(item): [_serialize(("vsys", item.target_vsys, *path[1:]))
                         if path[0] == "vsys" else _serialize(path[1:]) for path in paths]
            for item, paths in interface_items
        }
        for vsys in dict.fromkeys(item.target_vsys for item, _ in vsys_items if item.target_vsys is not None):
            scoped_items = [(item, paths) for item, paths in vsys_items if item.target_vsys == vsys]
            vsys_commands.extend(self._render_vsys_scope(vsys, scoped_items))
            for item, paths in scoped_items:
                item_commands.setdefault(_key(item), []).extend(
                    command for command in (_serialize(("vsys", vsys, *path[1:])) for path in paths)
                    if command not in item_commands.setdefault(_key(item), [])
                )
        routes = [(item, cli_paths.static_route(item)) for item in plan.static_routes
                  if item.status is PANMigrationStatus.SUPPORTED and _key(item) in allowed and can_create(item)]
        item_commands.update({_key(item): [_serialize(path[1:]) for path in paths] for item, paths in management_profiles})
        dhcp_servers = [(item, cli_paths.dhcp_server(item)) for item in plan.dhcp_servers
                        if item.status is PANMigrationStatus.SUPPORTED and _key(item) in allowed and can_create(item)]
        crypto_profiles = [(item, paths_for(item, path)) for family, path in (
            (plan.ike_crypto_profiles, cli_paths.ike_crypto_profile), (plan.ipsec_crypto_profiles, cli_paths.ipsec_crypto_profile))
            for item in family if item.status is PANMigrationStatus.SUPPORTED and _key(item) in allowed and can_create(item)]
        item_commands.update({_key(item): [_serialize(path[1:]) for path in paths] for item, paths in crypto_profiles})
        item_commands.update({_key(item): [_serialize(path[1:]) for path in paths] for item, paths in routes})
        item_commands.update({_key(item): [_serialize(path[1:]) for path in paths] for item, paths in dhcp_servers})
        commands.extend(self._render_device_scope(management_profiles))
        commands.extend(self._render_device_scope(interface_pre))
        commands[0:0] = [_serialize(("network", "virtual-router", name)) for name in dict.fromkeys(virtual_router_names)]
        commands.extend(vsys_commands)
        device_tail = [*interface_post, *dhcp_servers, *crypto_profiles, *routes]
        commands.extend(self._render_device_scope(device_tail))
        return RenderedMigration(tuple(commands), _report(plan, commands, validation, item_commands,
                                                          dispositions, render_blockers, decision_keys))

    def _render_vsys_scope(self, vsys, items):
        return [_serialize(("vsys", vsys, *path[1:])) for _, paths in items for path in paths]

    def _render_device_scope(self, items):
        if not items:
            return []
        commands = []
        commands.extend(_serialize(path[1:]) for _, paths in items for path in paths)
        return commands

    def write_files(self, rendered: RenderedMigration, output: str | Path) -> None:
        output = Path(output)
        output.mkdir(parents=True, exist_ok=True)
        (output / "palo_alto_config.set").write_text("\n".join(rendered.commands), encoding="utf-8")
        (output / "migration_report.json").write_text(json.dumps(rendered.report, indent=2), encoding="utf-8")

def _serialize(path):
    return "set " + " ".join(value if value in {"[", "]"} else _v(value) for value in path)


def _key(item):
    return (item.source_object_type, item.target_vsys, item.target_name or item.source_name)


def _exclusion_category(item, disposition, blockers, validation):
    """Explain exclusion without changing rendering or approval eligibility."""
    if disposition is not PANRenderDisposition.BLOCK:
        return 'INCLUDED'
    if any(fragment in warning for warning in item.warnings for fragment in (
            'explicit source IPv4 address could not be parsed safely',
            'could not be parsed as a static IPv4 address',
            'address subnet is not a valid explicit IPv4 subnet')):
        return 'SOURCE_DATA'
    if any(code in blockers for code in ('TARGET_SCOPE_CONFLICT', 'TARGET_MAPPING_CONFLICT',
            'TARGET_NAME_CONFLICT', 'TARGET_OBJECT_AMBIGUOUS', 'TARGET_RULE_PLACEMENT_UNVERIFIED')):
        return 'TARGET_CONFLICT'
    if item.status is not PANMigrationStatus.SUPPORTED:
        mapping_warnings = [warning for warning in item.warnings if warning.startswith((
            'missing target ', 'missing Palo Alto ', 'missing mapped target '))]
        if mapping_warnings and len(mapping_warnings) == len(item.warnings):
            return 'PREREQUISITE'
        return 'UNSUPPORTED'
    if 'DEPENDENCY_BLOCKED' in blockers or validation is not None and _key(item) not in validation.renderable_item_keys:
        return 'PREREQUISITE'
    if 'DESIGN_GROUP_NOT_APPROVED' in blockers:
        return 'NOT_APPROVED'
    return 'PREREQUISITE'


def _report(plan, commands, validation, item_commands=None, dispositions=None, render_blockers=None, decision_keys=None):
    items = list(_items(plan))
    command_text = "\n".join(commands)
    issue_counts = {}
    for issue in (validation.issues if validation else plan.issues):
        entry = issue_counts.setdefault(issue.code, {"code": issue.code, "message": issue.message, "count": 0})
        entry["count"] += 1
    counts = {status.value: sum(item.status is status for item in items) for status in PANMigrationStatus}
    digest = hashlib.sha256(command_text.encode("utf-8")).hexdigest()
    dispositions = dispositions or {}
    render_blockers = render_blockers or {}
    decision_keys = decision_keys or {}
    def disposition(item):
        if validation is not None and _key(item) not in validation.renderable_item_keys:
            return PANRenderDisposition.BLOCK
        return dispositions.get(item_key(item), PANRenderDisposition.CREATE
            if item.status is PANMigrationStatus.SUPPORTED else PANRenderDisposition.BLOCK)
    disposition_counts = {status.value: sum(disposition(item) is status
                                             for item in items) for status in PANRenderDisposition}
    if not disposition_counts["CONFIGURE"]:
        disposition_counts.pop("CONFIGURE")
    command_renderable = sum(disposition(item) in {PANRenderDisposition.CREATE, PANRenderDisposition.CONFIGURE} and
                              (validation is None or _key(item) in validation.renderable_item_keys)
                              for item in items)
    satisfied = sum(disposition(item) is PANRenderDisposition.REUSE or
                    disposition(item) in {PANRenderDisposition.CREATE, PANRenderDisposition.CONFIGURE} and
                    (validation is None or _key(item) in validation.renderable_item_keys)
                    for item in items)
    exclusions = [_exclusion_category(item, disposition(item),
        render_blockers.get(item_key(item), ()), validation) for item in items]
    validation_codes = {}
    for issue in validation.issues if validation else ():
        ref = issue.source
        validation_codes.setdefault((ref.source_vdom, ref.source_kind, ref.source_name, ref.source_policy_id), []).append(issue.code)
    return {"summary": {"counts": counts, "renderable": command_renderable,
                        "render_dispositions": disposition_counts, "satisfied": satisfied,
                        "command_renderable": command_renderable,
                        "commands": len(commands), "command_sha256": digest},
            "cli_compatibility": {"reference_version": "11.1", "verification": "DOCUMENTED_SYNTAX",
                                  "device_validation": "UNVERIFIED", "other_versions": "UNVERIFIED"},
            "counts": counts, "command_sha256": digest,
            "commands": len(commands), "render_dispositions": disposition_counts,
            "satisfied": satisfied, "command_renderable": command_renderable,
            "export_counts": dict(Counter(exclusions)),
            "issue_summary": list(issue_counts.values()),
            "items": [{"item_key": item_key(item), "source_vdom": item.source_vdom, "source_kind": item.source_kind, "source_name": item.source_name,
                        "source_policy_id": item.source_policy_id, "source_object_type": item.source_object_type,
                        "target_vsys": item.target_vsys, "target_name": item.target_name,
                        "status": item.status.value, "warnings": list(item.warnings),
                        "decision_keys": list(decision_keys.get(item_key(item), ())),
                        "render_disposition": disposition(item).value,
                        "export_category": category,
                        "satisfied": (disposition(item) is PANRenderDisposition.REUSE or
                                      disposition(item) in {PANRenderDisposition.CREATE, PANRenderDisposition.CONFIGURE} and item.status is PANMigrationStatus.SUPPORTED
                                      and (validation is None or _key(item) in validation.renderable_item_keys)),
                        "command_renderable": (disposition(item) in {PANRenderDisposition.CREATE, PANRenderDisposition.CONFIGURE}
                                               and item.status is PANMigrationStatus.SUPPORTED
                                               and (validation is None or _key(item) in validation.renderable_item_keys)),
                        "renderable": (disposition(item) in {PANRenderDisposition.CREATE, PANRenderDisposition.CONFIGURE}
                                       and item.status is PANMigrationStatus.SUPPORTED
                                       and (validation is None or _key(item) in validation.renderable_item_keys)),
                        "render_blockers": [*item.warnings, *render_blockers.get(item_key(item), ()), *validation_codes.get((item.source_vdom, item.source_kind, item.source_name, item.source_policy_id), ())],
                        "rendered": bool((item_commands or {}).get(_key(item))),
                        "commands": list((item_commands or {}).get(_key(item), ())) } for item, category in zip(items, exclusions)]}


def _items(plan):
    for name in ("addresses", "address_groups", "services", "service_groups", "schedules", "interfaces", "zones", "static_routes", "dhcp_servers", "security_rules", "nat_rules", "ike_crypto_profiles", "ipsec_crypto_profiles", 'ike_gateways', 'ipsec_tunnels', 'management_profiles'):
        yield from getattr(plan, name)
