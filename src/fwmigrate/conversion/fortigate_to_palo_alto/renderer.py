"""Deterministic Palo Alto set-command rendering."""

import json
import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from . import cli_paths
from .models import PANMigrationPlan, PANMigrationStatus
from .target_plan_validation import PANRenderDisposition, item_key
from .validation import MigrationValidationResult, validate_plan


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
               dispositions=None, render_blockers=None, decision_keys=None) -> RenderedMigration:
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
        can_create = lambda item: disposition(item) is PANRenderDisposition.CREATE
        commands = []
        interface_items = [
            (item, cli_paths.interface(item))
            for item in plan.interfaces
            if item.status is PANMigrationStatus.SUPPORTED and _key(item) in allowed and can_create(item)
        ]
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
            (item, path(item)) for name, path in scopes for item in getattr(plan, name)
            if item.status is PANMigrationStatus.SUPPORTED and _key(item) in allowed and can_create(item)
        ]]
        vsys_commands = []
        item_commands = {
            _key(item): [_serialize(path[1:]) for path in paths]
            for item, paths in interface_items
        }
        for vsys in dict.fromkeys(item.target_vsys for item, _ in vsys_items if item.target_vsys is not None):
            scoped_items = [(item, paths) for item, paths in vsys_items if item.target_vsys == vsys]
            vsys_commands.extend(self._render_vsys_scope(vsys, scoped_items))
            for item, paths in scoped_items:
                item_commands.setdefault(_key(item), []).extend(
                    command for command in (_serialize(path[1:]) for path in paths)
                    if command not in item_commands.setdefault(_key(item), [])
                )
        routes = [(item, cli_paths.static_route(item)) for item in plan.static_routes
                  if item.status is PANMigrationStatus.SUPPORTED and _key(item) in allowed and can_create(item)]
        item_commands.update({_key(item): [_serialize(path[1:]) for path in paths] for item, paths in routes})
        commands.extend(self._render_device_scope(interface_pre, reset_vsys=False))
        commands.extend(vsys_commands)
        device_tail = [*interface_post, *routes]
        commands.extend(self._render_device_scope(device_tail, reset_vsys=bool(vsys_commands)))
        return RenderedMigration(tuple(commands), _report(plan, commands, validation, item_commands,
                                                          dispositions, render_blockers, decision_keys))

    def _render_vsys_scope(self, vsys, items):
        return [f"set system setting target-vsys {_v(vsys)}", *(
            _serialize(path[1:]) for _, paths in items for path in paths
        )]

    def _render_device_scope(self, items, *, reset_vsys):
        if not items:
            return []
        commands = ["set system target-vsys none"] if reset_vsys else []
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
    disposition = lambda item: dispositions.get(item_key(item), PANRenderDisposition.CREATE
        if item.status is PANMigrationStatus.SUPPORTED else PANRenderDisposition.BLOCK)
    disposition_counts = {status.value: sum(disposition(item) is status
                                             for item in items) for status in PANRenderDisposition}
    command_renderable = sum(disposition(item) is PANRenderDisposition.CREATE and
                              (validation is None or _key(item) in validation.renderable_item_keys)
                              for item in items)
    satisfied = sum(disposition(item) is PANRenderDisposition.REUSE or
                    disposition(item) is PANRenderDisposition.CREATE and
                    (validation is None or _key(item) in validation.renderable_item_keys)
                    for item in items)
    return {"summary": {"counts": counts, "renderable": command_renderable,
                        "render_dispositions": disposition_counts, "satisfied": satisfied,
                        "command_renderable": command_renderable,
                        "commands": len(commands), "command_sha256": digest},
            "counts": counts, "command_sha256": digest,
            "commands": len(commands), "render_dispositions": disposition_counts,
            "satisfied": satisfied, "command_renderable": command_renderable,
            "issue_summary": list(issue_counts.values()),
            "items": [{"item_key": item_key(item), "source_vdom": item.source_vdom, "source_kind": item.source_kind, "source_name": item.source_name,
                        "source_policy_id": item.source_policy_id, "source_object_type": item.source_object_type,
                        "target_vsys": item.target_vsys, "target_name": item.target_name,
                        "status": item.status.value, "warnings": list(item.warnings),
                        "decision_keys": list(decision_keys.get(item_key(item), ())),
                        "render_disposition": disposition(item).value,
                        "satisfied": (disposition(item) is PANRenderDisposition.REUSE or
                                      disposition(item) is PANRenderDisposition.CREATE and item.status is PANMigrationStatus.SUPPORTED
                                      and (validation is None or _key(item) in validation.renderable_item_keys)),
                        "command_renderable": (disposition(item) is PANRenderDisposition.CREATE
                                               and item.status is PANMigrationStatus.SUPPORTED
                                               and (validation is None or _key(item) in validation.renderable_item_keys)),
                        "renderable": (disposition(item) is PANRenderDisposition.CREATE
                                       and item.status is PANMigrationStatus.SUPPORTED
                                       and (validation is None or _key(item) in validation.renderable_item_keys)),
                        "render_blockers": [*item.warnings, *render_blockers.get(item_key(item), ()), *(issue.code for issue in (validation.issues if validation else ()) if issue.source.source_name == item.source_name and issue.source.source_vdom == item.source_vdom)],
                        "rendered": bool((item_commands or {}).get(_key(item))),
                        "commands": list((item_commands or {}).get(_key(item), ())) } for item in items]}


def _items(plan):
    for name in ("addresses", "address_groups", "services", "service_groups", "schedules", "interfaces", "zones", "static_routes", "security_rules", "nat_rules"):
        yield from getattr(plan, name)
