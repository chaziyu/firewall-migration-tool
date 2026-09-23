"""Deterministic Palo Alto set-command rendering."""

import json
import re
from dataclasses import dataclass
from pathlib import Path

from . import cli_paths
from .models import PANMigrationPlan, PANMigrationStatus
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
    def render(self, plan: PANMigrationPlan, validation: MigrationValidationResult | None = None, **options) -> RenderedMigration:
        del options
        actual_validation = validate_plan(plan)
        if validation is not None and validation != actual_validation:
            raise ValueError("validation result does not match this migration plan")
        validation = actual_validation
        allowed = validation.renderable_item_keys
        commands = []
        scopes = (("addresses", cli_paths.address), ("address_groups", cli_paths.address_group),
                  ("services", cli_paths.service), ("service_groups", cli_paths.service_group),
                  ("schedules", cli_paths.schedule), ("zones", cli_paths.zone),
                  ("nat_rules", cli_paths.nat_rule), ("security_rules", cli_paths.security_rule))
        vsys_items = [(item, path(item)) for name, path in scopes for item in getattr(plan, name)
                      if item.status is PANMigrationStatus.SUPPORTED and _key(item) in allowed]
        vsys_commands = []
        for vsys in dict.fromkeys(item.target_vsys for item, _ in vsys_items if item.target_vsys is not None):
            vsys_commands.extend(self._render_vsys_scope(vsys, [(item, paths) for item, paths in vsys_items if item.target_vsys == vsys]))
        routes = [(item, cli_paths.static_route(item)) for item in plan.static_routes
                  if item.status is PANMigrationStatus.SUPPORTED and _key(item) in allowed]
        commands.extend(vsys_commands)
        commands.extend(self._render_device_scope(routes, reset_vsys=bool(vsys_commands)))
        return RenderedMigration(tuple(commands), _report(plan, commands, validation))

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

    def render_files(self, plan: PANMigrationPlan, output: str | Path) -> RenderedMigration:
        validation = validate_plan(plan)
        rendered = self.render(plan, validation)
        self.write_files(rendered, output)
        return rendered

    def write_files(self, rendered: RenderedMigration, output: str | Path) -> None:
        output = Path(output)
        output.mkdir(parents=True, exist_ok=True)
        (output / "palo_alto_config.set").write_text("\n".join(rendered.commands) + "\n", encoding="utf-8")
        (output / "conversion_report.json").write_text(json.dumps(rendered.report, indent=2), encoding="utf-8")

def _serialize(path):
    return "set " + " ".join(value if value in {"[", "]"} else _v(value) for value in path)


def _key(item):
    return (item.source_object_type, item.target_vsys, item.target_name or item.source_name)


def _report(plan, commands, validation):
    items = list(_items(plan))
    return {"counts": {status.value: sum(item.status is status for item in items) for status in PANMigrationStatus},
            "commands": len(commands), "issues": [issue.message for issue in (validation.issues if validation else plan.issues)],
            "items": [{"source_vdom": item.source_vdom, "source_kind": item.source_kind, "source_name": item.source_name,
                        "source_policy_id": item.source_policy_id, "target_vsys": item.target_vsys, "target_name": item.target_name,
                        "status": item.status.value, "warnings": list(item.warnings),
                        "rendered": item.status is PANMigrationStatus.SUPPORTED and (validation is None or _key(item) in validation.renderable_item_keys)} for item in items]}


def _items(plan):
    for name in ("addresses", "address_groups", "services", "service_groups", "schedules", "zones", "static_routes", "security_rules", "nat_rules"):
        yield from getattr(plan, name)
