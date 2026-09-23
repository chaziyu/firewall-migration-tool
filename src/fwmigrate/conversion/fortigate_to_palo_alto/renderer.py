"""Deterministic Palo Alto set-command rendering."""

import json
from dataclasses import dataclass
from pathlib import Path

from .models import PANMigrationPlan, PANMigrationStatus


@dataclass(frozen=True, slots=True)
class RenderedMigration:
    commands: tuple[str, ...]
    report: dict


class PANSetRenderer:
    def render(self, plan: PANMigrationPlan, **options) -> RenderedMigration:
        del options
        commands = []
        for item in plan.addresses:
            if item.status is PANMigrationStatus.SUPPORTED:
                commands.append(f"set address {item.source_name} {item.address_type} {item.value}")
        for item in plan.address_groups:
            if item.status is PANMigrationStatus.SUPPORTED:
                for member in item.members:
                    commands.append(f"set address-group {item.source_name} static {member}")
        for item in plan.services:
            if item.status is PANMigrationStatus.SUPPORTED:
                commands.append(f"set service {item.source_name} protocol {item.protocol} port {item.destination_port}")
        for item in plan.service_groups:
            if item.status is PANMigrationStatus.SUPPORTED:
                for member in item.members:
                    commands.append(f"set service-group {item.source_name} members {member}")
        for item in plan.zones:
            if item.status is PANMigrationStatus.SUPPORTED:
                for interface in item.interfaces:
                    commands.append(f"set zone {item.source_name} network layer3 {interface}")
        for item in plan.static_routes:
            if item.status is PANMigrationStatus.SUPPORTED:
                commands.append(f"set network virtual-router {item.virtual_router} routing-table ip static-route {item.source_name} destination {item.destination}")
        for item in plan.nat_rules:
            if item.status is PANMigrationStatus.SUPPORTED:
                commands.append(f"set rulebase nat rules {item.source_name} source-translation {item.source_translation}")
        for item in plan.security_rules:
            if item.status is PANMigrationStatus.SUPPORTED:
                commands.append(f"set rulebase security rules {item.source_name} action {item.action}")
        return RenderedMigration(tuple(commands), _report(plan, commands))

    def render_files(self, plan: PANMigrationPlan, output: str | Path) -> RenderedMigration:
        rendered = self.render(plan)
        output = Path(output)
        output.mkdir(parents=True, exist_ok=True)
        (output / "palo_alto_config.set").write_text("\n".join(rendered.commands) + "\n", encoding="utf-8")
        (output / "conversion_report.json").write_text(json.dumps(rendered.report, indent=2), encoding="utf-8")
        return rendered


def _report(plan, commands):
    items = [item for name in ("addresses", "address_groups", "services", "service_groups", "schedules", "zones", "static_routes", "security_rules", "nat_rules") for item in getattr(plan, name)]
    counts = {status.value: sum(item.status is status for item in items) for status in PANMigrationStatus}
    return {"counts": counts, "commands": len(commands), "issues": [issue.message for issue in plan.issues], "items": [{"name": item.source_name, "status": item.status.value, "warnings": list(item.warnings)} for item in items]}
