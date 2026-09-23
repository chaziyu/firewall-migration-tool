"""Deterministic Palo Alto set-command rendering."""

import json
import re
from dataclasses import dataclass
from pathlib import Path

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


def _words(values):
    return " ".join(_v(value) for value in values)


def _prefix(item, path):
    return ["set", "vsys", _v(item.target_vsys), *path] if item.target_vsys else ["set", *path]


class PANSetRenderer:
    def render(self, plan: PANMigrationPlan, validation: MigrationValidationResult | None = None, **options) -> RenderedMigration:
        del options
        if validation is None and any(item.target_vsys for item in _items(plan)):
            validation = validate_plan(plan)
        allowed = validation.renderable_item_keys if validation else None
        commands = []
        for name in ("addresses", "address_groups", "services", "service_groups", "schedules", "zones", "static_routes", "nat_rules", "security_rules"):
            for item in getattr(plan, name):
                if item.status is not PANMigrationStatus.SUPPORTED or (allowed is not None and _key(item) not in allowed):
                    continue
                commands.extend(getattr(self, f"_render_{name}")(item))
        return RenderedMigration(tuple(commands), _report(plan, commands, validation))

    def render_files(self, plan: PANMigrationPlan, output: str | Path) -> RenderedMigration:
        validation = validate_plan(plan)
        rendered = self.render(plan, validation)
        output = Path(output)
        output.mkdir(parents=True, exist_ok=True)
        (output / "palo_alto_config.set").write_text("\n".join(rendered.commands) + "\n", encoding="utf-8")
        (output / "conversion_report.json").write_text(json.dumps(rendered.report, indent=2), encoding="utf-8")
        return rendered

    def _render_addresses(self, item):
        return [" ".join((*_prefix(item, ["address", _v(item.target_name or item.source_name)]), _v(item.address_type), _v(item.value)))]

    def _render_address_groups(self, item):
        return [" ".join((*_prefix(item, ["address-group", _v(item.target_name or item.source_name), "static"]), _v(member))) for member in item.members]

    def _render_services(self, item):
        result = [" ".join((*_prefix(item, ["service", _v(item.target_name or item.source_name), "protocol"]), _v(item.protocol)))]
        if item.destination_port:
            result.append(" ".join((*_prefix(item, ["service", _v(item.target_name or item.source_name), "port"]), _v(item.destination_port))))
        if item.source_port:
            result.append(" ".join((*_prefix(item, ["service", _v(item.target_name or item.source_name), "source-port"]), _v(item.source_port))))
        return result

    def _render_service_groups(self, item):
        return [" ".join((*_prefix(item, ["service-group", _v(item.target_name or item.source_name), "members"]), _v(member))) for member in item.members]

    def _render_schedules(self, item):
        base = ["schedule", _v(item.target_name or item.source_name)]
        if item.schedule_type in {"weekly", "recurring"}:
            return [" ".join((*_prefix(item, base + ["weekly", day, "start-time"]), _v(start))) for day, start, _ in item.weekly] + [" ".join((*_prefix(item, base + ["weekly", day, "end-time"]), _v(end))) for day, _, end in item.weekly]
        return [" ".join((*_prefix(item, base + ["non-recurring", start]), _v(end))) for start, end in item.non_recurring]

    def _render_zones(self, item):
        return [" ".join((*_prefix(item, ["zone", _v(item.target_name or item.source_name), "network", "layer3"]), _v(interface))) for interface in item.interfaces]

    def _render_routes(self, item):
        base = ["network", "virtual-router", _v(item.virtual_router), "routing-table", "ip", "static-route", _v(item.target_name or item.source_name)]
        result = [" ".join((*_prefix(item, base + ["destination"]), _v(item.destination)))]
        if item.interface: result.append(" ".join((*_prefix(item, base + ["interface"]), _v(item.interface))))
        if item.nexthop: result.append(" ".join((*_prefix(item, base + ["nexthop", item.nexthop_type or "ip-address"]), _v(item.nexthop))))
        if item.admin_distance is not None: result.append(" ".join((*_prefix(item, base + ["admin-dist"]), _v(item.admin_distance))))
        return result

    def _render_nat_rules(self, item):
        base = ["rulebase", "nat", "rules", _v(item.target_name or item.source_name)]
        result = []
        for key, values in (("from", item.from_zones), ("to", item.to_zones), ("source", item.source_addresses), ("destination", item.destination_addresses)):
            if values: result.append(" ".join((*_prefix(item, base + [key]), _words(values))))
        if item.service: result.append(" ".join((*_prefix(item, base + ["service"]), _v(item.service))))
        if item.to_interface: result.append(" ".join((*_prefix(item, base + ["to-interface"]), _v(item.to_interface))))
        if item.source_translation_type:
            path = base + ["source-translation", item.source_translation_type]
            if item.source_interface_address: result.append(" ".join((*_prefix(item, path + ["interface-address"]),)))
            for address in item.translated_addresses: result.append(" ".join((*_prefix(item, path + ["translated-address"]), _v(address))))
        if item.destination_translated_address: result.append(" ".join((*_prefix(item, base + ["destination-translation", "static-ip"]), _v(item.destination_translated_address))))
        return result

    def _render_security_rules(self, item):
        base = ["rulebase", "security", "rules", _v(item.target_name or item.source_name)]
        result = []
        for key, values in (("from", item.from_zones), ("to", item.to_zones), ("source", item.sources), ("destination", item.destinations), ("service", item.services)):
            result.append(" ".join((*_prefix(item, base + [key]), _words(values))))
        if item.schedule: result.append(" ".join((*_prefix(item, base + ["schedule"]), _v(item.schedule))))
        if item.negate_source: result.append(" ".join((*_prefix(item, base + ["negate-source"]), "yes")))
        if item.negate_destination: result.append(" ".join((*_prefix(item, base + ["negate-destination"]), "yes")))
        if item.disabled: result.append(" ".join((*_prefix(item, base + ["disabled"]), "yes")))
        if item.description: result.append(" ".join((*_prefix(item, base + ["description"]), _v(item.description))))
        if item.action: result.append(" ".join((*_prefix(item, base + ["action"]), _v(item.action))))
        return result


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
