"""Render approved ASA configuration commands without device operations."""

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path

from ..validation import dispositions, ordered_items, validate_plan


_ORDER = {"interface": 0, "address": 1, "nat_pool": 1, "address_group": 2, "service": 3,
          "service_group": 4, "schedule": 5, "static_route": 6, "nat": 7,
          "policy": 8, "default_behavior": 9, "acl_binding": 10}


@dataclass(frozen=True, slots=True)
class RenderedASA:
    commands: tuple[str, ...]
    command_text: str
    command_sha256: str
    report: dict

    @property
    def command_count(self):
        return len(self.commands)


class ASACLIRenderer:
    def render(self, plan, *, approved_items=None):
        validate_plan(plan)
        disposition = dispositions(plan)
        selected = None if approved_items is None else set(approved_items)
        if selected is not None and any(
            set(item.dependencies) - selected for item in plan.items if item.key in selected
        ):
            raise ValueError("ASA approved selection is missing required dependencies")
        if selected is not None and any(item.approval_group and any(
                row.approval_group == item.approval_group and row.key not in selected for row in plan.items)
                for item in plan.items if item.key in selected):
            raise ValueError("ASA approved selection is missing an atomic NAT group")
        rows = [item for item in ordered_items(plan, priority=lambda item: (
                    _ORDER.get(item.family, 50), bool(dict(item.settings).get("vlan_id")), item.source_order, item.key))
                if disposition[item.key] in {"CREATE", "REUSE"}
                and (selected is None or item.key in selected)]
        commands = []
        for item in rows:
            if disposition[item.key] == "CREATE":
                commands.extend(dict(item.settings).get("commands", ()))
        command_text = "\n".join(commands) + ("\n" if commands else "")
        command_sha = hashlib.sha256(command_text.encode("utf-8")).hexdigest()
        report_items = []
        for item in plan.items:
            blockers = list(item.blockers)
            if disposition[item.key] == "BLOCK" and not blockers:
                blockers.append("DEPENDENCY_BLOCKED")
            report_items.append({**asdict(item), "settings": dict(item.settings),
                                 "dependencies": list(item.dependencies), "blockers": blockers,
                                 "render_disposition": "NOT_APPROVED" if selected is not None
                                 and item.key not in selected and disposition[item.key] in {"CREATE", "REUSE"}
                                 else disposition[item.key]})
        create_count = sum(row["render_disposition"] == "CREATE" for row in report_items)
        reuse_count = sum(row["render_disposition"] == "REUSE" for row in report_items)
        omitted_count = sum(row["render_disposition"] == "NOT_APPROVED" for row in report_items)
        block_count = sum(row["render_disposition"] == "BLOCK" for row in report_items)
        if (create_count or reuse_count) and (block_count or omitted_count or any(row.blocking for row in plan.findings)):
            status = "READY_WITH_MANUAL_WORK"
        elif create_count or reuse_count:
            status = "READY_FOR_REVIEW"
        else:
            status = "BLOCKED"
        report = {
            "pair_id": "fortigate_to_cisco_asa",
            "source_vdom": plan.source_vdom,
            "target_context": plan.target_context,
            "target_version": plan.target_version,
            "target_mode": plan.target_mode,
            "plan_status": status,
            "renderable_item_count": create_count,
            "reused_item_count": reuse_count,
            "blocked_item_count": block_count,
            "not_approved_item_count": omitted_count,
            "items": report_items,
            "findings": [asdict(row) for row in plan.findings],
            "command_count": len(commands),
            "command_sha256": command_sha,
            "deployment_available": False,
            "destination_verified": False,
            "offline_export": True,
            "verification": "Offline ASA configuration export; hardware fit, existing bindings, routing adjacency, ARP behavior, licensing, and device acceptance require separate review.",
        }
        return RenderedASA(tuple(commands), command_text, command_sha, report)

    def write_files(self, rendered: RenderedASA, output):
        folder = Path(output)
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "asa_config.cfg").write_bytes(rendered.command_text.encode("utf-8"))
        (folder / "migration_report.json").write_text(json.dumps(rendered.report, indent=2), encoding="utf-8")
