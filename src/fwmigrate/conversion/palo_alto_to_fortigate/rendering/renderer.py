"""Render exactly the approved, dependency-satisfied FortiOS configuration."""
from collections import Counter
import hashlib
import json
from pathlib import Path

from ..models import FGRenderedMigration
from ..options import safe_text
from ..plan_dependencies import ordered_items, render_blockers
from ..validation import validate_plan


def quoted(value):
    safe_text(value, limit=4096, allow_empty=True)
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


class FGCLIRenderer:
    def render(self, plan, options, *, approved=None):
        validate_plan(plan)
        blockers = render_blockers(plan, approved)
        commands, rows = [], []
        # Cyclic or missing dependencies never produce commands, including independent siblings.
        try:
            ordered = ordered_items(plan)
        except ValueError:
            ordered = plan.items
            blockers = {i.key: (*blockers[i.key], "Invalid dependency graph.") for i in ordered}
        for item in ordered:
            reasons = blockers[item.key]
            disposition = "BLOCK" if reasons else item.disposition
            rows.append({**item.to_dict(), "render_disposition": disposition, "blocking_reasons": list(reasons),
                         "approved": approved is None or item.key in approved})
            if disposition not in {"CREATE", "CONFIGURE"}:
                continue
            multi = options.profile.get("vdom_mode") == "multi"
            if multi:
                commands.extend(("config global",) if item.global_scope else ("config vdom", "edit " + quoted(item.target_vdom)))
            commands.extend(("config " + item.section, "edit " + quoted(item.target_name)))
            for key, values in item.settings:
                if not values:
                    raise ValueError("Empty target setting cannot be rendered")
                commands.append("set " + key + " " + " ".join(quoted(value) for value in values))
            commands.extend(("next", "end"))
            if multi:
                commands.extend(("end",) if item.global_scope else ("next", "end"))
        counts = Counter(row["render_disposition"] for row in rows)
        status = "PARTIAL" if counts["BLOCK"] or plan.findings else "READY" if commands else "READY_NO_CHANGES"
        text = "\n".join(commands)
        report = {"source_vendor": "palo_alto", "target_vendor": "fortigate", "plan_status": status,
                  "items": rows, "findings": list(plan.findings), "render_summary": dict(counts),
                  "command_count": len(commands), "command_count_unit": "CLI lines", "command_sha256": hashlib.sha256(text.encode()).hexdigest(),
                  "deployment_eligibility": {"eligible": False, "reason": "FortiGate export only; live application is not implemented."}}
        return FGRenderedMigration(tuple(commands), report)

    def write_files(self, rendered, output):
        folder = Path(output)
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "fortigate_config.conf").write_bytes(rendered.text.encode("utf-8"))
        (folder / "migration_report.json").write_text(json.dumps(rendered.report, indent=2), encoding="utf-8")
