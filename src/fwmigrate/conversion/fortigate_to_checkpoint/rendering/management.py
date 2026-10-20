"""Render a reviewed Check Point Management API request specification."""

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path

from ..plan_dependencies import dispositions, ordered_items, validate_plan
from .commands import render_management_commands


MANAGEMENT_FILE = "checkpoint_management_operations.json"
GAIA_FILE = "gaia_config.clish"
BINDINGS_FILE = "checkpoint_bindings.json"
REPORT_FILE = "migration_report.json"
COMMANDS_FILE = "checkpoint_management.sh"


def _json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _item_record(item, disposition):
    row = asdict(item)
    row["settings"] = dict(item.settings)
    row["dependencies"] = list(item.dependencies)
    row["blockers"] = list(item.blockers or (() if disposition != "BLOCK" else ("DEPENDENCY_BLOCKED",)))
    row["render_disposition"] = disposition
    return row


@dataclass(frozen=True, slots=True)
class RenderedCheckPoint:
    management_text: str
    gaia_text: str
    bindings_text: str
    report: dict
    file_hashes: dict[str, str]
    operation_count: int
    gaia_command_count: int
    commands_text: str | None = None

    @property
    def files(self):
        files = {
            MANAGEMENT_FILE: self.management_text.encode("utf-8"),
            GAIA_FILE: self.gaia_text.encode("utf-8"),
            BINDINGS_FILE: self.bindings_text.encode("utf-8"),
        }
        if self.commands_text is not None:
            files[COMMANDS_FILE] = self.commands_text.encode("utf-8")
        return files


class CPManagementRenderer:
    """Emit API request templates; this class never sends requests."""

    def render(self, plan, *, approved_items=None):
        validate_plan(plan)
        state = dispositions(plan)
        selected = None if approved_items is None else set(approved_items)
        by_key = {item.key: item for item in plan.items}
        if selected is not None and any(key not in by_key or state[key] == "BLOCK"
                or not set(by_key[key].dependencies) <= selected for key in selected):
            raise ValueError("Check Point selection contains blocked or missing dependencies")
        existing_uids = {f"{item.key}.uid": dict(item.settings)["target_uid"]
                         for item in plan.items if state[item.key] == "REUSE"}

        def resolve_uids(value):
            if isinstance(value, dict):
                if set(value) == {"$response_binding"} and value["$response_binding"] in existing_uids:
                    return existing_uids[value["$response_binding"]]
                return {key: resolve_uids(child) for key, child in value.items()}
            if isinstance(value, (tuple, list)):
                return [resolve_uids(child) for child in value]
            return value

        management_keys = {item.key for item in plan.items
                           if state[item.key] == "CREATE" and dict(item.settings).get("management_operation")}
        operations, bindings = [], []
        for item in ordered_items(plan):
            if state[item.key] != "CREATE" or (selected is not None and item.key not in selected):
                continue
            operation = dict(item.settings).get("management_operation")
            if not operation:
                continue
            binding = operation.get("response_binding")
            if binding:
                bindings.append({**binding, "operation_id": item.key})
            operations.append({
                "operation_id": item.key,
                "source": {"vdom": item.source_vdom, "kind": item.family, "name": item.source_name},
                "method": "POST",
                "path": operation["path"],
                "request_body_template": resolve_uids(operation["request_body_template"]),
                "response_binding": binding,
                "depends_on": [key for key in item.dependencies if key in management_keys],
                "policy_context": operation.get("policy_context"),
            })
        options = plan.options
        commands_text = render_management_commands(operations) if options.get("target_mode") == "new" else None
        management = {
            "format": "check_point_management_api_request_spec_v1",
            "api_version": options["management_api_version"],
            "target": {"management_target": options["management_target"],
                       "domain": options["management_domain"]},
            "operation_count": len(operations),
            "execution": "Reviewed request specification only. No authentication, session creation, request execution, publish, or policy installation is included.",
            "response_binding_instructions": "After a successful operation, capture the response value at each json_pointer under binding_id. Replace every $response_binding template marker with that returned UID before dependent requests.",
            "operations": operations,
        }
        gaia_lines = []
        for item in ordered_items(plan):
            if state[item.key] != "CREATE" or (selected is not None and item.key not in selected):
                continue
            gaia_lines.extend(dict(item.settings).get("gaia_commands", ()))
        gaia_text = "\n".join(gaia_lines) + ("\n" if gaia_lines else "")
        management_bytes = _json_bytes(management)
        gaia_bytes = gaia_text.encode("utf-8")
        management_hash = hashlib.sha256(management_bytes).hexdigest()
        gaia_hash = hashlib.sha256(gaia_bytes).hexdigest()
        manifest = {
            "format": "fortigate_to_checkpoint_binding_manifest_v1",
            "source_vendor": "fortigate",
            "target_vendor": "checkpoint",
            "source_vdom": plan.source_vdom,
            "management": {"target": options["management_target"],
                           "domain": options["management_domain"],
                           "api_version": options["management_api_version"],
                           "policy_package": options["policy_package"],
                           "access_layer": options["access_layer"],
                           "install_on": options["install_on"]},
            "gaia": {"target": options["gaia_target"]},
            "files": {MANAGEMENT_FILE: {"sha256": management_hash, "byte_count": len(management_bytes)},
                      GAIA_FILE: {"sha256": gaia_hash, "byte_count": len(gaia_bytes)}},
            "response_bindings": bindings,
            "manual_checks": [
                "Confirm the Management Domain, package, layer, object-name availability, and cleanup anchor in the destination snapshot.",
                "Confirm gateway topology, interface addressing, anti-spoofing, and route conflicts before Gaia changes.",
                "Review both files together. Management policy objects and Gaia configuration do not activate or assign each other.",
            ],
        }
        if commands_text is not None:
            manifest["manual_checks"][0] = "Use an existing API session in the intended Management Domain. New package/object names must be unused. Select gateways and review topology before publishing and installing policy."
            manifest["files"][COMMANDS_FILE] = {
                "sha256": hashlib.sha256(commands_text.encode("utf-8")).hexdigest(),
                "byte_count": len(commands_text.encode("utf-8")),
            }
        bindings_bytes = _json_bytes(manifest)
        bindings_hash = hashlib.sha256(bindings_bytes).hexdigest()
        records = [_item_record(item, state[item.key]) for item in plan.items]
        for record in records:
            if selected is not None and record["render_disposition"] in {"CREATE", "REUSE"} and record["key"] not in selected:
                record["render_disposition"] = "NOT_APPROVED"
        counts = {name: sum(record["render_disposition"] == name for record in records)
                  for name in ("CREATE", "REUSE", "BLOCK", "NOT_APPROVED")}
        satisfied = counts["CREATE"] + counts["REUSE"]
        status = "READY_WITH_MANUAL_WORK" if satisfied and (counts["BLOCK"] or counts["NOT_APPROVED"] or plan.findings) else (
            "READY_FOR_REVIEW" if satisfied else "BLOCKED")
        report = {
            "pair_id": "fortigate_to_checkpoint",
            "source_vendor": "fortigate",
            "target_vendor": "checkpoint",
            "source_vdom": plan.source_vdom,
            "management_target": options["management_target"],
            "management_domain": options["management_domain"],
            "management_api_version": options["management_api_version"],
            "gaia_target": options["gaia_target"],
            "plan_status": status,
            "items": records,
            "findings": [asdict(row) for row in plan.findings],
            "render_summary": counts,
            "management_operation_count": len(operations),
            "gaia_command_count": len(gaia_lines),
            "file_sha256": {MANAGEMENT_FILE: management_hash, GAIA_FILE: gaia_hash,
                            BINDINGS_FILE: bindings_hash},
            "destination_snapshot_compared": False,
            "destination_verified": False,
            "export_mode": "reviewed_offline_bundle",
            "deployment_available": False,
            "verification": "Check Point Management API requests and Gaia commands are separate reviewed files. Destination conflicts, gateway topology, anti-spoofing, activation, and device acceptance require manual review.",
        }
        if commands_text is not None:
            report["file_sha256"][COMMANDS_FILE] = manifest["files"][COMMANDS_FILE]["sha256"]
            report["target_mode"] = "new"
        return RenderedCheckPoint(management_bytes.decode("utf-8"), gaia_text,
                                  bindings_bytes.decode("utf-8"), report,
                                  report["file_sha256"], len(operations), len(gaia_lines), commands_text)

    def write_files(self, rendered: RenderedCheckPoint, output):
        folder = Path(output)
        folder.mkdir(parents=True, exist_ok=True)
        for name, contents in rendered.files.items():
            (folder / name).write_bytes(contents)
        (folder / REPORT_FILE).write_bytes(_json_bytes(rendered.report))
