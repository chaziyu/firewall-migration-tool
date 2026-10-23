"""Render a reviewed Cisco FMC REST API request specification."""

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import re

from ..plan_dependencies import dispositions, ordered_items, validate_plan
from .commands import render_fmc_curl_commands


OPERATION_FILE = "cisco_fmc_operations.json"
BINDINGS_FILE = "cisco_fmc_bindings.json"
CURL_FILE = "cisco_fmc_curl.sh"
INSTRUCTIONS_FILE = "ftd_application_instructions.txt"
REPORT_FILE = "migration_report.json"


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
class RenderedFMC:
    operations_text: str
    bindings_text: str
    instructions_text: str
    report: dict
    file_hashes: dict[str, str]
    operation_count: int
    curl_text: str | None = None

    @property
    def files(self):
        files = {
            OPERATION_FILE: self.operations_text.encode("utf-8"),
            BINDINGS_FILE: self.bindings_text.encode("utf-8"),
            INSTRUCTIONS_FILE: self.instructions_text.encode("utf-8"),
        }
        if self.curl_text is not None:
            files[CURL_FILE] = self.curl_text.encode("utf-8")
        return files


class FMCRequestRenderer:
    """Emit FMC REST API request templates; this class never sends requests."""

    def render(self, plan, *, approved_items=None):
        validate_plan(plan)
        state = dispositions(plan)
        selected = None if approved_items is None else set(approved_items)
        by_key = {item.key: item for item in plan.items}
        if selected is not None and any(
            key not in by_key or state[key] == "BLOCK"
            or not set(by_key[key].dependencies) <= selected
            for key in selected
        ):
            raise ValueError("Cisco FTD selection contains blocked or missing dependencies")

        existing_ids = {
            f"{item.key}.id": dict(item.settings)["target_id"]
            for item in plan.items
            if state[item.key] == "REUSE" and "target_id" in dict(item.settings)
        }

        def resolve_ids(value):
            if isinstance(value, dict):
                if set(value) == {"$response_binding"} and value["$response_binding"] in existing_ids:
                    return existing_ids[value["$response_binding"]]
                return {k: resolve_ids(v) for k, v in value.items()}
            if isinstance(value, (tuple, list)):
                return [resolve_ids(item) for item in value]
            return value

        def resolve_ids_in_path(path):
            res = path
            for bind_key, uid in existing_ids.items():
                pattern = r"\{\$response_binding:\s*" + re.escape(bind_key) + r"\}"
                res = re.sub(pattern, uid, res)
            return res

        fmc_keys = {
            item.key for item in plan.items
            if state[item.key] == "CREATE" and dict(item.settings).get("fmc_operation")
        }
        operations, bindings = [], []
        for item in ordered_items(plan):
            if state[item.key] != "CREATE" or (selected is not None and item.key not in selected):
                continue
            operation = dict(item.settings).get("fmc_operation")
            if not operation:
                continue
            binding = operation.get("response_binding")
            if binding:
                bindings.append({**binding, "operation_id": item.key})
            operations.append({
                "operation_id": item.key,
                "source": {
                    "scope": item.source_scope,
                    "kind": item.source_kind or item.family,
                    "name": item.source_name,
                    "path": item.source_path,
                },
                "method": "POST",
                "path": resolve_ids_in_path(operation["path"]),
                "request_body_template": resolve_ids(operation["request_body_template"]),
                "response_binding": binding,
                "depends_on": [key for key in item.dependencies if key in fmc_keys],
                "policy_context": operation.get("policy_context"),
            })

        options = plan.options
        curl_text = (render_fmc_curl_commands(operations, manager_target=options.get("manager_target"),
                                             domain_id=options.get("domain_id"))
                     if options.get("target_mode") == "new" else None)

        operations_spec = {
            "format": "cisco_fmc_rest_api_request_spec_v1",
            "api_version": options.get("fmc_api_version", "7.7.0"),
            "target": {
                "manager_target": options.get("manager_target"),
                "domain_id": options.get("domain_id"),
                "domain_name": options.get("domain_name"),
                "policy_name": options.get("policy_name"),
            },
            "operation_count": len(operations),
            "execution": "Reviewed request specification only. No authentication, token storage, request execution, policy assignment, or deployment is included.",
            "response_binding_instructions": "Capture the returned object ID at each json_pointer and substitute into dependent requests before sending.",
            "operations": operations,
        }

        instructions_lines = [
            "==================================================================",
            " Cisco Secure Firewall Threat Defense (FTD) Migration Instructions",
            " Target: FMC REST API Version 7.7.0 (FMC-Managed FTD)",
            "==================================================================",
            "",
            "1. FMC Management Authentication & Target Domain:",
            "   - Ensure access to Cisco Secure Firewall Management Center 7.7.",
            f"   - Approved FMC host: {options.get('manager_target') or '(required)'}. Recheck its identity before applying.",
            f"   - Target Domain: {options.get('domain_name') or '(optional name)'} (UUID: {options.get('domain_id') or '(required)'}).",
            "   - Generate an FMC REST API authentication token via POST /api/fmc_platform/v1/auth/generatetoken.",
            "",
            "2. Execute FMC Object & Policy Operations:",
            "   - Follow the sequence defined in cisco_fmc_operations.json.",
            "   - Or run bash cisco_fmc_curl.sh [TOKEN_FILE] with Python 3.11+ in an authorized environment.",
            "   - Without TOKEN_FILE, the script prompts privately. Never pass the token itself as an argument.",
            "   - The script is bound to the approved host/domain; TLS verification is enabled and redirects are rejected.",
            "   - Requests stop on HTTP, response or binding errors. No automatic retries: reconcile partial changes first.",
            "   - Each operation captures returned IDs for dependent access control rules.",
            "",
            "3. Security Zone to Device Interface Assignment (Required):",
            "   - FMC security zones must be associated with target FTD physical or sub-interfaces.",
            "   - Navigate to: Devices > Device Management > [Your FTD Device] > Interfaces.",
            "   - Assign each created Security Zone (inside, outside, etc.) to the respective interface.",
            "   - Without interface assignment, the Access Control Policy will not process traffic.",
            "",
            "4. Access Control Policy Assignment & Deployment:",
            f"   - Migrated Access Control Policy: {options.get('policy_name', 'PAN_Migrated_ACP')}.",
            "   - Navigate to: Policies > Access Control.",
            "   - Under Policy Management, assign the policy to the target FTD device.",
            "   - Click Deploy to push the policy to the managed FTD device.",
            "",
            "5. Manual Verifications:",
            "   - NAT, routing, and deep inspection profiles (IPS/File/URL) must be reviewed manually.",
            "   - Pre-existing active NAT rules and App-ID rules were not automatically converted.",
            "",
        ]
        instructions_text = "\n".join(instructions_lines)

        operations_bytes = _json_bytes(operations_spec)
        instructions_bytes = instructions_text.encode("utf-8")
        operations_hash = hashlib.sha256(operations_bytes).hexdigest()
        instructions_hash = hashlib.sha256(instructions_bytes).hexdigest()

        manifest = {
            "format": "palo_alto_to_cisco_ftd_binding_manifest_v1",
            "source_vendor": "palo_alto",
            "target_vendor": "cisco_ftd",
            "source_scope": plan.source_scope,
            "fmc": {
                "manager_target": options.get("manager_target"),
                "domain_id": options.get("domain_id"),
                "domain_name": options.get("domain_name"),
                "api_version": options.get("fmc_api_version", "7.7.0"),
                "policy_name": options.get("policy_name"),
                "target_device_id": options.get("target_device_id"),
                "target_device_name": options.get("target_device_name"),
            },
            "files": {
                OPERATION_FILE: {"sha256": operations_hash, "byte_count": len(operations_bytes)},
                INSTRUCTIONS_FILE: {"sha256": instructions_hash, "byte_count": len(instructions_bytes)},
            },
            "response_bindings": bindings,
            "deferred_application_bindings": [
                key for key in ("manager_target", "domain_id", "domain_name", "target_device_id")
                if not options.get(key)
            ],
            "manual_checks": [
                "Confirm FMC REST API version 7.7.0 and target domain UUID before executing requests.",
                "Assign imported Security Zones to target FTD device interfaces before traffic can be enforced.",
                "Assign the migrated Access Control Policy to the target FTD device and deploy via FMC.",
                "Verify NAT policies and static routing manually; live execution remains manual.",
            ],
        }

        if curl_text is not None:
            curl_bytes = curl_text.encode("utf-8")
            manifest["files"][CURL_FILE] = {
                "sha256": hashlib.sha256(curl_bytes).hexdigest(),
                "byte_count": len(curl_bytes),
            }

        bindings_bytes = _json_bytes(manifest)
        bindings_hash = hashlib.sha256(bindings_bytes).hexdigest()

        records = [_item_record(item, state[item.key]) for item in plan.items]
        for record in records:
            if selected is not None and record["render_disposition"] in {"CREATE", "REUSE"} and record["key"] not in selected:
                record["render_disposition"] = "NOT_APPROVED"

        counts = {
            name: sum(record["render_disposition"] == name for record in records)
            for name in ("CREATE", "REUSE", "BLOCK", "NOT_APPROVED")
        }
        satisfied = counts["CREATE"] + counts["REUSE"]
        status = (
            "READY_WITH_MANUAL_WORK"
            if satisfied and (counts["BLOCK"] or counts["NOT_APPROVED"] or plan.findings)
            else ("READY_FOR_REVIEW" if satisfied else "BLOCKED")
        )

        report = {
            "pair_id": "palo_alto_to_cisco_ftd",
            "source_vendor": "palo_alto",
            "target_vendor": "cisco_ftd",
            "source_scope": plan.source_scope,
            "manager_target": options.get("manager_target"),
            "domain_id": options.get("domain_id"),
            "domain_name": options.get("domain_name"),
            "fmc_api_version": options.get("fmc_api_version", "7.7.0"),
            "policy_name": options.get("policy_name"),
            "target_device_id": options.get("target_device_id"),
            "target_device_name": options.get("target_device_name"),
            "plan_status": status,
            "items": records,
            "findings": [asdict(row) for row in plan.findings],
            "render_summary": counts,
            "fmc_operation_count": len(operations),
            "file_sha256": {
                OPERATION_FILE: operations_hash,
                INSTRUCTIONS_FILE: instructions_hash,
                BINDINGS_FILE: bindings_hash,
            },
            "destination_snapshot_compared": False,
            "destination_verified": False,
            "export_mode": "reviewed_offline_bundle",
            "deployment_available": False,
            "verification": "Cisco FMC REST API requests and application instructions are separate reviewed files. Target interface-to-zone assignment, policy assignment, and deployment require manual review.",
        }

        if curl_text is not None:
            report["file_sha256"][CURL_FILE] = manifest["files"][CURL_FILE]["sha256"]
            report["target_mode"] = "new"

        return RenderedFMC(
            operations_text=operations_bytes.decode("utf-8"),
            bindings_text=bindings_bytes.decode("utf-8"),
            instructions_text=instructions_text,
            report=report,
            file_hashes=report["file_sha256"],
            operation_count=len(operations),
            curl_text=curl_text,
        )

    def write_files(self, rendered: RenderedFMC, output):
        folder = Path(output)
        folder.mkdir(parents=True, exist_ok=True)
        for name, contents in rendered.files.items():
            (folder / name).write_bytes(contents)
        (folder / REPORT_FILE).write_bytes(_json_bytes(rendered.report))
