"""Non-executable deterministic FortiGate -> PAN-OS review contracts."""
from dataclasses import asdict, dataclass
import hashlib
import json


def design_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=True).encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class PANDraftDecision:
    decision_key: str
    source_vdom: str
    source_kind: str
    source_name: str
    target_field: str
    proposed_value: str | None
    operation: str | None
    status: str
    target_scope: str | None
    dependencies: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()
    blocking_reasons: tuple[str, ...] = ()
    approved: bool = False

    def to_dict(self):
        return asdict(self)


@dataclass(frozen=True, slots=True)
class PANMigrationDraft:
    context: dict
    decisions: tuple[PANDraftDecision, ...]
    configuration: tuple[dict, ...]
    findings: tuple[dict, ...] = ()
    decision_state_digest: str | None = None

    def to_dict(self):
        body = {"envelope_type": "pan_migration_draft", "schema_version": 1,
                "decision_state_digest": self.decision_state_digest,
                "context": self.context, "decisions": [item.to_dict() for item in self.decisions],
                "configuration": list(self.configuration), "findings": list(self.findings),
                "destination_verified": self.context["reference_role"] == "DESTINATION"
                    and bool(self.context["reference_digest"] and self.context["target_device"])}
        body["issues"] = draft_issues(body["decisions"], body["configuration"])
        body['source_issues'] = [row for row in self.findings if row['code'].startswith('SOURCE_')]
        body['task_summary'] = {
            'choices': sum(row['category'] == 'CHOICE' for row in body['issues']),
            'prerequisites': sum(row['category'] == 'PREREQUISITE' for row in body['issues']),
            'conflicts': sum(row['category'] == 'CONFLICT' for row in body['issues']),
            'manual_items': sum(row['status'] == 'UNSUPPORTED' for row in self.configuration),
            'manual_issues': sum(row['category'] == 'MANUAL' for row in body['issues']),
        }
        missing = []
        for field in ("reference_digest", "target_device", "target_serial", "baseline_sha256", "baseline_format"):
            if not self.context.get(field):
                missing.append(field)
        if self.context["reference_role"] != "DESTINATION":
            missing.append("destination_evidence")
        body["readiness"] = {
            "coverage": {"supported": sum(row["status"] == "READY" for row in self.configuration),
                         "manual": sum(row["status"] == "UNSUPPORTED" for row in self.configuration)},
            "approval": "REVIEW_REQUIRED",
            "deployment": {"assessment": "PRE_ARTIFACT", "eligible": False,
                           "missing_prerequisites": missing},
        }
        body["digest"] = design_digest(body)
        return body


def draft_issues(decisions, configuration):
    """Pair-specific, scope-preserving root tasks; actions select current editable decisions."""
    rows = {row["decision_key"]: row for row in decisions}
    result = {}
    root_cache = {}
    affected_seen = {}
    source_seen = {}
    def roots(key, visiting=frozenset()):
        if key in root_cache:
            return root_cache[key]
        if key in visiting:
            return [key]
        parents = [parent for parent in rows[key]["dependencies"] if parent in rows and rows[parent]["status"] != "READY"]
        value = list(dict.fromkeys(root for parent in parents for root in roots(parent, visiting | {key}))) if parents else [key]
        root_cache[key] = value
        return value
    def add(code, category, row, explanation, resolution, decision=None, prerequisites=()):
        identity = (row.get("source_vdom"), code, decision or row.get("group_key") or row.get("decision_key"))
        key = design_digest(identity)
        root = rows.get(decision, row)
        if decision in rows:
            category = "MANUAL" if root["status"] == "UNSUPPORTED" else "CONFLICT" if root["status"] == "CONFLICT" else "CHOICE"
        summary = explanation
        if decision in rows and category != "MANUAL":
            field = {"vsys": "VSYS", "virtual_router": "virtual router",
                     "target_interface": "interface", "target_zone": "zone"}.get(root["target_field"], "value")
            summary = (f"Resolve the target {field} conflict for {root['source_name']}."
                       if category == "CONFLICT" else f"Assign a target {field} for {root['source_name']}.")
        issue = result.setdefault(key, {"id": key, "code": code, "category": category,
            "source_vdom": root.get("source_vdom"), "source_kind": root.get("source_kind"),
            "source_name": root.get("source_name"), "affected_keys": [], "affected_sources": [],
            "prerequisite_keys": list(prerequisites), "explanation": summary, "explanations": [],
            "resolution_kind": resolution,
            "action": {"kind": "EDIT_MAPPING", "decision_key": decision}
                if category != "MANUAL" and decision in rows and rows[decision]["status"] != "UNSUPPORTED" else None})
        affected = row.get("group_key") or row.get("decision_key")
        if explanation not in issue["explanations"]:
            issue["explanations"].append(explanation)
        if affected not in affected_seen.setdefault(key, set()):
            affected_seen[key].add(affected)
            issue["affected_keys"].append(affected)
        source_key = (row.get("source_vdom"), row.get("source_kind"), row.get("source_name"))
        if source_key not in source_seen.setdefault(key, set()):
            source_seen[key].add(source_key)
            issue["affected_sources"].append(dict(zip(("source_vdom", "source_kind", "source_name"), source_key)))
    for row in decisions:
        if row["status"] == "READY":
            continue
        parents = [key for key in row["dependencies"] if key in rows and rows[key]["status"] != "READY"]
        category = "MANUAL" if row["status"] == "UNSUPPORTED" else "CONFLICT" if row["status"] == "CONFLICT" else "PREREQUISITE" if parents else "CHOICE"
        for root in roots(row["decision_key"]):
            add("MAPPING_" + ("CONFLICT" if rows[root]["status"] == "CONFLICT" else "CHOICE"), category, row,
                "; ".join(row["blocking_reasons"]) or "Choose an explicit target value.",
                "MANUAL_IMPLEMENTATION" if category == "MANUAL" else "MAPPING", root, parents)
    for row in configuration:
        for cause in row.get("causes", ()):
            category = "CHOICE" if cause["resolution_type"] == "MISSING_MAPPING" and cause["decision_key"] in rows else "CONFLICT" if cause["resolution_type"] == "TARGET_CONFLICT" else "MANUAL"
            if category == "CHOICE":
                for root in roots(cause["decision_key"]):
                    add("MAPPING_" + ("CONFLICT" if rows[root]["status"] == "CONFLICT" else "CHOICE"),
                        category, row, cause["why"], cause["resolution_type"], root)
            else:
                add(cause["code"], category, row, cause["why"], cause["resolution_type"], cause["decision_key"])
        parents = [key for key in row["dependencies"] if key in rows and rows[key]["status"] != "READY"]
        for parent in dict.fromkeys(root for parent in parents for root in roots(parent)):
            add("MAPPING_" + ("CONFLICT" if rows[parent]["status"] == "CONFLICT" else "CHOICE"),
                "PREREQUISITE", row, "Resolve the related placement before reviewing dependent configuration.",
                "MAPPING", parent, [parent])
        if row["status"] != "READY" and not row.get("causes") and not parents:
            add("CONFIGURATION_" + row["status"], "MANUAL" if row["status"] == "UNSUPPORTED" else "CONFLICT" if row["status"] == "CONFLICT" else "PREREQUISITE",
                row, "; ".join(row["blocking_reasons"]), "MANUAL_IMPLEMENTATION" if row["status"] == "UNSUPPORTED" else "REVIEW", prerequisites=row["dependencies"])
    return list(result.values())
