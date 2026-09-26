"""Report target-aware conflicts and render dispositions."""

from dataclasses import dataclass
from enum import StrEnum

from .models import PANMigrationPlan
from .plan_dependencies import PANPlanDependencyIndex, expand_plan_dependents, item_key


class PANRenderDisposition(StrEnum):
    CREATE = "CREATE"
    REUSE = "REUSE"
    BLOCK = "BLOCK"


_REUSABLE = {"address", "address_group", "service", "service_group", "schedule"}


@dataclass(frozen=True, slots=True)
class PANTargetPlanFinding:
    code: str
    message: str
    source_vdom: str | None
    source_kind: str | None
    source_name: str | None
    target_name: str | None = None
    decision_key: str | None = None
    affected_item_keys: tuple[str, ...] = ()
    evidence: object = None

    def to_dict(self):
        return {"code": self.code, "message": self.message, "source_vdom": self.source_vdom,
                "source_kind": self.source_kind, "source_name": self.source_name,
                "target_name": self.target_name, "decision_key": self.decision_key,
                "affected_item_keys": list(self.affected_item_keys), "evidence": self.evidence}


def _items(plan):
    for family in ("addresses", "address_groups", "services", "service_groups", "schedules", "zones",
                   "static_routes", "security_rules", "nat_rules"):
        yield from getattr(plan, family)


def _reuse_code(status):
    return "TARGET_NAME_CONFLICT" if status == "NAME_CONFLICT" else "TARGET_OBJECT_AMBIGUOUS"


def _reuse_message(status, family, target_name):
    if status == "NAME_CONFLICT":
        return f"Target {family.replace('_', ' ')} '{target_name}' has explicit semantics that differ from the planned object."
    return f"Target {family.replace('_', ' ')} '{target_name}' cannot be confirmed as an exact match."


def validate_target_plan(plan: PANMigrationPlan, classifications, target_findings,
                         decisions, dependency_index: PANPlanDependencyIndex):
    """Convert target conflicts to findings without discovering relationships."""
    result = []
    for item in classifications:
        status = item.get("status")
        if status not in {"NAME_CONFLICT", "AMBIGUOUS", "EXACT_MATCH"}:
            continue
        if status == "EXACT_MATCH" and item.get("family") in _REUSABLE:
            continue
        family, name = item.get("family"), item.get("target_name")
        matches = [planned for planned in _items(plan) if planned.source_object_type == family
                   and (planned.source_vdom or "root") == (item.get("source_vdom") or "root")
                   and planned.source_kind == item.get("source_kind")
                   and planned.target_vsys == item.get("target_vsys")
                   and planned.source_name == item.get("source_name")]
        affected = expand_plan_dependents(dependency_index, (item_key(planned) for planned in matches))
        result.append(PANTargetPlanFinding(
            _reuse_code(status), _reuse_message(status, family or "target object", name),
            item.get("source_vdom"), matches[0].source_kind if matches else family,
            item.get("source_name"), name,
            affected_item_keys=affected,
            evidence=item.get("evidence")))
    decisions_by_key = {decision.key: decision for decision in decisions.decisions}
    for finding in target_findings:
        if finding.severity != "error":
            continue
        decision = decisions_by_key.get(finding.decision_key)
        affected = (expand_plan_dependents(dependency_index,
                    dependency_index.item_keys_by_decision.get(finding.decision_key, ())) if decision else ())
        result.append(PANTargetPlanFinding(
            "TARGET_SCOPE_CONFLICT" if finding.code == "TARGET_SCOPE_AMBIGUOUS" else "TARGET_MAPPING_CONFLICT",
            finding.message, decision.source_vdom if decision else None,
            decision.source_kind if decision else None, decision.source_name if decision else None,
            finding.target_object, finding.decision_key, affected,
            {"original_code": finding.code}))
    return tuple(result)


def assess_target_plan(plan: PANMigrationPlan, classifications, target_findings,
                       decisions, dependency_index: PANPlanDependencyIndex):
    """Apply target-aware dispositions to immutable planner output."""
    items = list(_items(plan))
    dispositions = {item_key(item): PANRenderDisposition.CREATE for item in items}
    blockers = {item_key(item): [] for item in items}
    by_identity = {(entry["family"], entry.get("source_vdom", "root"), entry.get("source_kind"),
                    entry.get("target_vsys"), entry.get("source_name")): entry
                   for entry in classifications}
    for item in items:
        family = item.source_object_type
        result = by_identity.get((family, item.source_vdom or "root", item.source_kind,
                                  item.target_vsys, item.source_name))
        if result:
            status = result.get("status")
            if status == "EXACT_MATCH" and family in _REUSABLE:
                dispositions[item_key(item)] = PANRenderDisposition.REUSE
            elif status in {"NAME_CONFLICT", "AMBIGUOUS", "EXACT_MATCH"}:
                dispositions[item_key(item)] = PANRenderDisposition.BLOCK
                blockers[item_key(item)].append(_reuse_code(status))
    for item in items:
        if item.status.value != "SUPPORTED":
            dispositions[item_key(item)] = PANRenderDisposition.BLOCK
            blockers[item_key(item)].append("PLAN_ITEM_UNSUPPORTED")
    initially_blocked = [key for key, disposition in dispositions.items()
                         if disposition is PANRenderDisposition.BLOCK]
    for key in expand_plan_dependents(dependency_index, initially_blocked):
        if key in dispositions and dispositions[key] is not PANRenderDisposition.BLOCK:
            dispositions[key] = PANRenderDisposition.BLOCK
            blockers[key].append("DEPENDENCY_BLOCKED")
    for finding in target_findings:
        if finding.severity != "error":
            continue
        for key in expand_plan_dependents(dependency_index,
                dependency_index.item_keys_by_decision.get(finding.decision_key, ())):
            if key in dispositions:
                dispositions[key] = PANRenderDisposition.BLOCK
                blockers[key].append("TARGET_SCOPE_CONFLICT" if finding.code == "TARGET_SCOPE_AMBIGUOUS"
                                     else "TARGET_MAPPING_CONFLICT")
    return dispositions, {key: list(dict.fromkeys(values)) for key, values in blockers.items() if values}
