"""Stable design identity and exact, pair-owned approval selection."""

from dataclasses import asdict, replace
import hashlib
import json
import time

from ..models import SRXMigrationPlan
from ..options import SRXInterfaceMapping, SRXMigrationOptions
from ..plan_dependencies import validate_plan
from ..rendering.renderer import JunosSetRenderer


PAIR = {
    "pair_id": "fortigate_to_juniper_srx",
    "source_vendor": "fortigate",
    "target_vendor": "juniper_srx",
}
DRAFT_TYPE = "fortigate_to_juniper_srx_design_v1"
APPROVAL_TYPE = "fortigate_to_juniper_srx_approval_v1"
APPROVAL_TTL_SECONDS = 20 * 60


def options_mapping(options):
    parsed = options if isinstance(options, SRXMigrationOptions) else SRXMigrationOptions(**(options or {}))
    return {
        "source_vdom": parsed.source_vdom,
        "target_context": parsed.target_context,
        "target_version": parsed.target_version,
        "target_mode": parsed.target_mode,
        "routing_table": parsed.routing_table,
        "timezone": parsed.timezone,
        "interfaces": {
            vdom: {name: asdict(mapping if isinstance(mapping, SRXInterfaceMapping) else SRXInterfaceMapping(**mapping))
                   for name, mapping in mappings.items()}
            for vdom, mappings in parsed.interfaces.items()
        },
        "zones": {vdom: dict(mappings) for vdom, mappings in parsed.zones.items()},
    }


def _canonical_digest(value):
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _target_context(evidence):
    if evidence is None:
        return None
    return {
        "digest": evidence.digest,
        "context": evidence.context,
        "version": evidence.version,
        "mode": evidence.mode,
        "complete_families": sorted(evidence.complete_families),
    }


def build_deterministic_draft(plan: SRXMigrationPlan, source_digest, options, target_evidence=None):
    plan = validate_plan(plan)
    target = _target_context(target_evidence)
    context = {
        **PAIR,
        "source_digest": source_digest,
        "target_digest": target["digest"] if target else None,
        "target_evidence": target,
        "options": options_mapping(options),
    }
    content = {
        "context": context,
        "plan": asdict(plan),
    }
    return {
        "envelope_type": DRAFT_TYPE,
        **context,
        "context_digest": _canonical_digest(context),
        "digest": _canonical_digest(content),
        "items": [asdict(item) for item in plan.items],
        "findings": [asdict(finding) for finding in plan.findings],
    }


def _selected_plan(plan, selected_items):
    plan = validate_plan(plan)
    if not isinstance(selected_items, list) or not selected_items:
        raise ValueError("Select at least one complete migration item")
    if any(not isinstance(key, str) for key in selected_items):
        raise ValueError("Migration selection contains an invalid item key")
    if len(selected_items) != len(set(selected_items)):
        raise ValueError("Migration selection contains duplicate item keys")

    by_key = {item.key: item for item in plan.items}
    unknown = set(selected_items) - set(by_key)
    if unknown:
        raise ValueError("Migration selection contains unknown item keys")
    if any("PLAN_DEPENDENCY_CYCLE" in item.blockers or "PLAN_DEPENDENCY_UNRESOLVED" in item.blockers
           for item in plan.items):
        raise ValueError("The current migration dependency graph is invalid")
    if any(finding.code == "SOURCE_VALIDATION_ERRORS" and finding.blocking for finding in plan.findings):
        raise ValueError("Source validation errors block migration approval")
    if any(finding.source_kind == "target" and finding.blocking for finding in plan.findings):
        raise ValueError("Target scope or context is incomplete")

    groups = {}
    for item in plan.items:
        if item.approval_group:
            groups.setdefault(item.approval_group, set()).add(item.key)

    expanded = set(selected_items)
    changed = True
    while changed:
        changed = False
        for key in tuple(expanded):
            item = by_key[key]
            additions = set(item.dependencies)
            if item.approval_group:
                additions.update(groups[item.approval_group])
            if not additions <= expanded:
                expanded.update(additions)
                changed = True

    if expanded - set(by_key):
        raise ValueError("A selected migration dependency is unavailable")
    ordered_keys = tuple(item.key for item in plan.items if item.key in expanded)
    blocked = [by_key[key] for key in ordered_keys if by_key[key].blockers]
    if blocked:
        raise ValueError("A selected item, dependency or atomic review group is blocked")

    selected_plan = replace(plan, items=tuple(by_key[key] for key in ordered_keys))
    rendered = JunosSetRenderer().render(selected_plan)
    if rendered.blocked_items:
        raise ValueError("A selected item or dependency cannot be rendered safely")
    return ordered_keys, rendered


def approve_design(plan, draft, selected_items, target_evidence=None):
    current = build_deterministic_draft(
        plan, draft.get("source_digest"), draft.get("options", {}), target_evidence,
    )
    if (draft.get("envelope_type") != DRAFT_TYPE
            or any(draft.get(key) != value for key, value in PAIR.items())
            or draft.get("digest") != current["digest"]
            or draft.get("context_digest") != current["context_digest"]):
        raise ValueError("Draft changed; prepare and review the current migration again")
    selected, rendered = _selected_plan(plan, selected_items)
    return {
        "envelope_type": APPROVAL_TYPE,
        **PAIR,
        "source_digest": current["source_digest"],
        "target_digest": current["target_digest"],
        "draft_digest": current["digest"],
        "context_digest": current["context_digest"],
        "selected_items": list(selected),
        "command_count": rendered.command_count,
        "command_sha256": rendered.command_sha256,
        "expires_at": time.time() + APPROVAL_TTL_SECONDS,
    }


def validate_approval(plan, draft, approval):
    if not isinstance(approval, dict):
        raise ValueError("A current signed design approval is required")
    expires_at = approval.get("expires_at")
    if type(expires_at) not in {int, float} or time.time() >= expires_at:
        raise ValueError("Design approval has expired")
    if (approval.get("envelope_type") != APPROVAL_TYPE
            or any(approval.get(key) != value for key, value in PAIR.items())
            or approval.get("source_digest") != draft.get("source_digest")
            or approval.get("target_digest") != draft.get("target_digest")
            or approval.get("draft_digest") != draft.get("digest")
            or approval.get("context_digest") != draft.get("context_digest")):
        raise ValueError("Approval belongs to a different pair, source or design")
    selected, rendered = _selected_plan(plan, approval.get("selected_items"))
    if (approval.get("selected_items") != list(selected)
            or approval.get("command_count") != rendered.command_count
            or approval.get("command_sha256") != rendered.command_sha256):
        raise ValueError("Approved operations changed; review the current migration again")
    return selected, rendered


def export_decisions(source_digest, options):
    return {
        "format_version": 1,
        **PAIR,
        "source_digest": source_digest,
        "options": options_mapping(options),
    }


def import_decisions(document, source_digest):
    if (not isinstance(document, dict) or document.get("format_version") != 1
            or document.get("source_digest") != source_digest
            or any(document.get(key) != value for key, value in PAIR.items())):
        raise ValueError("Decision document belongs to a different pair, source or schema")
    # Imported mapping values are proposals; approval is always created separately.
    return export_decisions(source_digest, document.get("options", {}))["options"]
