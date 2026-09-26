"""Build allowlisted AI context from deterministic migration review results."""

import hashlib
import json

from .sanitizer import sanitize_ai_context

_SOURCE_FIELDS = ("source_type", "source_role", "source_parent", "source_vlan", "source_vrf", "source_members")
_CANDIDATE_EVIDENCE = ("strong_evidence", "supporting_evidence", "contradictions")


def _eligible_candidates(candidates):
    candidates = [item for item in candidates if isinstance(item, dict)
                  and isinstance(item.get("value"), str) and item["value"]
                  and str(item.get("match_class", item.get("class", ""))).upper() != "AMBIGUOUS"]
    scopes = {}
    for item in candidates:
        scope = item.get("scope_identity", item.get("target_scope"))
        if scope is not None:
            scopes.setdefault(item["value"], set()).add(scope)
    ambiguous = {value for value, identities in scopes.items() if len(identities) > 1}
    return [item for item in candidates if item["value"] not in ambiguous]


def build_ai_review_context(*, source_digest, target_digest, target_device, decisions, review_workflow,
                            review_context, decision_candidates, auto_decisions, target_findings,
                            operation, prompt_version, max_bytes=16000, max_groups=20):
    decision_by_key = {item.key: item for item in decisions.decisions}
    findings = {item.decision_key: item for item in target_findings}
    groups = []
    decision_refs = {}
    ai_candidates = {}
    for group in review_workflow.get("review_groups", ()):
        if group.get("queue") == "COMPLETE" or (operation == "questions" and group.get("queue") == "READY_TO_CONFIRM"):
            continue
        rows = []
        for item in group.get("decisions", ()):
            decision = decision_by_key.get(item.get("key"))
            auto_status = getattr(auto_decisions.get(item.get("key"), {}).get("status"), "value",
                                  auto_decisions.get(item.get("key"), {}).get("status", ""))
            if (decision is None or decision.review_state.value == "CONFIRMED"
                    or decision.mode.value in {"AUTO", "UNSUPPORTED"}):
                continue
            if auto_status in {"VERIFIED", "DERIVED"}:
                continue
            eligible = _eligible_candidates(decision_candidates.get(decision.key, ()))
            decision_ref = f"decision_{len(decision_refs) + 1}"
            decision_refs[decision_ref] = decision.key
            eligible = eligible[:8]
            ai_candidates[decision.key] = eligible
            values = list(dict.fromkeys(item["value"] for item in eligible))
            candidates = []
            for candidate in eligible:
                value = candidate["value"]
                evidence = []
                for field in _CANDIDATE_EVIDENCE:
                    facts = candidate.get(field, ())
                    if isinstance(facts, (list, tuple)):
                        evidence.extend(str(fact)[:128] for fact in facts[:8] if isinstance(fact, str))
                candidates.append({"value": value, "class": str(candidate.get("class", "")), "evidence": evidence[:8]})
            facts = review_context.get(decision.key, {})
            source_facts = {field: facts[field] for field in _SOURCE_FIELDS if field in facts and field != "source_members"}
            if "source_members" in facts:
                source_facts["source_members"] = {"present": True,
                    "count": len(facts["source_members"]) if isinstance(facts["source_members"], (list, tuple)) else 0}
            rows.append({
                "key": decision_ref,
                "target_field": decision.target_field,
                "mode": decision.mode.value,
                "review_state": decision.review_state.value,
                "allowed_values": values,
                "candidates": candidates,
                "source": source_facts,
                "target_finding": str(getattr(findings.get(decision.key), "code", "")) or None,
                "auto_status": str(auto_status),
            })
        if rows:
            groups.append({
                "source_vdom": group.get("source_vdom", ""),
                "source_kind": group.get("source_kind", ""),
                "source_name": group.get("source_name", ""),
                "queue": group.get("queue", "NEEDS_INPUT"),
                "affected_count": int(group.get("affected_count", 0) or 0),
                "decisions": rows,
            })

    total_groups = len(groups)
    priority = {"vdom": 0, "interface": 1, "zone": 2}
    groups.sort(key=lambda group: (-group["affected_count"], priority.get(group["source_kind"], 3),
                                   group["source_vdom"].casefold(), group["source_name"].casefold()))
    groups = groups[:max_groups]
    selected_keys = {item["key"] for group in groups for item in group["decisions"]}
    base = {
        "source_digest": source_digest,
        "target_digest": target_digest,
        "target_device": target_device,
        "operation": operation,
        "prompt_version": prompt_version,
        "groups": groups,
    }
    while groups and len(json.dumps(base, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=False).encode("utf-8")) > max_bytes:
        groups.pop()
        base["groups"] = groups
    selected_keys = {item["key"] for group in groups for item in group["decisions"]}
    safe = sanitize_ai_context(base, max_bytes=max_bytes)
    safe_allowed_values = {}
    for group in safe["groups"]:
        for decision in group["decisions"]:
            # Sanitization may replace an address-like target name. Such a value
            # is descriptive only and must not become a selectable assignment.
            original_key = decision_refs[decision["key"]]
            raw_values = {candidate["value"] for candidate in ai_candidates[original_key]}
            decision["allowed_values"] = [value for value in decision["allowed_values"] if value in raw_values]
            decision["candidates"] = [candidate for candidate in decision["candidates"]
                                       if candidate["value"] in decision["allowed_values"]]
            safe_allowed_values[decision["key"]] = tuple(decision["allowed_values"])
    decision_state = [{"key": item.key, "mode": item.mode.value, "review_state": item.review_state.value,
                       "value": item.value, "suggested_value": item.suggested_value,
                       "evidence_type": item.evidence_type, "evidence_value": item.evidence_value}
                      for item in decisions.decisions]
    state_identity = {"context": safe, "decision_state": decision_state,
                      "candidates": decision_candidates}
    digest = hashlib.sha256(json.dumps(state_identity, sort_keys=True, separators=(",", ":"),
                                       ensure_ascii=False, default=str).encode("utf-8")).hexdigest()
    return {"context": safe, "context_digest": digest, "allowed_values": safe_allowed_values,
            "decision_refs": {key: value for key, value in decision_refs.items() if key in selected_keys},
            "total_groups": total_groups, "analyzed_groups": len(groups)}
