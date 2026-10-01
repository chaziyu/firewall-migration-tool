"""Editable review prefill from existing deterministic evidence."""

from dataclasses import replace

from ..decisions import PANDecisionMode, PANDecisionReviewState, PANMigrationDecisionSet


def apply_review_suggestions(decisions, results, *, candidates=None):
    updated = []
    for decision in decisions.decisions:
        if decision.review_state is PANDecisionReviewState.CONFIRMED or decision.mode in {
            PANDecisionMode.AUTO, PANDecisionMode.UNSUPPORTED,
        }:
            updated.append(decision)
            continue
        result = results.get(decision.key, {})
        status, value = result.get("status"), result.get("value")
        options = (candidates or {}).get(decision.key, ())
        matching = [item for item in options if item["value"] == (value or decision.suggested_value)]
        blocked = status in {"CANDIDATE", "CONFLICT"} or len(matching) > 1
        if decision.target_field == "target_interface":
            blocked = blocked or not (len(matching) == 1 and matching[0].get("class") == "STRONG"
                and matching[0].get("available", True) and not matching[0].get("contested"))
        if blocked:
            decision = replace(decision, suggested_value=None, value=None, mode=PANDecisionMode.REQUIRED,
                reason=result.get("reason") or "No unique, available target suggestion.",
                evidence_source=None, evidence_type=None, evidence_value=None, target_object=None,
                evidence_target_digest=None, evidence_target_device=None)
        elif status in {"VERIFIED", "DERIVED"} and value:
            uses_target = bool(result.get("uses_target_evidence"))
            existing_target_suggestion = uses_target and decision.evidence_source == "TARGET" and decision.suggested_value == value
            decision = replace(decision, suggested_value=value, value=None, mode=PANDecisionMode.SUGGESTED,
                reason=result["reason"], evidence_source="TARGET" if uses_target else "DERIVED",
                evidence_type=decision.evidence_type if existing_target_suggestion else f"REVIEW_{status}_SUGGESTION",
                evidence_value=decision.evidence_value if existing_target_suggestion else value,
                target_object=decision.target_object if existing_target_suggestion else value,
                evidence_target_digest=None, evidence_target_device=None)
        updated.append(decision)
    return PANMigrationDecisionSet(tuple(updated))
