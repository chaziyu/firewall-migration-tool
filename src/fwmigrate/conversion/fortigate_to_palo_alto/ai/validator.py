"""Semantic validation against the current deterministic review state."""

from fwmigrate.ai.errors import AIInvalidResponseError


def _text(value, name):
    if not isinstance(value, str) or not value.strip() or len(value) > 512:
        raise AIInvalidResponseError(f"AI response has invalid {name}")
    return value.strip()


def validate_analysis_output(output, *, groups, allowed_values, max_results=8):
    """Validate advisory results against closed candidates and their exact evidence."""
    from .models import PANAIAssistKind

    if not isinstance(output, dict) or not isinstance(output.get("results"), list):
        raise AIInvalidResponseError("AI response has invalid analysis results")
    key_to_group = {item["key"]: group for group in groups for item in group["decisions"]}
    candidate_evidence = {}
    for group in groups:
        for decision in group["decisions"]:
            candidate_evidence[decision["key"]] = {
                item["value"]: set(item.get("evidence", ())) for item in decision.get("candidates", ())
            }
    results = output["results"]
    if len(results) > max_results:
        raise AIInvalidResponseError("AI returned too many analysis results")
    validated = []
    for item in results:
        if not isinstance(item, dict):
            raise AIInvalidResponseError("AI response has an invalid analysis result")
        try:
            kind = PANAIAssistKind(item.get("kind"))
        except (TypeError, ValueError) as exc:
            raise AIInvalidResponseError("AI response has an unsupported result kind") from exc
        keys = item.get("decision_keys")
        if (not isinstance(keys, list) or not keys or len(keys) > 8
                or any(not isinstance(key, str) for key in keys)
                or len(set(keys)) != len(keys)
                or any(key not in key_to_group for key in keys)):
            raise AIInvalidResponseError("AI result references an unknown decision")
        identities = {(key_to_group[key]["source_vdom"], key_to_group[key]["source_kind"], key_to_group[key]["source_name"])
                      for key in keys}
        if len(identities) != 1:
            raise AIInvalidResponseError("AI result combines unrelated review groups")
        assignments = item.get("assignments")
        choices = item.get("choices")
        comparisons = item.get("comparisons")
        if not isinstance(assignments, list) or not isinstance(choices, list) or len(choices) > 8:
            raise AIInvalidResponseError("AI result has invalid assignments or choices")
        checked_assignments = _validate_assignments(assignments, keys, allowed_values)
        checked_choices = []
        for choice in choices:
            if not isinstance(choice, dict):
                raise AIInvalidResponseError("AI result has an invalid choice")
            choice_assignments = _validate_assignments(choice.get("assignments"), keys, allowed_values)
            if not choice_assignments:
                raise AIInvalidResponseError("AI choice must assign a supplied candidate")
            checked_choices.append({"label": _text(choice.get("label"), "choice label"),
                                    "assignments": choice_assignments})
        evidence = _strings(item.get("evidence"), "evidence")
        checked_comparisons = []
        if not isinstance(comparisons, list):
            raise AIInvalidResponseError("AI result has invalid comparisons")
        if kind is PANAIAssistKind.MAPPING_RECOMMENDATION:
            if not checked_assignments or checked_choices or comparisons:
                raise AIInvalidResponseError("AI mapping recommendation must contain exactly one assignment set")
            assignment_evidence = [candidate_evidence[item["decision_key"]].get(item["value"], set())
                                   for item in checked_assignments]
            valid_evidence = set().union(*assignment_evidence)
            if (not evidence or not set(evidence).issubset(valid_evidence)
                    or any(not facts.intersection(evidence) for facts in assignment_evidence)):
                raise AIInvalidResponseError("AI recommendation contains unsupported evidence")
            choices_for_proposal = [{"label": item["summary"], "assignments": checked_assignments}]
        elif kind is PANAIAssistKind.CANDIDATE_COMPARISON:
            if assignments or choices or evidence or not comparisons or len(comparisons) > 32:
                raise AIInvalidResponseError("AI comparison contains invalid decision data")
            seen_candidates = set()
            for comparison in comparisons:
                if not isinstance(comparison, dict):
                    raise AIInvalidResponseError("AI comparison contains an invalid candidate")
                value = comparison.get("candidate_value")
                if not isinstance(value, str):
                    raise AIInvalidResponseError("AI comparison references an unknown candidate")
                if value in seen_candidates:
                    raise AIInvalidResponseError("AI comparison repeats a candidate")
                seen_candidates.add(value)
                expected = set().union(*(candidate_evidence[key].get(value, set()) for key in keys))
                if not any(value in candidate_evidence[key] for key in keys):
                    raise AIInvalidResponseError("AI comparison references an unknown candidate")
                facts = _strings(comparison.get("evidence"), "comparison evidence")
                if not set(facts).issubset(expected):
                    raise AIInvalidResponseError("AI comparison invented candidate evidence")
                checked_comparisons.append({"candidate_value": value, "evidence": facts,
                    "limitations": _strings(comparison.get("limitations"), "comparison limitations")})
            choices_for_proposal = []
        else:
            if assignments or comparisons or evidence:
                raise AIInvalidResponseError("AI question contains a recommendation")
            choices_for_proposal = checked_choices
        validated.append({
            "kind": kind.value,
            "title": _text(item.get("title"), "title"),
            "summary": _text(item.get("summary"), "summary"),
            "question": _text(item.get("question"), "question") if kind is PANAIAssistKind.ARCHITECTURE_QUESTION else None,
            "decision_keys": keys, "choices": choices_for_proposal,
            "evidence": evidence,
            "rationale": _strings(item.get("rationale"), "rationale"),
            "missing_information": _strings(item.get("missing_information"), "missing information"),
            "limitations": _strings(item.get("limitations"), "limitations"),
            "comparisons": checked_comparisons,
        })
    return validated


def _validate_assignments(assignments, keys, allowed_values):
    if not isinstance(assignments, list) or len(assignments) > 8:
        raise AIInvalidResponseError("AI result has invalid assignments")
    checked = []
    assigned = set()
    for assignment in assignments:
        if not isinstance(assignment, dict):
            raise AIInvalidResponseError("AI result has an invalid assignment")
        key, value = assignment.get("decision_key"), assignment.get("value")
        if (not isinstance(key, str) or key not in keys or key in assigned or not isinstance(value, str)
                or value not in allowed_values.get(key, ())):
            raise AIInvalidResponseError("AI result contains an unsupported target value")
        assigned.add(key)
        checked.append({"decision_key": key, "value": value})
    return checked


def _strings(value, name):
    if not isinstance(value, list) or len(value) > 8:
        raise AIInvalidResponseError(f"AI response has invalid {name}")
    return [_text(item, name) for item in value]


def validate_explanation_output(output, *, group):
    if not isinstance(output, dict) or not isinstance(output.get("comparisons"), list):
        raise AIInvalidResponseError("AI response has invalid comparison")
    expected_evidence = {candidate["value"]: set(candidate["evidence"])
                         for decision in group["decisions"] for candidate in decision["candidates"]}
    expected = set(expected_evidence)
    comparisons = output["comparisons"]
    seen = set()
    for item in comparisons:
        if (not isinstance(item, dict) or item.get("candidate_value") not in expected
                or item["candidate_value"] in seen):
            raise AIInvalidResponseError("AI comparison references an unknown candidate")
        seen.add(item["candidate_value"])
        item["evidence"] = _strings(item.get("evidence"), "evidence")
        if not set(item["evidence"]).issubset(expected_evidence[item["candidate_value"]]):
            raise AIInvalidResponseError("AI comparison invented candidate evidence")
        item["limitations"] = _strings(item.get("limitations"), "limitations")
    if seen != expected:
        raise AIInvalidResponseError("AI comparison omitted a deterministic candidate")
    output["title"] = _text(output.get("title"), "title")
    output["summary"] = _text(output.get("summary"), "summary")
    output["rationale"] = _strings(output.get("rationale"), "rationale")
    output["missing_information"] = _strings(output.get("missing_information"), "missing information")
    output["limitations"] = _strings(output.get("limitations"), "limitations")
    return output
