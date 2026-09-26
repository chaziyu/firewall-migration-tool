"""Semantic validation against the current deterministic review state."""

from fwmigrate.ai.errors import AIInvalidResponseError


def _text(value, name):
    if not isinstance(value, str) or not value.strip() or len(value) > 512:
        raise AIInvalidResponseError(f"AI response has invalid {name}")
    return value.strip()


def validate_architecture_output(output, *, groups, allowed_values, max_questions=8):
    if not isinstance(output, dict) or not isinstance(output.get("questions"), list):
        raise AIInvalidResponseError("AI response has invalid questions")
    key_to_group = {item["key"]: group for group in groups for item in group["decisions"]}
    questions = output["questions"]
    if len(questions) > max_questions:
        raise AIInvalidResponseError("AI returned too many questions")
    validated = []
    for question in questions:
        if not isinstance(question, dict):
            raise AIInvalidResponseError("AI response has an invalid question")
        keys = question.get("decision_keys")
        if (not isinstance(keys, list) or not keys or len(set(keys)) != len(keys)
                or any(key not in key_to_group for key in keys)):
            raise AIInvalidResponseError("AI question references an unknown decision")
        identities = {(key_to_group[key]["source_vdom"], key_to_group[key]["source_kind"], key_to_group[key]["source_name"]) for key in keys}
        if len(identities) != 1:
            raise AIInvalidResponseError("AI question combines unrelated review groups")
        choices = question.get("choices")
        if not isinstance(choices, list) or len(choices) > 8:
            raise AIInvalidResponseError("AI question has invalid choices")
        checked_choices = []
        for choice in choices:
            if not isinstance(choice, dict) or not isinstance(choice.get("assignments"), list):
                raise AIInvalidResponseError("AI question has an invalid choice")
            assignments = choice["assignments"]
            assigned = set()
            for assignment in assignments:
                if not isinstance(assignment, dict):
                    raise AIInvalidResponseError("AI choice has an invalid assignment")
                key, value = assignment.get("decision_key"), assignment.get("value")
                if key not in keys or key in assigned or not isinstance(value, str) or value not in allowed_values.get(key, ()):
                    raise AIInvalidResponseError("AI choice contains an unsupported target value")
                assigned.add(key)
            if not assignments:
                raise AIInvalidResponseError("AI choice must assign a supplied candidate")
            checked_choices.append({"label": _text(choice.get("label"), "choice label"),
                                    "assignments": assignments})
        validated.append({
            "title": _text(question.get("title"), "title"), "summary": _text(question.get("summary"), "summary"),
            "question": _text(question.get("question"), "question"), "decision_keys": keys,
            "choices": checked_choices,
            "rationale": _strings(question.get("rationale"), "rationale"),
            "missing_information": _strings(question.get("missing_information"), "missing information"),
            "limitations": _strings(question.get("limitations"), "limitations"),
        })
    return validated


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
