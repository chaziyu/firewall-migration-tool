import pytest

from fwmigrate.ai.errors import AIInvalidResponseError
from fwmigrate.conversion.fortigate_to_palo_alto.ai.sanitizer import sanitize_ai_context
from fwmigrate.conversion.fortigate_to_palo_alto.ai.validator import (
    validate_analysis_output, validate_explanation_output,
)


def _group():
    return [{"source_vdom": "root", "source_kind": "interface", "source_name": "agg1", "decisions": [
        {"key": "key1", "target_field": "target_interface", "mode": "REQUIRED", "review_state": "PENDING",
         "allowed_values": ["ae1"], "candidates": [{"value": "ae1", "class": "STRONG", "evidence": []}], "source": {}}
    ]}]


def test_sanitizer_masks_addresses_and_fails_closed_on_secrets_and_limits():
    assert sanitize_ai_context({"evidence": "exact IP 10.2.3.4/24"})["evidence"] == "exact IP [address evidence]"
    assert sanitize_ai_context({"evidence": "IPv6 2001:db8::1/64"})["evidence"] == "IPv6 [address evidence]"
    with pytest.raises(AIInvalidResponseError): sanitize_ai_context({"api_key": "secret"})
    with pytest.raises(AIInvalidResponseError): sanitize_ai_context({"evidence": "x" * 300})


def test_explanation_cannot_invent_candidate_evidence():
    group = _group()[0] | {"decisions": [_group()[0]["decisions"][0] | {
        "candidates": [{"value": "ae1", "class": "STRONG", "evidence": ["confirmed parent ae1"]}]}]}
    explanation = {"title": "Compare", "summary": "Evidence matches.", "comparisons": [
        {"candidate_value": "ae1", "evidence": ["confirmed parent ae1"], "limitations": []}],
        "rationale": [], "missing_information": [], "limitations": []}
    assert validate_explanation_output(explanation, group=group)["title"] == "Compare"
    explanation["comparisons"][0]["evidence"] = ["invented IP match"]
    with pytest.raises(AIInvalidResponseError): validate_explanation_output(explanation, group=group)


def _analysis(kind, *, value="ae1", evidence=("confirmed parent ae1",)):
    return {"results": [{"kind": kind, "title": "Review", "summary": "Review candidate evidence.",
        "question": "Which mapping?", "decision_keys": ["key1"],
        "assignments": ([{"decision_key": "key1", "value": value}]
                        if kind == "MAPPING_RECOMMENDATION" else []),
        "evidence": list(evidence) if kind == "MAPPING_RECOMMENDATION" else [],
        "choices": ([{"label": "Use ae1", "assignments": [{"decision_key": "key1", "value": value}]}]
                    if kind == "ARCHITECTURE_QUESTION" else []),
        "comparisons": ([{"candidate_value": value, "evidence": ["confirmed parent ae1"], "limitations": []}]
                        if kind == "CANDIDATE_COMPARISON" else []),
        "rationale": [], "missing_information": [], "limitations": []}]}


def test_analysis_recommendations_require_closed_values_and_candidate_evidence():
    group = _group()
    group[0]["decisions"][0]["candidates"][0]["evidence"] = ["confirmed parent ae1"]
    allowed = {"key1": ("ae1",)}
    result = validate_analysis_output(_analysis("MAPPING_RECOMMENDATION"), groups=group, allowed_values=allowed)
    assert result[0]["choices"][0]["assignments"][0]["value"] == "ae1"
    for output, candidates in [
        (_analysis("MAPPING_RECOMMENDATION", value="ae2"), allowed),
        (_analysis("MAPPING_RECOMMENDATION", evidence=("invented topology",)), allowed),
        (_analysis("MAPPING_RECOMMENDATION"), {"key1": ()}),
    ]:
        with pytest.raises(AIInvalidResponseError):
            validate_analysis_output(output, groups=group, allowed_values=candidates)


def test_analysis_questions_and_comparisons_cannot_escape_candidates_or_group_scope():
    group = _group()
    group[0]["decisions"][0]["candidates"][0]["evidence"] = ["confirmed parent ae1"]
    assert validate_analysis_output(_analysis("ARCHITECTURE_QUESTION"), groups=group,
                                    allowed_values={"key1": ("ae1",)})
    with pytest.raises(AIInvalidResponseError):
        validate_analysis_output(_analysis("ARCHITECTURE_QUESTION", value="ae2"), groups=group,
                                 allowed_values={"key1": ("ae1",)})
    with pytest.raises(AIInvalidResponseError):
        validate_analysis_output(_analysis("CANDIDATE_COMPARISON", value="ae2"), groups=group,
                                 allowed_values={"key1": ("ae1",)})
    mixed = group + [{**group[0], "source_name": "other"}]
    output = _analysis("ARCHITECTURE_QUESTION")
    output["results"][0]["decision_keys"] = ["key1", "key2"]
    mixed[1]["decisions"] = [{**mixed[1]["decisions"][0], "key": "key2"}]
    with pytest.raises(AIInvalidResponseError):
        validate_analysis_output(output, groups=mixed, allowed_values={"key1": ("ae1",), "key2": ("ae1",)})
