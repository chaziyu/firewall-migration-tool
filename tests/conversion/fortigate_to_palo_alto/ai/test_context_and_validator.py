import pytest

from fwmigrate.ai.errors import AIInvalidResponseError
from fwmigrate.conversion.fortigate_to_palo_alto.ai.sanitizer import sanitize_ai_context
from fwmigrate.conversion.fortigate_to_palo_alto.ai.validator import (
    validate_analysis_output, validate_explanation_output, validate_selection_output,
)
from fwmigrate.conversion.fortigate_to_palo_alto.ai.assistant import (
    _compact_selection, _expand_compact_selection,
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
    output = _analysis("MAPPING_RECOMMENDATION")
    output["results"][0]["decision_keys"] = ["key1", "key2"]
    output["results"][0]["assignments"][0]["decision_key"] = "key1"
    with pytest.raises(AIInvalidResponseError):
        validate_analysis_output(output, groups=mixed, allowed_values={"key1": ("ae1",), "key2": ("ae1",)})


def test_candidate_comparison_discards_nonactionable_choices():
    group = _group()
    group[0]["decisions"][0]["candidates"][0]["evidence"] = ["confirmed parent ae1"]
    output = _analysis("CANDIDATE_COMPARISON")
    output["results"][0]["choices"] = [{"label": "malformed extra", "assignments": []}]
    result = validate_analysis_output(output, groups=group, allowed_values={"key1": ("ae1",)})
    assert result[0]["choices"] == []


def test_one_recommendation_can_assign_interface_and_zone_within_one_review_group():
    group = _group()[0]
    group["decisions"].append({"key": "key2", "target_field": "target_zone", "mode": "REQUIRED",
        "review_state": "PENDING", "allowed_values": ["trust"],
        "candidates": [{"value": "trust", "class": "STRONG", "evidence": ["explicit target zone"]}], "source": {}})
    group["decisions"][0]["candidates"][0]["evidence"] = ["confirmed parent ae1"]
    output = _analysis("MAPPING_RECOMMENDATION")
    result = output["results"][0]
    result["decision_keys"] = ["key1", "key2"]
    result["assignments"] = [{"decision_key": "key1", "value": "ae1"},
                             {"decision_key": "key2", "value": "trust"}]
    result["evidence"] = ["confirmed parent ae1", "explicit target zone"]
    validated = validate_analysis_output(output, groups=[group],
        allowed_values={"key1": ("ae1",), "key2": ("trust",)})
    assert len(validated[0]["choices"][0]["assignments"]) == 2


def test_selection_accepts_only_group_options_and_copied_evidence():
    group = _group()[0]
    group["decisions"][0]["candidates"] = [{"value": "ae1", "strong_evidence": ["explicit PAN interface"],
        "supporting_evidence": ["same target VSYS"]}]
    valid = {"decision_keys": ["key1"], "suggested_assignments": [
        {"decision_key": "key1", "value": "ae1"}], "evidence": ["explicit PAN interface"],
        "rationale": [], "alternatives": [], "missing_information": [], "limitations": []}
    result = validate_selection_output(valid, group=group, allowed_values={"key1": ("ae1",)})
    assert result["suggested_assignments"] == valid["suggested_assignments"]
    for field, value in [
        ("suggested_assignments", [{"decision_key": "key1", "value": "new-zone"}]),
        ("suggested_assignments", [{"decision_key": "key1", "value": "ae1"},
                                   {"decision_key": "key1", "value": "ae1"}]),
        ("evidence", ["invented topology"]),
    ]:
        invalid = valid | {field: value}
        with pytest.raises(AIInvalidResponseError):
            validate_selection_output(invalid, group=group, allowed_values={"key1": ("ae1",)})


def test_selection_may_return_no_assignment_when_evidence_is_ambiguous():
    group = _group()[0]
    output = {"decision_keys": ["key1"], "suggested_assignments": [], "evidence": [],
        "rationale": ["Available options have equal evidence."], "alternatives": ["ae1"],
        "missing_information": [], "limitations": []}
    assert validate_selection_output(output, group=group, allowed_values={"key1": ("ae1",)})[
        "suggested_assignments"] == []


def test_selection_validates_evidence_for_each_combined_assignment():
    group = _group()[0]
    group["decisions"][0]["candidates"] = [{"value": "ae1", "strong_evidence": ["aggregate match"]}]
    group["decisions"].append({"key": "key2", "candidates": [
        {"value": "trust", "strong_evidence": ["zone match"]}]})
    output = {"decision_keys": ["key1", "key2"], "suggested_assignments": [
        {"decision_key": "key1", "value": "ae1"}, {"decision_key": "key2", "value": "trust"}],
        "evidence": ["aggregate match", "zone match"], "rationale": [], "alternatives": [],
        "missing_information": [], "limitations": []}
    assert len(validate_selection_output(output, group=group,
        allowed_values={"key1": ("ae1",), "key2": ("trust",)})["suggested_assignments"]) == 2


def test_compact_selection_resolves_only_supplied_option_and_evidence_ids():
    group = _group()[0]
    group["confirmed_engineer_context"] = []
    group["decisions"][0]["candidates"] = [{"value": "ae1", "strong_evidence": ["explicit aggregate"],
        "supporting_evidence": []}]
    payload, options = _compact_selection(group)
    assert payload["decisions"][0]["options"][0]["id"] == "o1_1"
    output = {"choices": [{"decision_id": "d1", "option_id": "o1_1", "evidence_ids": ["e1"]}],
              "missing_information": [], "limitations": []}
    expanded = _expand_compact_selection(output, group, options)
    assert expanded["suggested_assignments"] == [{"decision_key": "key1", "value": "ae1"}]
    ambiguous = _expand_compact_selection(output | {"choices": output["choices"] * 2}, group, options)
    assert ambiguous["suggested_assignments"] == []
    with pytest.raises(AIInvalidResponseError):
        _expand_compact_selection(output | {"choices": [output["choices"][0] | {
            "option_id": "invented"}]}, group, options)
