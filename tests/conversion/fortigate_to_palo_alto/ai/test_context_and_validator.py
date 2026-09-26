import pytest

from fwmigrate.ai.errors import AIInvalidResponseError
from fwmigrate.conversion.fortigate_to_palo_alto.ai.sanitizer import sanitize_ai_context
from fwmigrate.conversion.fortigate_to_palo_alto.ai.validator import validate_architecture_output, validate_explanation_output


def _group():
    return [{"source_vdom": "root", "source_kind": "interface", "source_name": "agg1", "decisions": [
        {"key": "key1", "target_field": "target_interface", "mode": "REQUIRED", "review_state": "PENDING",
         "allowed_values": ["ae1"], "candidates": [{"value": "ae1", "class": "STRONG", "evidence": []}], "source": {}}
    ]}]


def _question(value):
    return {"questions": [{"title": "Aggregate mapping", "summary": "Compare candidates", "question": "Which interface?",
        "decision_keys": ["key1"], "choices": [{"label": value, "assignments": [{"decision_key": "key1", "value": value}]}],
        "rationale": ["Supplied topology supports this choice"], "missing_information": [], "limitations": []}]}


def test_sanitizer_masks_addresses_and_fails_closed_on_secrets_and_limits():
    assert sanitize_ai_context({"evidence": "exact IP 10.2.3.4/24"})["evidence"] == "exact IP [address evidence]"
    assert sanitize_ai_context({"evidence": "IPv6 2001:db8::1/64"})["evidence"] == "IPv6 [address evidence]"
    with pytest.raises(AIInvalidResponseError): sanitize_ai_context({"api_key": "secret"})
    with pytest.raises(AIInvalidResponseError): sanitize_ai_context({"evidence": "x" * 300})


def test_architecture_validator_accepts_only_pending_group_candidates():
    result = validate_architecture_output(_question("ae1"), groups=_group(), allowed_values={"key1": ("ae1",)})
    assert result[0]["choices"][0]["assignments"][0]["value"] == "ae1"
    with pytest.raises(AIInvalidResponseError):
        validate_architecture_output(_question("ae3"), groups=_group(), allowed_values={"key1": ("ae1",)})
    output = _question("ae1"); output["questions"][0]["decision_keys"] = ["invented"]
    with pytest.raises(AIInvalidResponseError):
        validate_architecture_output(output, groups=_group(), allowed_values={"key1": ("ae1",)})


def test_explanation_cannot_invent_candidate_evidence():
    group = _group()[0] | {"decisions": [_group()[0]["decisions"][0] | {
        "candidates": [{"value": "ae1", "class": "STRONG", "evidence": ["confirmed parent ae1"]}]}]}
    explanation = {"title": "Compare", "summary": "Evidence matches.", "comparisons": [
        {"candidate_value": "ae1", "evidence": ["confirmed parent ae1"], "limitations": []}],
        "rationale": [], "missing_information": [], "limitations": []}
    assert validate_explanation_output(explanation, group=group)["title"] == "Compare"
    explanation["comparisons"][0]["evidence"] = ["invented IP match"]
    with pytest.raises(AIInvalidResponseError): validate_explanation_output(explanation, group=group)
