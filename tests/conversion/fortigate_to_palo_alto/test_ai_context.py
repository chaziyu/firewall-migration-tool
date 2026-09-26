from types import SimpleNamespace

from fwmigrate.conversion.fortigate_to_palo_alto.ai.context import build_ai_review_context


def _state(queue, operation="questions", candidates=()):
    decision = SimpleNamespace(key="scope|interface|port1|target_interface", target_field="target_interface",
                               mode=SimpleNamespace(value="REQUIRED"), review_state=SimpleNamespace(value="PENDING"),
                               value=None, suggested_value=None, evidence_type=None, evidence_value=None)
    group = {"queue": queue, "source_vdom": "root", "source_kind": "interface", "source_name": "port1",
             "affected_count": 1, "decisions": [{"key": decision.key}]}
    return build_ai_review_context(source_digest="s", target_digest="t", target_device="fw1",
        decisions=SimpleNamespace(decisions=(decision,)), review_workflow={"review_groups": [group]},
        review_context={}, decision_candidates={decision.key: candidates}, auto_decisions={}, target_findings=(),
        operation=operation, prompt_version="test")


def test_ai_questions_skip_ready_to_confirm_groups_but_explanations_keep_them():
    assert not _state("READY_TO_CONFIRM")["context"]["groups"]
    assert len(_state("READY_TO_CONFIRM", "explain")["context"]["groups"]) == 1


def test_ai_eligible_values_exclude_ambiguous_scopes():
    result = _state("CHOOSE_CANDIDATE", candidates=(
        {"value": "ethernet1/1", "class": "STRONG", "target_scope": "vsys-a"},
        {"value": "ethernet1/1", "class": "STRONG", "target_scope": "vsys-b"},
        {"value": "ethernet1/2", "match_class": "AMBIGUOUS", "scope_identity": "shared"},
        {"value": "ethernet1/3", "class": "POSSIBLE", "target_scope": "vsys-a"},
    ))
    group = result["context"]["groups"][0]
    assert group["decisions"][0]["allowed_values"] == ["ethernet1/3"]
    assert result["allowed_values"][group["decisions"][0]["key"]] == ("ethernet1/3",)
