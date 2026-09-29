import json
from types import SimpleNamespace

import pytest

from fwmigrate.conversion.fortigate_to_palo_alto import ai_advisor
from fwmigrate.conversion.fortigate_to_palo_alto.decisions import (
    PANDecisionMode,
    PANMigrationDecision,
    PANMigrationDecisionSet,
)
from fwmigrate import web


def _state():
    decision = PANMigrationDecision(
        source_vdom="root",
        source_kind="interface",
        source_name="wan1",
        target_field="target_interface",
        mode=PANDecisionMode.REQUIRED,
    )
    key = decision.key
    return {
        "analysis": SimpleNamespace(),
        "source_digest": "source-digest",
        "target_digest": "target-digest",
        "target_device": "device-1",
        "target_context": SimpleNamespace(metadata={
            "vendor": "palo_alto", "config_digest": "target-digest", "device": "device-1",
        }),
        "decisions": PANMigrationDecisionSet((decision,)),
        "decision_candidates": {key: [{
            "value": "ethernet1/1",
            "target_scope": "vsys1",
            "class": "STRONG",
            "strong_evidence": ["matching interface family"],
            "supporting_evidence": ["matching subnet"],
        }]},
        "decision_evidence": {key: "SOURCE"},
        "target_findings": [],
        "review_context": {
            key: {
                "source_type": "physical",
                "source_ip": "192.0.2.1/24",
                "source_description": "must never reach Groq",
            },
        },
    }


def test_groq_proposal_is_candidate_bound_and_server_approved(monkeypatch):
    state = _state()
    key = state["decisions"].decisions[0].key
    prepared = ai_advisor.build_proposal_context(state, [key], model="openai/gpt-oss-120b")
    serialized_context = json.dumps(prepared["request"])
    assert "source_description" not in serialized_context
    assert "must never reach Groq" not in serialized_context
    item = prepared["request"]["decisions"][0]
    candidate = item["candidates"][0]
    evidence_ref = candidate["evidence"][0]["ref"]
    response = {"proposals": [{
        "decision_id": item["decision_id"],
        "action": "USE_EXISTING",
        "candidate_id": candidate["candidate_id"],
        "rationale": "Matching interface evidence supports this target.",
        "evidence_refs": [evidence_ref],
    }]}
    proposal = ai_advisor.validate_model_output(json.dumps(response), prepared)[0]
    assert proposal["proposed_value"] == "ethernet1/1"
    assert proposal["target_scope"] == "vsys1"
    with pytest.raises(ValueError, match="outside the supplied context"):
        ai_advisor.validate_model_output(json.dumps({"proposals": [{
            **response["proposals"][0], "candidate_id": "invented-target",
        }]}), prepared)

    entry = SimpleNamespace(source_digest="source-digest")
    monkeypatch.setattr(web, "_lookup_preview", lambda *_: entry)
    monkeypatch.setattr(web, "_build_migration_review_state", lambda *_: state)
    monkeypatch.setenv("FWMIGRATE_AI_ENABLED", "1")
    monkeypatch.setenv("GROQ_API_KEY", "test-key")
    monkeypatch.setattr(ai_advisor, "request_proposals", lambda _prepared: [proposal])
    client = web.create_app({"TESTING": True}).test_client()
    proposed = client.post("/api/migration/ai/propose", json={
        "preview_id": "source-preview", "decision_keys": [key],
    })
    assert proposed.status_code == 200
    proposal_id = proposed.get_json()["proposals"][0]["proposal_id"]
    approved = client.post("/api/migration/ai/approve", json={
        "preview_id": "source-preview", "proposal_id": proposal_id,
    })
    assert approved.status_code == 200
    decision = approved.get_json()["decisions"]["decisions"][0]
    assert decision["review_state"] == "CONFIRMED"
    assert decision["evidence_source"] == "ENGINEER"
    assert decision["evidence_type"] == "ENGINEER_APPROVED_AI_PROPOSAL"

    stale = dict(state, target_device="device-2")
    with pytest.raises(ValueError, match="stale"):
        ai_advisor.revalidate_stored_proposal(stale, proposal)
