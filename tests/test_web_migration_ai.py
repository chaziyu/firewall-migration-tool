import hashlib
import json
import sys
import types
from types import SimpleNamespace

import pytest

from fwmigrate.conversion.fortigate_to_palo_alto import ai_advisor
from fwmigrate.conversion.fortigate_to_palo_alto.decisions import (
    PANDecisionMode,
    PANMigrationDecision,
    PANMigrationDecisionSet,
)
from fwmigrate.conversion.fortigate_to_palo_alto.design.models import (
    PANDecisionDependency,
    PANDecisionGraph,
    PANMigrationDesignSession,
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


def _two_decision_state():
    state = _state()
    second = PANMigrationDecision(
        source_vdom="root",
        source_kind="interface",
        source_name="lan1",
        target_field="target_interface",
        mode=PANDecisionMode.REQUIRED,
    )
    state["decisions"] = PANMigrationDecisionSet((*state["decisions"].decisions, second))
    state["decision_candidates"][second.key] = [{
        "value": "ethernet1/2",
        "target_scope": "vsys1",
        "class": "STRONG",
        "strong_evidence": ["matching interface family"],
        "supporting_evidence": [],
    }]
    state["decision_evidence"][second.key] = "SOURCE"
    state["review_context"][second.key] = {"source_type": "physical", "source_ip": "198.51.100.1/24"}
    return state


def _proposal_rows(prepared):
    rows = []
    for item in prepared["request"]["decisions"]:
        candidate = item["candidates"][0]
        rows.append({
            "decision_id": item["decision_id"],
            "action": "USE_EXISTING",
            "candidate_id": candidate["candidate_id"],
            "rationale": "Matching interface evidence supports this target.",
            "evidence_refs": [candidate["evidence"][0]["ref"]],
        })
    return rows


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
    exported = client.get("/api/migration/ai/audit/export")
    audit_row = json.loads(exported.data.decode().strip())
    assert audit_row["engineer_action"] == "APPROVED"
    assert audit_row["final_value"] == "ethernet1/1"
    assert "must never reach Groq" not in exported.data.decode()
    duplicate_outcome = client.post("/api/migration/ai/outcome", json={
        "proposal_id": proposal_id, "engineer_action": "REJECTED",
    })
    assert duplicate_outcome.status_code == 409
    malformed_action = client.post("/api/migration/ai/outcome", json={
        "proposal_id": proposal_id, "engineer_action": [],
    })
    assert malformed_action.status_code == 400

    stale = dict(state, target_device="device-2")
    with pytest.raises(ValueError, match="stale"):
        ai_advisor.revalidate_stored_proposal(stale, proposal)


def test_local_qwen_uses_bounded_json_schema_request(monkeypatch):
    state = _state()
    key = state["decisions"].decisions[0].key
    prepared = ai_advisor.build_proposal_context(
        state, [key], model="Qwen/Qwen3-0.6B", provider="qwen_local"
    )
    candidate = prepared["request"]["decisions"][0]["candidates"][0]
    completion = {"choices": [{"message": {"content": json.dumps({"proposals": [{
        "decision_id": prepared["request"]["decisions"][0]["decision_id"],
        "action": "USE_EXISTING",
        "candidate_id": candidate["candidate_id"],
        "rationale": "Matching target evidence.",
        "evidence_refs": [candidate["evidence"][0]["ref"]],
    }]})}}]}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def read(self):
            return json.dumps(completion).encode()

    requests = []

    def fake_urlopen(request, timeout):
        requests.append((request, timeout))
        return Response()

    monkeypatch.setenv("FWMIGRATE_AI_LOCAL_URL", "http://127.0.0.1:1234/v1")
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.setattr(ai_advisor, "urlopen", fake_urlopen)

    proposal = ai_advisor.request_proposals(prepared)[0]

    assert proposal["provider"] == "qwen_local"
    assert proposal["model"] == "Qwen/Qwen3-0.6B"
    assert proposal["proposed_value"] == "ethernet1/1"
    sent = json.loads(requests[0][0].data)
    assert requests[0][0].full_url == "http://127.0.0.1:1234/v1/chat/completions"
    assert requests[0][1] <= 120
    assert sent["temperature"] == 0
    assert sent["response_format"]["json_schema"]["strict"] is True
    assert "must never reach Groq" not in json.dumps(sent)


def test_ai_context_rejects_a_mapping_before_its_dependency_is_ready():
    state = _two_decision_state()
    keys = [item.key for item in state["decisions"].decisions]
    state["design_session"] = PANMigrationDesignSession(
        source_digest="source-digest",
        target_digest="target-digest",
        target_device="device-1",
        decisions=state["decisions"],
        dependency_graph=PANDecisionGraph((
            PANDecisionDependency(keys[0]),
            PANDecisionDependency(keys[1], (keys[0],)),
        )),
        unresolved=tuple(keys),
    )

    assert ai_advisor.build_proposal_context(state, [keys[0]])["request"]["decisions"]
    with pytest.raises(ValueError, match="blocked by unresolved design dependencies"):
        ai_advisor.build_proposal_context(state, [keys[1]])


def test_repaired_proposal_revalidates_against_current_base_context(monkeypatch):
    state = _two_decision_state()
    third = PANMigrationDecision(
        source_vdom="root",
        source_kind="interface",
        source_name="dmz1",
        target_field="target_interface",
        mode=PANDecisionMode.REQUIRED,
    )
    state["decisions"] = PANMigrationDecisionSet((*state["decisions"].decisions, third))
    state["decision_candidates"][third.key] = [{
        "value": "ethernet1/4",
        "target_scope": "vsys1",
        "class": "STRONG",
        "strong_evidence": ["evidence for ethernet1/4"],
        "supporting_evidence": [],
    }]
    state["decision_evidence"][third.key] = "SOURCE"
    state["review_context"][third.key] = {"source_type": "physical", "source_ip": "203.0.113.1/24"}
    keys = [item.key for item in state["decisions"].decisions]

    def candidate(value):
        return {
            "value": value,
            "target_scope": "vsys1",
            "class": "STRONG",
            "strong_evidence": [f"evidence for {value}"],
            "supporting_evidence": [],
        }

    state["decision_candidates"][keys[0]] = [candidate("ethernet1/1"), candidate("ethernet1/2")]
    state["decision_candidates"][keys[1]] = [candidate("ethernet1/1"), candidate("ethernet1/3")]
    initial_context = ai_advisor.build_proposal_context(state, keys, provider="groq")
    initial = ai_advisor.validate_model_output(
        json.dumps({"proposals": _proposal_rows(initial_context)}), initial_context
    )
    repair_contexts = []

    def repair(prepared):
        repair_contexts.append(prepared["request"]["decisions"][0]["design_context"])
        rows = _proposal_rows(prepared)
        return ai_advisor.validate_model_output(json.dumps({"proposals": rows}), prepared)

    monkeypatch.setattr(ai_advisor, "request_proposals", repair)
    repaired = ai_advisor.repair_conflicted_proposals(state, keys, initial)

    assert [item["proposed_value"] for item in repaired] == ["ethernet1/2", "ethernet1/3", "ethernet1/4"]
    assert all(item["validation_status"] == "VALID" for item in repaired)
    assert all(item["context_digest"] != item["base_context_digest"] for item in repaired[:2])
    assert len(repair_contexts[0]["current_proposals"]) == 3
    assert len(repair_contexts[0]["mutable_decision_ids"]) == 2
    assert hashlib.sha256(third.key.encode()).hexdigest() not in repair_contexts[0]["mutable_decision_ids"]
    assert all(
        ai_advisor.revalidate_stored_proposal(state, item)["proposed_value"] == item["proposed_value"]
        for item in repaired
    )


def test_qwen_abstention_escalates_only_that_decision_to_groq(monkeypatch):
    state = _two_decision_state()
    keys = [item.key for item in state["decisions"].decisions]
    local_prepared = ai_advisor.build_proposal_context(
        state, keys, model="Qwen/Qwen3-0.6B", provider="qwen_local"
    )
    local_rows = _proposal_rows(local_prepared)
    local_rows[1] = {
        **local_rows[1],
        "action": "NO_SAFE_PROPOSAL",
        "candidate_id": None,
        "evidence_refs": [],
    }
    local_output = ai_advisor.validate_model_output(
        json.dumps({"proposals": local_rows}), local_prepared
    )
    requested = []

    def local(_prepared):
        return local_output

    def groq(prepared):
        requested.extend(item["decision_id"] for item in prepared["request"]["decisions"])
        return ai_advisor.validate_model_output(
            json.dumps({"proposals": _proposal_rows(prepared)}), prepared
        )

    monkeypatch.setenv("GROQ_API_KEY", "test-key")
    monkeypatch.setattr(ai_advisor, "_request_local", local)
    monkeypatch.setattr(ai_advisor, "_request_groq", groq)

    result = ai_advisor.request_proposals(local_prepared)

    assert len(requested) == 1
    assert len(result) == 2
    assert all(item["action"] == "USE_EXISTING" for item in result)
    assert [item["provider"] for item in result] == ["qwen_local", "groq"]
    def unavailable(_):
        raise ai_advisor.AdvisorUnavailable("unavailable")

    monkeypatch.setattr(ai_advisor, "_request_groq", unavailable)
    retained = ai_advisor.request_proposals(local_prepared)
    assert [item["provider"] for item in retained] == ["qwen_local", "qwen_local"]
    assert all(item["escalation_failure_category"] == "AI_UNAVAILABLE" for item in retained)


def test_bulk_ai_approval_is_atomic_when_one_proposal_is_stale(monkeypatch):
    state = _two_decision_state()
    keys = [item.key for item in state["decisions"].decisions]
    prepared = ai_advisor.build_proposal_context(state, keys, model="groq-model", provider="groq")
    proposals = ai_advisor.validate_model_output(
        json.dumps({"proposals": _proposal_rows(prepared)}), prepared
    )
    entry = SimpleNamespace(source_digest="source-digest")
    monkeypatch.setattr(web, "_lookup_preview", lambda *_: entry)
    monkeypatch.setattr(web, "_build_migration_review_state", lambda *_: state)
    monkeypatch.setenv("FWMIGRATE_AI_ENABLED", "1")
    monkeypatch.setenv("GROQ_API_KEY", "test-key")
    monkeypatch.setattr(ai_advisor, "request_proposals", lambda _prepared: proposals)
    client = web.create_app({"TESTING": True}).test_client()
    proposed = client.post("/api/migration/ai/propose", json={
        "preview_id": "source-preview", "decision_keys": keys,
    })
    assert proposed.status_code == 200
    proposal_ids = [item["proposal_id"] for item in proposed.get_json()["proposals"]]

    original_revalidate = ai_advisor.revalidate_stored_proposal

    def fail_second(current_state, proposal):
        if proposal["decision_key"] == keys[1]:
            raise ValueError("stale second proposal")
        return original_revalidate(current_state, proposal)

    monkeypatch.setattr(ai_advisor, "revalidate_stored_proposal", fail_second)
    failed = client.post("/api/migration/ai/approve-bulk", json={
        "preview_id": "source-preview", "proposal_ids": proposal_ids,
    })
    assert failed.status_code == 409

    monkeypatch.setattr(ai_advisor, "revalidate_stored_proposal", original_revalidate)
    approved = client.post("/api/migration/ai/approve-bulk", json={
        "preview_id": "source-preview", "proposal_ids": proposal_ids,
    })
    assert approved.status_code == 200
    result = approved.get_json()
    assert result["approved_count"] == 2
    assert all(
        item["evidence_type"] == "ENGINEER_APPROVED_AI_PROPOSAL"
        for item in result["decisions"]["decisions"]
        if item["review_state"] == "CONFIRMED"
    )
    assert all(
        item["evidence_value"] == item["value"]
        for item in result["decisions"]["decisions"]
        if item["review_state"] == "CONFIRMED"
    )
    exported = client.get("/api/migration/ai/audit/export")
    assert exported.status_code == 200
    audit_rows = [json.loads(line) for line in exported.data.decode().splitlines()]
    assert len(audit_rows) == 2
    assert all(item["engineer_action"] == "APPROVED" for item in audit_rows)
    assert all(item["review_context"] for item in audit_rows)
    assert "must never reach Groq" not in exported.data.decode()


def test_provider_contract_and_categorized_safe_failure(monkeypatch, caplog):
    state = _state()
    key = state["decisions"].decisions[0].key
    prepared = ai_advisor.build_proposal_context(state, [key], model="openai/gpt-oss-120b", provider="groq")
    sent = []
    content = json.dumps({"proposals": _proposal_rows(prepared)})
    completion = SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=content))])
    client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(
        create=lambda **kwargs: sent.append(kwargs) or completion)))
    monkeypatch.setitem(sys.modules, "groq", types.SimpleNamespace(Groq=lambda **_: client))
    monkeypatch.setenv("GROQ_API_KEY", "secret-test-key")
    assert ai_advisor._request_groq(prepared)[0]["action"] == "USE_EXISTING"
    assert sent[0]["reasoning_effort"] == "medium"
    assert sent[0]["response_format"]["json_schema"]["strict"] is True
    assert ai_advisor.advisor_capabilities("groq", "another-model").response_mode == "JSON_ONLY"

    class Rejected(Exception):
        status_code = 400
        request_id = "safe-request-id"

    def reject(**_):
        raise Rejected("secret-test-key must not appear in logs")

    client.chat.completions.create = reject
    monkeypatch.setattr(web, "_lookup_preview", lambda *_: SimpleNamespace(source_digest="source-digest"))
    monkeypatch.setattr(web, "_build_migration_review_state", lambda *_: state)
    monkeypatch.setenv("FWMIGRATE_AI_ENABLED", "1")
    client_api = web.create_app({"TESTING": True}).test_client()
    response = client_api.post("/api/migration/ai/propose", json={
        "preview_id": "source-preview", "decision_keys": [key],
    })
    assert response.status_code == 502
    assert response.get_json()["code"] == "AI_REQUEST_REJECTED"
    assert "secret-test-key" not in response.get_data(as_text=True)
    assert "secret-test-key" not in caplog.text
    assert "status=400" in caplog.text
    assert "request_id=safe-request-id" in caplog.text
    audit = json.loads(client_api.get("/api/migration/ai/audit/export").data.decode().strip())
    assert audit["failure_category"] == "AI_REQUEST_REJECTED"
    assert "secret-test-key" not in json.dumps(audit)


def test_status_self_test_and_local_json_only(monkeypatch):
    monkeypatch.setenv("FWMIGRATE_AI_ENABLED", "1")
    monkeypatch.setenv("FWMIGRATE_AI_LOCAL_URL", "http://127.0.0.1:1234/v1")
    monkeypatch.setenv("FWMIGRATE_AI_LOCAL_RESPONSE_MODE", "JSON_ONLY")
    monkeypatch.setenv("GROQ_API_KEY", "secret-test-key")
    state = _state()
    key = state["decisions"].decisions[0].key
    prepared = ai_advisor.build_proposal_context(state, [key], provider="qwen_local")
    assert prepared["response_mode"] == "JSON_ONLY"
    captured = []

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def read(self):
            body = {"choices": [{"message": {"content": json.dumps({"proposals": _proposal_rows(prepared)})}}]}
            return json.dumps(body).encode()

    def fake_urlopen(request, timeout):
        captured.append(json.loads(request.data))
        return Response()

    monkeypatch.setattr(ai_advisor, "urlopen", fake_urlopen)
    assert ai_advisor._request_local(prepared)[0]["response_mode"] == "JSON_ONLY"
    assert captured[0]["response_format"] == {"type": "json_object"}
    assert "reasoning_effort" not in captured[0]

    monkeypatch.setattr(ai_advisor, "_request_local", lambda test_prepared: ai_advisor.validate_model_output(
        json.dumps({"proposals": _proposal_rows(test_prepared)}), test_prepared))
    client = web.create_app({"TESTING": True}).test_client()
    status = client.get("/api/migration/ai/status")
    assert status.status_code == 200
    assert status.get_json()["local_configured"] is True
    assert "secret-test-key" not in status.get_data(as_text=True)
    tested = client.post("/api/migration/ai/test")
    assert tested.status_code == 200
    assert tested.get_json()["structured_output"] is True


def test_automatic_ready_batches_follow_graph(monkeypatch):
    state = _two_decision_state()
    first, second = (item.key for item in state["decisions"].decisions)
    state["design_session"] = PANMigrationDesignSession(
        source_digest="source-digest", target_digest="target-digest", target_device="device-1",
        decisions=state["decisions"],
        dependency_graph=PANDecisionGraph((
            PANDecisionDependency(first), PANDecisionDependency(second, (first,)),
        )), unresolved=(first, second),
    )
    sent = []

    def fake_provider(prepared):
        sent.extend(prepared["by_decision"])
        return ai_advisor.validate_model_output(json.dumps({"proposals": _proposal_rows(prepared)}), prepared)

    monkeypatch.setenv("FWMIGRATE_AI_ENABLED", "1")
    monkeypatch.setenv("GROQ_API_KEY", "test-key")
    monkeypatch.delenv("FWMIGRATE_AI_LOCAL_URL", raising=False)
    monkeypatch.setattr(ai_advisor, "request_proposals", fake_provider)
    monkeypatch.setattr(web, "_lookup_preview", lambda *_: SimpleNamespace(source_digest="source-digest"))
    monkeypatch.setattr(web, "_build_migration_review_state", lambda *_: state)
    client = web.create_app({"TESTING": True}).test_client()
    result = client.post("/api/migration/ai/propose", json={"preview_id": "source-preview"})
    assert result.status_code == 200
    assert sent == [first]
    assert [item["decision_key"] for item in result.get_json()["proposals"]] == [first]


def test_ready_proposals_batch_server_side(monkeypatch):
    state = _state()
    decisions = list(state["decisions"].decisions)
    for index in range(1, 9):
        decision = PANMigrationDecision(
            source_vdom="root", source_kind="interface", source_name=f"port{index}",
            target_field="target_interface", mode=PANDecisionMode.REQUIRED,
        )
        decisions.append(decision)
        state["decision_candidates"][decision.key] = [{
            "value": f"ethernet1/{index + 1}", "target_scope": "vsys1", "class": "STRONG",
            "strong_evidence": ["synthetic matching interface"], "supporting_evidence": [],
        }]
        state["review_context"][decision.key] = {"source_type": "physical"}
    state["decisions"] = PANMigrationDecisionSet(tuple(decisions))
    state["design_session"] = PANMigrationDesignSession(
        source_digest="source-digest", target_digest="target-digest", target_device="device-1",
        decisions=state["decisions"],
        dependency_graph=PANDecisionGraph(tuple(PANDecisionDependency(item.key) for item in decisions)),
        unresolved=tuple(item.key for item in decisions),
    )
    batches = []

    def fake_provider(prepared):
        batches.append(len(prepared["by_decision"]))
        return ai_advisor.validate_model_output(json.dumps({"proposals": _proposal_rows(prepared)}), prepared)

    monkeypatch.setenv("FWMIGRATE_AI_ENABLED", "1")
    monkeypatch.setenv("GROQ_API_KEY", "test-key")
    monkeypatch.delenv("FWMIGRATE_AI_LOCAL_URL", raising=False)
    monkeypatch.setattr(ai_advisor, "request_proposals", fake_provider)
    monkeypatch.setattr(web, "_lookup_preview", lambda *_: SimpleNamespace(source_digest="source-digest"))
    monkeypatch.setattr(web, "_build_migration_review_state", lambda *_: state)
    client = web.create_app({"TESTING": True}).test_client()
    result = client.post("/api/migration/ai/propose", json={"preview_id": "source-preview"})
    assert result.status_code == 200
    assert batches == [8, 1]
    assert len(result.get_json()["proposals"]) == 9
    audit = [json.loads(line) for line in client.get("/api/migration/ai/audit/export").data.decode().splitlines()]
    assert len({item["batch_id"] for item in audit}) == 1
    assert all(item["request_duration_ms"] >= 0 for item in audit)


def test_complex_candidate_set_escalates_without_local_call(monkeypatch):
    state = _state()
    key = state["decisions"].decisions[0].key
    state["decision_candidates"][key] = [{
        "value": f"ethernet1/{index}", "target_scope": "vsys1", "class": "STRONG",
        "strong_evidence": ["synthetic evidence"], "supporting_evidence": [],
    } for index in range(1, 5)]
    prepared = ai_advisor.build_proposal_context(state, [key], provider="qwen_local")
    monkeypatch.setenv("GROQ_API_KEY", "test-key")
    monkeypatch.setattr(ai_advisor, "_request_local", lambda _: pytest.fail("complex choice sent to local model"))
    monkeypatch.setattr(ai_advisor, "_request_groq", lambda remote: ai_advisor.validate_model_output(
        json.dumps({"proposals": _proposal_rows(remote)}), remote))
    proposal = ai_advisor.request_proposals(prepared)[0]
    assert proposal["provider"] == "groq"
    assert proposal["escalated_from"] == "qwen_local"
