import hashlib
import json
import sys
import types
from dataclasses import replace
from types import SimpleNamespace

import pytest

from fwmigrate.conversion.fortigate_to_palo_alto import ai_advisor
from fwmigrate.conversion.fortigate_to_palo_alto.decisions import (
    PANDecisionMode,
    PANDecisionReviewState,
    PANMigrationDecision,
    PANMigrationDecisionSet,
)
from fwmigrate.conversion.fortigate_to_palo_alto.design.models import (
    PANDecisionDependency,
    PANDecisionGraph,
    PANMigrationDesignSession,
)
from fwmigrate.conversion.fortigate_to_palo_alto.ai.models import PANAIProposal, PANAIProposalAction
from fwmigrate.conversion.fortigate_to_palo_alto.design.proposed import (
    PANProposedDesign,
    PANProposedDesignSession,
)
from fwmigrate.conversion.fortigate_to_palo_alto.design.session import create_design_session
from fwmigrate.conversion.fortigate_to_palo_alto.ai import orchestrator as ai_orchestrator
import fwmigrate.conversion.fortigate_to_palo_alto.application.review as migration_review
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


def _proposal_rows_for_values(prepared, values):
    key_by_id = {item["decision_id"]: key for key, item in prepared["by_decision"].items()}
    rows = []
    for item in prepared["request"]["decisions"]:
        key = key_by_id[item["decision_id"]]
        candidate = next(candidate for candidate in item["candidates"] if candidate["value"] == values[key])
        rows.append({
            "decision_id": item["decision_id"],
            "action": "USE_EXISTING",
            "candidate_id": candidate["candidate_id"],
            "rationale": "Matching interface evidence supports this target.",
            "evidence_refs": [candidate["evidence"][0]["ref"]],
        })
    return rows


def _proposal_batches(state, keys):
    proposals = []
    batch_size = ai_advisor._max_decisions()
    for offset in range(0, len(keys), batch_size):
        prepared = ai_advisor.build_proposal_context(
            state, list(keys[offset:offset + batch_size]), provider="groq"
        )
        proposals.extend(ai_advisor.validate_model_output(
            json.dumps({"proposals": _proposal_rows(prepared)}), prepared
        ))
    return proposals


def _design_state(decision_count=2, *, chained=False):
    decisions = []
    candidates = {}
    evidence = {}
    context = {}
    for index in range(decision_count):
        kind = "vdom" if chained and index == 0 else "interface"
        name = "root" if kind == "vdom" else f"port{index:03d}"
        field = "vsys" if kind == "vdom" else "target_interface"
        decision = PANMigrationDecision(
            source_vdom="root", source_kind=kind, source_name=name,
            target_field=field, mode=PANDecisionMode.REQUIRED,
        )
        decisions.append(decision)
        value = "vsys1" if kind == "vdom" else f"ethernet1/{index + 1}"
        candidates[decision.key] = [{
            "value": value, "target_scope": "vsys1", "class": "STRONG",
            "strong_evidence": ["matching interface family"], "supporting_evidence": [],
        }]
        evidence[decision.key] = "TARGET"
        context[decision.key] = {"source_type": "physical"}
    decision_set = PANMigrationDecisionSet(tuple(decisions))
    if chained:
        dependencies = (PANDecisionDependency(decisions[0].key), PANDecisionDependency(decisions[1].key, (decisions[0].key,)))
    else:
        dependencies = tuple(PANDecisionDependency(item.key) for item in decisions)
    graph = PANDecisionGraph(dependencies)
    target_metadata = {"vendor": "palo_alto", "config_digest": "target-digest", "device": "device-1"}
    source = SimpleNamespace(interfaces=[])
    target = SimpleNamespace(config=SimpleNamespace(), derived=SimpleNamespace())
    return {
        "analysis": SimpleNamespace(extracted=SimpleNamespace(config=source), derived=SimpleNamespace()),
        "source_digest": "source-digest", "target_digest": "target-digest", "target_device": "device-1",
        "target_context": SimpleNamespace(metadata=target_metadata, analysis=target, selected_device="device-1"),
        "decisions": decision_set,
        "design_session": PANMigrationDesignSession(
            source_digest="source-digest", target_digest="target-digest", target_device="device-1",
            decisions=decision_set, dependency_graph=graph, unresolved=tuple(item.key for item in decisions),
        ),
        "decision_candidates": candidates, "decision_evidence": evidence, "target_findings": [],
        "review_context": context,
    }


def _install_design_api(monkeypatch, state, *, discover=None, app_config=None):
    batches = []

    def fake_provider(prepared):
        batches.append(tuple(prepared["by_decision"]))
        return ai_advisor.validate_model_output(json.dumps({"proposals": _proposal_rows(prepared)}), prepared)

    def rebuild_state(_entry, payload, *_args):
        document = payload.get("decision_document") or {}
        if not document.get("decisions"):
            return state
        decisions = PANMigrationDecisionSet.from_dict({"decisions": document["decisions"]})
        graph = state["design_session"].dependency_graph
        updated = dict(state, decisions=decisions)
        updated["design_session"] = create_design_session(
            decisions, graph, source_digest=state["source_digest"],
            target_evidence=state["target_context"].metadata,
        )
        return updated

    original_candidates = state["decision_candidates"]
    monkeypatch.setattr(ai_orchestrator, "discover_target_candidates", discover or
                        (lambda _source, decisions, _target, _device, **_kwargs:
                         {item.key: original_candidates[item.key] for item in decisions.decisions
                          if item.key in original_candidates}))
    monkeypatch.setattr(ai_orchestrator, "build_review_evidence", lambda *_: {})
    monkeypatch.setattr(ai_advisor, "validate_against_target", lambda *_: ())
    monkeypatch.setattr(ai_advisor, "advisor_provider", lambda: "groq")
    monkeypatch.setattr(ai_advisor, "advisor_model", lambda: "openai/gpt-oss-120b")
    monkeypatch.setattr(ai_advisor, "request_proposals", fake_provider)
    monkeypatch.setattr(ai_advisor, "advisor_enabled", lambda: True)
    monkeypatch.setattr(web, "analyze_request_source", lambda *_: SimpleNamespace(source_digest=state["source_digest"]))
    monkeypatch.setattr(web, "_build_migration_review_state", rebuild_state)
    return web.create_app({"TESTING": True, **(app_config or {})}).test_client(), batches


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
    monkeypatch.setenv("FWMIGRATE_AI_MAX_BATCH", "3")

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

    assert [item["proposed_value"] for item in repaired.proposals] == ["ethernet1/2", "ethernet1/3", "ethernet1/4"]
    assert all(item["validation_status"] == "VALID" for item in repaired.proposals)
    assert all(item["context_digest"] != item["base_context_digest"] for item in repaired.proposals[:2])
    assert len(repair_contexts[0]["current_proposals"]) == 3
    assert len(repair_contexts[0]["mutable_decision_ids"]) == 2
    assert hashlib.sha256(third.key.encode()).hexdigest() not in repair_contexts[0]["mutable_decision_ids"]
    assert all(
        ai_advisor.revalidate_stored_proposal(state, item)["proposed_value"] == item["proposed_value"]
        for item in repaired.proposals
    )


def test_conflicted_proposals_repair_in_bounded_batches_from_latest_global_state(monkeypatch):
    state = _design_state(4)
    keys = tuple(item.key for item in state["decisions"].decisions)
    current_values = ("ethernet1/1", "ethernet1/1", "ethernet1/2", "ethernet1/2")
    alternate_values = ("ethernet1/2", "ethernet1/3", "ethernet1/4", "ethernet1/5")
    for key, current, alternate in zip(keys, current_values, alternate_values):
        base = state["decision_candidates"][key][0]
        state["decision_candidates"][key] = [
            {**base, "value": current}, {**base, "value": alternate},
        ]
    monkeypatch.setenv("FWMIGRATE_AI_MAX_BATCH", "2")
    monkeypatch.setattr(ai_advisor, "validate_against_target", lambda *_: ())
    initial = _proposal_batches(state, keys)
    assert all(item["validation_status"] == "CONFLICT"
               for item in ai_advisor.validate_proposal_set(state, initial))
    calls = []

    def repair(prepared):
        calls.append(prepared)
        return ai_advisor.validate_model_output(
            json.dumps({"proposals": _proposal_rows(prepared)}), prepared
        )

    monkeypatch.setattr(ai_advisor, "request_proposals", repair)
    result = ai_advisor.repair_conflicted_proposals(state, keys, initial)

    assert [tuple(item["by_decision"]) for item in calls] == [keys[:2], keys[2:]]
    assert all(len(item["by_decision"]) <= 2 for item in calls)
    assert all(len(item["request"]["decisions"]) <= 2 for item in calls)
    first_context, second_context = (
        item["request"]["decisions"][0]["design_context"] for item in calls
    )
    key_ids = {key: hashlib.sha256(key.encode()).hexdigest() for key in keys}
    assert len(first_context["current_proposals"]) == 4
    assert set(first_context["mutable_decision_ids"]) == {key_ids[key] for key in keys[:2]}
    current_after_first_batch = {item["decision_id"]: item for item in second_context["current_proposals"]}
    assert current_after_first_batch[key_ids[keys[0]]]["proposed_value"] == "ethernet1/2"
    assert current_after_first_batch[key_ids[keys[0]]]["validation_status"] == "CONFLICT"
    assert len(second_context["current_proposals"]) == 4
    assert set(second_context["mutable_decision_ids"]) == {key_ids[key] for key in keys[2:]}
    assert [item["decision_key"] for item in result.proposals] == list(keys)
    assert [item["validation_status"] for item in result.proposals] == ["VALID"] * 4
    assert result.exhausted is False


def test_repair_scope_only_mutates_named_decisions(monkeypatch):
    state = _design_state(4)
    keys = tuple(item.key for item in state["decisions"].decisions)
    for key, value, alternate in zip(
        keys,
        ("ethernet1/1", "ethernet1/1", "ethernet1/2", "ethernet1/2"),
        ("ethernet1/3", "ethernet1/4", "ethernet1/5", "ethernet1/6"),
    ):
        base = state["decision_candidates"][key][0]
        state["decision_candidates"][key] = [
            {**base, "value": value}, {**base, "value": alternate},
        ]
    monkeypatch.setenv("FWMIGRATE_AI_MAX_BATCH", "2")
    monkeypatch.setattr(ai_advisor, "validate_against_target", lambda *_: ())
    initial = _proposal_batches(state, keys)
    calls = []

    def repair(prepared):
        calls.append(prepared)
        return ai_advisor.validate_model_output(
            json.dumps({"proposals": _proposal_rows(prepared)}), prepared
        )

    monkeypatch.setattr(ai_advisor, "request_proposals", repair)
    result = ai_advisor.repair_conflicted_proposals(state, keys[:2], initial)

    assert len(calls) == 1
    assert tuple(calls[0]["by_decision"]) == keys[:2]
    assert {item["decision_key"] for item in result.proposals
            if item["validation_status"] == "CONFLICT"} == set(keys[2:])
    assert [item["proposed_value"] for item in result.proposals[2:]] == ["ethernet1/2", "ethernet1/2"]
    assert result.exhausted is True


def test_failure_in_later_repair_batch_keeps_that_batch_and_later_proposals(monkeypatch):
    state = _design_state(5)
    keys = tuple(item.key for item in state["decisions"].decisions)
    for key, value, alternate in zip(
        keys,
        ("ethernet1/1", "ethernet1/1", "ethernet1/2", "ethernet1/2", "ethernet1/2"),
        ("ethernet1/3", "ethernet1/4", "ethernet1/5", "ethernet1/6", "ethernet1/7"),
    ):
        base = state["decision_candidates"][key][0]
        state["decision_candidates"][key] = [
            {**base, "value": value}, {**base, "value": alternate},
        ]
    monkeypatch.setenv("FWMIGRATE_AI_MAX_BATCH", "2")
    monkeypatch.setattr(ai_advisor, "validate_against_target", lambda *_: ())
    initial = _proposal_batches(state, keys)
    calls = []

    def repair(prepared):
        batch = tuple(prepared["by_decision"])
        calls.append(batch)
        if len(calls) == 2:
            raise ai_advisor.AdvisorRequestError("later batch rejected")
        return ai_advisor.validate_model_output(
            json.dumps({"proposals": _proposal_rows(prepared)}), prepared
        )

    monkeypatch.setattr(ai_advisor, "request_proposals", repair)
    result = ai_advisor.repair_conflicted_proposals(state, keys, initial)

    assert calls == [keys[:2], keys[2:4]]
    assert len(result.proposals) == 5
    assert result.failures[0]["failure_category"] == "AI_REQUEST_REJECTED"
    assert result.failures[0]["decision_keys"] == list(keys[2:4])
    assert [item["proposed_value"] for item in result.proposals[:2]] == ["ethernet1/3", "ethernet1/4"]
    assert [item["candidate_id"] for item in result.proposals[2:]] == [
        item["candidate_id"] for item in initial[2:]
    ]
    assert result.exhausted is True


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
    assert [item["name"] for item in tested.get_json()["checks"]] == [
        "provider_contract", "production_shape",
    ]
    assert tested.get_json()["structured_output"] is True








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


def test_provisional_parent_unlocks_next_ai_wave_without_planner_input(monkeypatch):
    state = _design_state(chained=True)
    vsys_key, interface_key = (item.key for item in state["decisions"].decisions)
    zone = PANMigrationDecision("root", "zone", "LAN", "target_zone")
    state["decisions"] = PANMigrationDecisionSet((*state["decisions"].decisions, zone))
    graph = PANDecisionGraph((
        PANDecisionDependency(vsys_key),
        PANDecisionDependency(interface_key, (vsys_key,)),
        PANDecisionDependency(zone.key, (interface_key,)),
    ))
    state["design_session"] = create_design_session(
        state["decisions"], graph, source_digest=state["source_digest"],
        target_evidence=state["target_context"].metadata,
    )
    state["decision_candidates"] = {vsys_key: state["decision_candidates"][vsys_key]}
    state["review_context"][zone.key] = {"source_type": "zone"}
    state["decision_evidence"][zone.key] = "SOURCE"
    batches = []

    def discover(_source, decisions, _target, _device, *, evidence=None, proposed_design=None):
        result = {vsys_key: [{
            "value": "vsys1", "target_scope": "vsys1", "class": "STRONG",
            "strong_evidence": ["explicit target VSYS"], "supporting_evidence": [],
        }]}
        if proposed_design.provisional_value(vsys_key):
            result[interface_key] = [{
                "value": "ethernet1/7", "target_scope": "vsys1", "class": "STRONG",
                "strong_evidence": ["matching interface family"], "supporting_evidence": [],
            }]
        if proposed_design.provisional_value(interface_key):
            result[zone.key] = [{
                "value": "trust", "target_scope": "vsys1", "class": "STRONG",
                "strong_evidence": ["selected interface belongs to this zone"], "supporting_evidence": [],
            }]
        return result

    def fake_provider(prepared):
        batches.append(tuple(prepared["by_decision"]))
        return ai_advisor.validate_model_output(json.dumps({"proposals": _proposal_rows(prepared)}), prepared)

    monkeypatch.setattr(ai_orchestrator, "discover_target_candidates", discover)
    monkeypatch.setattr(ai_orchestrator, "build_review_evidence", lambda *_: {})
    monkeypatch.setattr(ai_advisor, "validate_against_target", lambda *_: ())
    monkeypatch.setattr(ai_advisor, "advisor_provider", lambda: "groq")
    monkeypatch.setattr(ai_advisor, "advisor_model", lambda: "openai/gpt-oss-120b")
    monkeypatch.setattr(ai_advisor, "request_proposals", fake_provider)
    monkeypatch.setattr(ai_advisor, "advisor_enabled", lambda: True)
    entry = SimpleNamespace(source_digest="source-digest")
    monkeypatch.setattr(web, "analyze_request_source", lambda *_: entry)
    monkeypatch.setattr(web, "_build_migration_review_state", lambda *_: state)
    client = web.create_app({"TESTING": True}).test_client()

    built = client.post("/api/migration/ai/design", json={"source": "source-preview"})
    assert built.status_code == 200
    body = built.get_json()
    assert batches == [(vsys_key,), (interface_key,), (zone.key,)]
    assert [item["decision_key"] for item in body["design_session"]["proposals"]] == [
        vsys_key, interface_key, zone.key,
    ]
    assert body["design_session"]["proposals"][1]["dependency_values"] == [[vsys_key, "vsys1"]]
    unapproved_options = PANMigrationDecisionSet.from_dict(body["decisions"]).to_options()
    assert unapproved_options.vdoms == {}
    assert unapproved_options.interfaces == {}
    assert unapproved_options.zones == {}

    approved = client.post(
        f"/api/migration/ai/design/{body['design_session']['design_session_id']}/approve",
        json={"design_session": body["design_session"], "source": "source-preview", "decision_document": body["decision_document"],
              "target_source": "target-preview", "target_device": "device-1", "approve_all": True},
    )
    assert approved.status_code == 200
    options = PANMigrationDecisionSet.from_dict(approved.get_json()["decisions"]).to_options()
    assert options.vdoms["root"].vsys == "vsys1"
    assert options.interfaces["root"]["port001"].target_interface == "ethernet1/7"
    assert options.zones["root"]["LAN"].target_zone == "trust"
    audit = approved.get_json()["design_session"]["audit"]
    assert all(item["engineer_action"] == "APPROVED" for item in audit)


def test_unrelated_decision_change_does_not_stale_proposal_but_dependency_change_does():
    state = _two_decision_state()
    first, second = (item.key for item in state["decisions"].decisions)
    original = ai_advisor.build_proposal_context(state, [first])
    proposal = ai_advisor.validate_model_output(json.dumps({"proposals": _proposal_rows(original)}), original)[0]
    changed_second = replace(state["decisions"].decisions[1], value="manual-vsys",
                             review_state=PANDecisionReviewState.CONFIRMED)
    unrelated_change = dict(state, decisions=PANMigrationDecisionSet((state["decisions"].decisions[0], changed_second)))
    assert ai_advisor.revalidate_stored_proposal(unrelated_change, proposal)["proposed_value"] == "ethernet1/1"

    state["design_session"] = PANMigrationDesignSession(
        source_digest="source-digest", target_digest="target-digest", target_device="device-1",
        decisions=state["decisions"], dependency_graph=PANDecisionGraph((
            PANDecisionDependency(first), PANDecisionDependency(second, (first,)),
        )), unresolved=(first, second),
    )
    parent_context = ai_advisor.build_proposal_context(state, [first])
    parent = PANAIProposal.from_dict(ai_advisor.validate_model_output(
        json.dumps({"proposals": _proposal_rows(parent_context)}), parent_context
    )[0])
    design = PANProposedDesign("source-digest", "target-digest", "device-1", state["decisions"], (parent,))
    child_context = ai_advisor.build_proposal_context(state, [second], proposed_design=design)
    child = ai_advisor.validate_model_output(json.dumps({"proposals": _proposal_rows(child_context)}), child_context)[0]
    changed_parent = replace(parent, proposed_value="ethernet1/9")
    changed_design = design.with_state(proposals=(changed_parent,))
    with pytest.raises(ValueError, match="stale|upstream"):
        ai_advisor.revalidate_stored_proposal(state, child, proposed_design=changed_design)


def test_proposed_design_session_has_no_256_decision_ceiling(monkeypatch):
    state = _design_state(300)
    original_candidates = state["decision_candidates"]
    batches = []

    def discover(_source, decisions, _target, _device, *, evidence=None, proposed_design=None):
        return {item.key: original_candidates[item.key] for item in decisions.decisions}

    def fake_provider(prepared):
        batches.append(tuple(prepared["by_decision"]))
        return ai_advisor.validate_model_output(json.dumps({"proposals": _proposal_rows(prepared)}), prepared)

    monkeypatch.setenv("FWMIGRATE_AI_MAX_BATCH", "32")
    monkeypatch.setenv("FWMIGRATE_AI_MAX_REQUEST_BYTES", "49152")
    monkeypatch.setattr(ai_orchestrator, "discover_target_candidates", discover)
    monkeypatch.setattr(ai_orchestrator, "build_review_evidence", lambda *_: {})
    monkeypatch.setattr(ai_advisor, "validate_against_target", lambda *_: ())
    monkeypatch.setattr(ai_advisor, "advisor_provider", lambda: "groq")
    monkeypatch.setattr(ai_advisor, "advisor_model", lambda: "openai/gpt-oss-120b")
    monkeypatch.setattr(ai_advisor, "request_proposals", fake_provider)
    monkeypatch.setattr(ai_advisor, "advisor_enabled", lambda: True)
    monkeypatch.setattr(web, "analyze_request_source", lambda *_: SimpleNamespace(source_digest="source-digest"))
    monkeypatch.setattr(web, "_build_migration_review_state", lambda *_: state)
    client = web.create_app({"TESTING": True}).test_client()

    response = client.post("/api/migration/ai/design", json={"source": "source-preview"})
    assert response.status_code == 200
    proposals = response.get_json()["design_session"]["proposals"]
    assert [len(batch) for batch in batches] == [32] * 9 + [12]
    assert len(proposals) == 300
    assert {item["decision_key"] for item in proposals} == set(original_candidates)


def test_family_approval_keeps_other_proposals_in_the_design(monkeypatch):
    state = _design_state(chained=True)
    vsys_key, interface_key = (item.key for item in state["decisions"].decisions)
    client, _ = _install_design_api(monkeypatch, state)
    built = client.post("/api/migration/ai/design", json={"source": "source-preview"}).get_json()
    session_id = built["design_session"]["design_session_id"]
    approved_vsys = client.post(
        f"/api/migration/ai/design/{session_id}/approve",
        json={"design_session": built["design_session"], "source": "source-preview", "decision_document": built["decision_document"],
              "target_source": "target-preview", "target_device": "device-1",
              "family": "ownership", "source_vdom": "root"},
    )
    assert approved_vsys.status_code == 200
    remaining = approved_vsys.get_json()["design_session"]["proposals"]
    assert [item["decision_key"] for item in remaining] == [interface_key]
    assert approved_vsys.get_json()["design_session"]["summary"]["engineer_confirmed"] == 1

    approved_interface = client.post(
        f"/api/migration/ai/design/{session_id}/approve",
        json={"design_session": approved_vsys.get_json()["design_session"], "source": "source-preview",
              "decision_document": approved_vsys.get_json()["decision_document"],
              "target_source": "target-preview", "target_device": "device-1",
              "decision_keys": [interface_key]},
    )
    assert approved_interface.status_code == 200
    assert approved_interface.get_json()["approved_count"] == 1
    assert approved_interface.get_json()["design_session"]["proposals"] == []
    assert {item["key"] for item in approved_interface.get_json()["decisions"]["decisions"]} == {
        vsys_key, interface_key,
    }


def test_engineer_modification_rebuilds_only_dependent_proposals(monkeypatch):
    state = _design_state(chained=True)
    vsys_key, interface_key = (item.key for item in state["decisions"].decisions)

    def discover(_source, decisions, _target, _device, *, evidence=None, proposed_design=None):
        result = {vsys_key: state["decision_candidates"][vsys_key]}
        if proposed_design.provisional_value(vsys_key):
            result[interface_key] = [{
                "value": "ethernet1/7", "target_scope": "vsys1", "class": "STRONG",
                "strong_evidence": ["matching interface family"], "supporting_evidence": [],
            }]
        return result

    client, _ = _install_design_api(monkeypatch, state, discover=discover)
    built = client.post("/api/migration/ai/design", json={"source": "source-preview"}).get_json()
    session_id = built["design_session"]["design_session_id"]
    modified = client.post(
        f"/api/migration/ai/design/{session_id}/modify",
        json={"design_session": built["design_session"], "source": "source-preview", "decision_document": built["decision_document"],
              "target_source": "target-preview", "target_device": "device-1",
              "changes": [{"decision_key": vsys_key, "value": "vsys2"}]},
    )
    assert modified.status_code == 200
    body = modified.get_json()
    assert next(item for item in body["decisions"]["decisions"] if item["key"] == vsys_key)["value"] == "vsys2"
    assert [item["decision_key"] for item in body["design_session"]["proposals"]] == [interface_key]
    assert body["design_session"]["proposals"][0]["dependency_values"] == [[vsys_key, "vsys2"]]
    actions = [(row["decision_key"], row["engineer_action"], row.get("failure_category"))
               for row in body["design_session"]["audit"]]
    assert (vsys_key, "MODIFIED", None) in actions
    assert (interface_key, "UNRESOLVED", "CONTEXT_CHANGED") in actions
    audit = body["design_session"]["audit"]
    audit_by_key = {item["decision_key"]: item for item in audit}
    assert audit_by_key[vsys_key]["final_value"] == "vsys2"
    assert any(item["decision_key"] == interface_key
               and item["failure_category"] == "CONTEXT_CHANGED" for item in audit)


def test_engineer_can_clear_a_decision_in_the_design_session(monkeypatch):
    state = _design_state(decision_count=1)
    decision_key = state["decisions"].decisions[0].key
    client, _ = _install_design_api(monkeypatch, state)
    built = client.post("/api/migration/ai/design", json={"source": "source-preview"}).get_json()
    session_id = built["design_session"]["design_session_id"]

    cleared = client.post(
        f"/api/migration/ai/design/{session_id}/modify",
        json={"design_session": built["design_session"], "source": "source-preview", "decision_document": built["decision_document"],
              "target_source": "target-preview", "target_device": "device-1",
              "changes": [{"decision_key": decision_key, "value": None}]},
    )

    assert cleared.status_code == 200
    decision = cleared.get_json()["decisions"]["decisions"][0]
    assert decision["value"] is None
    assert decision["review_state"] == "PENDING"
    assert PANMigrationDecisionSet.from_dict(cleared.get_json()["decisions"]).to_options().interfaces == {}


def test_reject_and_stale_target_design_session(monkeypatch):
    state = _design_state()
    client, _ = _install_design_api(monkeypatch, state)
    built = client.post("/api/migration/ai/design", json={"source": "source-preview"}).get_json()
    session_id = built["design_session"]["design_session_id"]
    first_key = built["design_session"]["proposals"][0]["decision_key"]
    rejected = client.post(
        f"/api/migration/ai/design/{session_id}/reject",
        json={"design_session": built["design_session"], "source": "source-preview", "decision_document": built["decision_document"],
              "target_source": "target-preview", "target_device": "device-1",
              "decision_keys": [first_key]},
    )
    assert rejected.status_code == 200
    body = rejected.get_json()
    assert next(item for item in body["design_session"]["proposals"]
                if item["decision_key"] == first_key)["validation_status"] == "REJECTED"
    assert body["design_session"]["summary"]["rejected"] == 1
    audit = body["design_session"]["audit"]
    assert next(item for item in audit if item["decision_key"] == first_key)["engineer_action"] == "REJECTED"

    changed = dict(state, target_digest="different-target")
    monkeypatch.setattr(web, "_build_migration_review_state", lambda *_: changed)
    stale = client.post(
        f"/api/migration/ai/design/{session_id}/approve",
        json={"design_session": body["design_session"], "source": "source-preview", "decision_document": body["decision_document"],
              "target_source": "target-preview", "target_device": "device-1",
              "approve_all": True},
    )
    assert stale.status_code == 409
    assert "stale" in stale.get_json()["error"].lower()


def test_design_session_does_not_depend_on_server_storage(monkeypatch):
    state = _design_state(1)
    client, _ = _install_design_api(monkeypatch, state)
    built = client.post('/api/migration/ai/design', json={'source': 'source-preview'}).get_json()
    assert built['design_session']['signature']
    assert client.get('/api/migration/ai/audit/export').status_code == 404
    assert client.get('/api/migration/ai/design/' + built['design_session']['design_session_id']).status_code == 404


def test_retry_exceptions_reuses_the_stored_session(monkeypatch):
    state = _design_state(1)
    client, _ = _install_design_api(monkeypatch, state)
    built = client.post("/api/migration/ai/design", json={"source": "source-preview"}).get_json()
    retried = client.post("/api/migration/ai/design", json={
        "design_session": built["design_session"], "source": "source-preview", "decision_document": built["decision_document"],
        "target_source": "target-preview", "target_device": "device-1",
        "design_session_id": built["design_session"]["design_session_id"], "retry_exceptions": True,
    })

    assert retried.status_code == 200
    assert retried.get_json()["design_session"]["design_session_id"] == built["design_session"]["design_session_id"]
    assert retried.get_json()["design_session"]["proposals"] == built["design_session"]["proposals"]


def test_design_approval_is_atomic_when_a_candidate_changes(monkeypatch):
    state = _design_state()
    client, _ = _install_design_api(monkeypatch, state)
    built = client.post("/api/migration/ai/design", json={"source": "source-preview"}).get_json()
    session_id = built["design_session"]["design_session_id"]
    first_key = built["design_session"]["proposals"][0]["decision_key"]
    state["decision_candidates"][first_key] = [{
        "value": "ethernet9/99", "target_scope": "vsys1", "class": "STRONG",
        "strong_evidence": ["replacement candidate"], "supporting_evidence": [],
    }]
    failed = client.post(
        f"/api/migration/ai/design/{session_id}/approve",
        json={"design_session": built["design_session"], "source": "source-preview", "decision_document": built["decision_document"],
              "target_source": "target-preview", "target_device": "device-1",
              "approve_all": True},
    )
    assert failed.status_code == 409
    current = built["design_session"]
    assert len(current["proposals"]) == 2
    assert current["summary"]["engineer_confirmed"] == 0


def test_provider_retries_only_transient_failure(monkeypatch):
    state = _state()
    key = state["decisions"].decisions[0].key
    prepared = ai_advisor.build_proposal_context(state, [key], provider="groq")
    calls = []

    def transient_then_ok(value):
        calls.append(value)
        if len(calls) == 1:
            raise ai_advisor.AdvisorTimeoutError("temporary timeout")
        return ai_advisor.validate_model_output(json.dumps({"proposals": _proposal_rows(value)}), value)

    monkeypatch.setattr(ai_advisor, "_request_groq", transient_then_ok)
    monkeypatch.setattr(ai_advisor.time, "sleep", lambda *_: None)
    assert ai_advisor.request_proposals(prepared)
    assert len(calls) == 2

    calls.clear()

    def rejected(value):
        calls.append(value)
        raise ai_advisor.AdvisorRequestError("invalid request")

    monkeypatch.setattr(ai_advisor, "_request_groq", rejected)
    with pytest.raises(ai_advisor.AdvisorRequestError):
        ai_advisor.request_proposals(prepared)
    assert len(calls) == 1

    calls.clear()
    sleeps = []
    monkeypatch.setenv("FWMIGRATE_AI_MAX_RETRY_DELAY_SECONDS", "10")
    monkeypatch.setattr(ai_advisor.time, "sleep", sleeps.append)

    def rate_limited_then_ok(value):
        calls.append(value)
        if len(calls) == 1:
            failure = ai_advisor.AdvisorFailure(
                category="AI_RATE_LIMITED",
                provider="groq",
                model=value["model"],
                retry_after_seconds=2.5,
            )
            raise ai_advisor.AdvisorRateLimitError("rate limited", failure=failure)
        return ai_advisor.validate_model_output(
            json.dumps({"proposals": _proposal_rows(value)}), value
        )

    monkeypatch.setattr(ai_advisor, "_request_groq", rate_limited_then_ok)
    assert ai_advisor.request_proposals(prepared)
    assert len(calls) == 2
    assert sleeps == [2.5]

    calls.clear()
    monkeypatch.setenv("FWMIGRATE_AI_MAX_RETRY_DELAY_SECONDS", "1")

    def long_rate_limit(value):
        calls.append(value)
        failure = ai_advisor.AdvisorFailure(
            category="AI_RATE_LIMITED",
            provider="groq",
            model=value["model"],
            retry_after_seconds=30,
        )
        raise ai_advisor.AdvisorRateLimitError("rate limited", failure=failure)

    monkeypatch.setattr(ai_advisor, "_request_groq", long_rate_limit)
    with pytest.raises(ai_advisor.AdvisorRateLimitError):
        ai_advisor.request_proposals(prepared)
    assert len(calls) == 1


def test_provider_error_records_retry_after_header():
    class RateLimited(Exception):
        status_code = 429
        headers = {"Retry-After": "3.25", "X-Request-Id": "retry-request"}

    error = ai_advisor.classify_provider_error(RateLimited(), provider="groq")
    assert isinstance(error, ai_advisor.AdvisorRateLimitError)
    assert error.failure.retry_after_seconds == 3.25
    assert error.failure.request_id == "retry-request"


def test_design_summary_separates_ready_blocked_and_manual_decisions():
    parent = PANMigrationDecision(
        source_vdom="root", source_kind="vdom", source_name="root",
        target_field="vsys", mode=PANDecisionMode.REQUIRED,
    )
    child = PANMigrationDecision(
        source_vdom="root", source_kind="interface", source_name="port1",
        target_field="target_interface", mode=PANDecisionMode.REQUIRED,
    )
    manual = PANMigrationDecision(
        source_vdom="root", source_kind="zone", source_name="dmz",
        target_field="target_zone", mode=PANDecisionMode.REQUIRED,
    )
    decisions = PANMigrationDecisionSet((parent, child, manual))
    graph = PANDecisionGraph((
        PANDecisionDependency(parent.key),
        PANDecisionDependency(child.key, (parent.key,)),
        PANDecisionDependency(manual.key),
    ))
    design = PANProposedDesign("source", "target", "device", decisions)
    session = PANProposedDesignSession(
        session_id="session", created_at=1, design=design,
        ai_eligible_decision_keys=(parent.key,), dependency_graph=graph,
    )

    summary = session.summary(graph)
    assert summary["ready_unresolved"] == 1
    assert summary["blocked_by_dependency"] == 1
    assert summary["not_ai_eligible"] == 1
    assert summary["blocked"] == 3


def test_proposed_design_splits_rejected_batches_and_keeps_partial_results(monkeypatch):
    state = _design_state(4)
    original_candidates = state["decision_candidates"]
    monkeypatch.setenv("FWMIGRATE_AI_MAX_BATCH", "4")
    monkeypatch.setenv("FWMIGRATE_AI_MAX_REQUEST_BYTES", "49152")
    monkeypatch.setattr(ai_orchestrator, "discover_target_candidates", lambda _source, decisions, *_args, **_kwargs:
                        {item.key: original_candidates[item.key] for item in decisions.decisions})
    monkeypatch.setattr(ai_orchestrator, "build_review_evidence", lambda *_: {})
    monkeypatch.setattr(ai_advisor, "validate_against_target", lambda *_: ())
    monkeypatch.setattr(ai_advisor, "advisor_provider", lambda: "groq")
    monkeypatch.setattr(ai_advisor, "groq_model", lambda tier="complex": f"test-{tier}")
    monkeypatch.setattr(ai_advisor, "classify_advisor_tiers", lambda _state, keys: {key: "simple" for key in keys})
    order = tuple(ai_advisor.ready_proposal_keys(state))
    calls = []

    def request(prepared):
        keys = tuple(prepared["by_decision"])
        calls.append(keys)
        if len(keys) == 4 or keys == order[2:] or keys == (order[2],):
            raise ai_advisor.AdvisorRequestError("provider rejected this batch")
        return ai_advisor.validate_model_output(
            json.dumps({"proposals": _proposal_rows(prepared)}), prepared
        )

    monkeypatch.setattr(ai_advisor, "request_proposals", request)
    session = ai_orchestrator.build_ai_proposed_design(state)

    assert [len(item) for item in calls] == [4, 2, 2, 1, 1]
    assert len(session.design.proposals) == 3
    assert session.failures[0]["decision_keys"] == [order[2]]
    assert session.failure_category == "AI_REQUEST_REJECTED"
    assert session.stable is True
    assert session.summary(state["design_session"].dependency_graph)["ready_unresolved"] == 1


def test_proposed_design_repairs_global_conflicts_in_bounded_batches(monkeypatch):
    state = _design_state(4)
    keys = tuple(item.key for item in state["decisions"].decisions)
    for key, value, alternate in zip(
        keys,
        ("ethernet1/1", "ethernet1/2", "ethernet1/1", "ethernet1/2"),
        ("ethernet1/2", "ethernet1/1", "ethernet1/5", "ethernet1/6"),
    ):
        base = state["decision_candidates"][key][0]
        state["decision_candidates"][key] = [
            {**base, "value": value}, {**base, "value": alternate},
        ]
    initial_values = dict(zip(keys, ("ethernet1/1", "ethernet1/2", "ethernet1/1", "ethernet1/2")))
    original_candidates = state["decision_candidates"]
    monkeypatch.setenv("FWMIGRATE_AI_MAX_BATCH", "2")
    monkeypatch.setenv("FWMIGRATE_AI_MAX_REQUEST_BYTES", "49152")
    monkeypatch.setattr(ai_orchestrator, "discover_target_candidates", lambda _source, decisions, *_args, **_kwargs:
                        {item.key: original_candidates[item.key] for item in decisions.decisions})
    monkeypatch.setattr(ai_orchestrator, "build_review_evidence", lambda *_: {})
    monkeypatch.setattr(ai_advisor, "validate_against_target", lambda *_: ())
    monkeypatch.setattr(ai_advisor, "advisor_provider", lambda: "groq")
    monkeypatch.setattr(ai_advisor, "groq_model", lambda tier="complex": f"test-{tier}")
    monkeypatch.setattr(ai_advisor, "classify_advisor_tiers", lambda _state, decision_keys: {
        key: "simple" for key in decision_keys
    })
    calls = []

    def request(prepared):
        calls.append(prepared)
        rows = (_proposal_rows(prepared) if prepared.get("design_context")
                else _proposal_rows_for_values(prepared, initial_values))
        return ai_advisor.validate_model_output(
            json.dumps({"proposals": rows}), prepared
        )

    monkeypatch.setattr(ai_advisor, "request_proposals", request)
    session = ai_orchestrator.build_ai_proposed_design(state)

    assert [len(item["by_decision"]) for item in calls] == [2, 2, 2, 2]
    assert all(len(item["request"]["decisions"]) <= 2 for item in calls)
    assert [bool(item.get("design_context")) for item in calls] == [False, False, True, True]
    assert len(session.design.proposals) == 4
    assert {item.decision_key for item in session.design.proposals} == set(keys)
    assert all(item.validation_status == "VALID" for item in session.design.proposals)
    assert session.failure_category is None


def test_request_byte_budget_splits_batches_and_never_truncates_candidates(monkeypatch):
    state = _design_state(2)
    keys = tuple(item.key for item in state["decisions"].decisions)
    model = "openai/gpt-oss-20b"
    one = [ai_advisor.build_proposal_context(state, [key], model=model, provider="groq")["request_bytes"]
           for key in keys]
    pair = ai_advisor.build_proposal_context(state, list(keys), model=model, provider="groq")["request_bytes"]
    assert pair > max(one)

    original_candidates = state["decision_candidates"]
    byte_limit = max(one) + 1
    monkeypatch.setenv("FWMIGRATE_AI_MAX_REQUEST_BYTES", str(byte_limit))
    monkeypatch.setenv("FWMIGRATE_AI_MAX_BATCH", "2")
    monkeypatch.setattr(ai_orchestrator, "discover_target_candidates", lambda _source, decisions, *_args, **_kwargs:
                        {item.key: original_candidates[item.key] for item in decisions.decisions})
    monkeypatch.setattr(ai_orchestrator, "build_review_evidence", lambda *_: {})
    monkeypatch.setattr(ai_advisor, "validate_against_target", lambda *_: ())
    monkeypatch.setattr(ai_advisor, "advisor_provider", lambda: "groq")
    monkeypatch.setattr(ai_advisor, "groq_model", lambda tier="complex": model)
    monkeypatch.setattr(ai_advisor, "classify_advisor_tiers", lambda _state, decision_keys: {
        key: "simple" for key in decision_keys
    })
    calls = []

    def request(prepared):
        calls.append(tuple(prepared["by_decision"]))
        assert prepared["request_bytes"] <= byte_limit
        return ai_advisor.validate_model_output(
            json.dumps({"proposals": _proposal_rows(prepared)}), prepared
        )

    monkeypatch.setattr(ai_advisor, "request_proposals", request)
    session = ai_orchestrator.build_ai_proposed_design(state)
    assert [len(item) for item in calls] == [1, 1]
    assert len(session.design.proposals) == 2
    assert all(len(original_candidates[key]) == 1 for key in keys)

    monkeypatch.setenv("FWMIGRATE_AI_MAX_REQUEST_BYTES", "49152")
    candidate_state = _state()
    key = candidate_state["decisions"].decisions[0].key
    candidate_state["decision_candidates"][key] = [
        {**candidate_state["decision_candidates"][key][0], "value": f"ethernet1/{index + 10}"}
        for index in range(1, 5)
    ]
    monkeypatch.setenv("FWMIGRATE_AI_MAX_CANDIDATES_PER_DECISION", "3")
    with pytest.raises(ValueError, match="not AI-eligible"):
        ai_advisor.build_proposal_context(candidate_state, [key], model=model, provider="groq")
    assert len(candidate_state["decision_candidates"][key]) == 4

    pruned_state = _state()
    pruned_key = pruned_state["decisions"].decisions[0].key
    base = pruned_state["decision_candidates"][pruned_key][0]
    pruned_state["decision_candidates"][pruned_key] = [
        {**base, "value": "ethernet1/21", "class": "STRONG",
         "strong_evidence": ["exact address", "matching family"]},
        {**base, "value": "ethernet1/22", "class": "STRONG",
         "strong_evidence": ["exact address"]},
        {**base, "value": "ethernet1/23", "class": "STRONG",
         "strong_evidence": ["matching family"]},
        {**base, "value": "ethernet1/24", "class": "POSSIBLE",
         "strong_evidence": [], "supporting_evidence": ["explicit target interface"]},
    ]
    pruned = ai_advisor.build_proposal_context(
        pruned_state, [pruned_key], model=model, provider="groq"
    )
    assert len(pruned_state["decision_candidates"][pruned_key]) == 4
    assert [item["value"] for item in pruned["request"]["decisions"][0]["candidates"]] == [
        "ethernet1/21", "ethernet1/22", "ethernet1/23",
    ]

    large_state = _design_state(2)
    keys = tuple(item.key for item in large_state["decisions"].decisions)
    large_state["decision_candidates"][keys[0]] = [
        {**large_state["decision_candidates"][keys[0]][0], "value": f"ethernet1/{index + 20}"}
        for index in range(4)
    ]
    large_candidates = large_state["decision_candidates"]
    monkeypatch.setattr(ai_orchestrator, "discover_target_candidates", lambda _source, decisions, *_args, **_kwargs:
                        {item.key: large_candidates[item.key] for item in decisions.decisions})
    monkeypatch.setenv("FWMIGRATE_AI_MAX_CANDIDATES_PER_DECISION", "3")
    calls.clear()
    limited = ai_orchestrator.build_ai_proposed_design(large_state)
    assert calls == [(keys[1],)]
    assert len(limited.design.proposals) == 1
    assert limited.failures == ()
    assert limited.summary(large_state["design_session"].dependency_graph)["not_ai_eligible"] == 1


def test_repair_result_surfaces_failures_and_retries_timeout(monkeypatch):
    state = _two_decision_state()
    decisions = state["decisions"].decisions
    shared = {**state["decision_candidates"][decisions[0].key][0]}
    state["decision_candidates"][decisions[0].key] = [shared, {
        **shared, "value": "ethernet1/2", "strong_evidence": ["fallback one"],
    }]
    state["decision_candidates"][decisions[1].key] = [{**shared}, {
        **shared, "value": "ethernet1/3", "strong_evidence": ["fallback two"],
    }]
    keys = [item.key for item in decisions]
    initial_context = ai_advisor.build_proposal_context(state, keys, provider="groq")
    initial = ai_advisor.validate_model_output(
        json.dumps({"proposals": _proposal_rows(initial_context)}), initial_context
    )
    assert any(item["validation_status"] == "CONFLICT"
               for item in ai_advisor.validate_proposal_set(state, initial))
    monkeypatch.setenv("GROQ_API_KEY", "test-key")
    monkeypatch.setattr(ai_advisor.time, "sleep", lambda *_: None)
    calls = []

    def timeout_then_repair(prepared):
        calls.append(prepared)
        if len(calls) == 1:
            raise ai_advisor.AdvisorTimeoutError("temporary timeout")
        return ai_advisor.validate_model_output(
            json.dumps({"proposals": _proposal_rows(prepared)}), prepared
        )

    monkeypatch.setattr(ai_advisor, "_request_groq", timeout_then_repair)
    repaired = ai_advisor.repair_conflicted_proposals(state, keys, initial)
    assert len(calls) == 2
    assert repaired.failures == ()
    assert not repaired.exhausted

    monkeypatch.setattr(ai_advisor, "_request_groq", lambda *_: (_ for _ in ()).throw(
        ai_advisor.AdvisorRequestError("safe provider failure")
    ))
    failed = ai_advisor.repair_conflicted_proposals(state, keys, initial)
    assert failed.failures[0]["failure_category"] == "AI_REQUEST_REJECTED"
    assert failed.failures[0]["decision_keys"] == keys
    assert failed.exhausted


def test_groq_model_tiering_is_deterministic(monkeypatch):
    state = _design_state(2)
    first, second = (item.key for item in state["decisions"].decisions)
    state["decision_candidates"][second] = [
        {"value": f"ethernet1/{index + 10}", "target_scope": "vsys1", "class": "STRONG",
         "strong_evidence": ["synthetic evidence"], "supporting_evidence": []}
        for index in range(1, 5)
    ]
    for name in ("FWMIGRATE_AI_GROQ_MODEL", "FWMIGRATE_GROQ_MODEL", "FWMIGRATE_AI_MODEL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("FWMIGRATE_AI_SIMPLE_MODEL", "openai/gpt-oss-20b")
    monkeypatch.setenv("FWMIGRATE_AI_COMPLEX_MODEL", "openai/gpt-oss-120b")
    monkeypatch.setenv("FWMIGRATE_AI_REPAIR_MODEL", "openai/gpt-oss-120b")

    tiers = ai_advisor.classify_advisor_tiers(state, [first, second])
    assert tiers == {first: "simple", second: "complex"}
    assert ai_advisor.model_for_decisions(state, [first], provider="groq") == "openai/gpt-oss-20b"
    assert ai_advisor.model_for_decisions(state, [second], provider="groq") == "openai/gpt-oss-120b"
    assert ai_advisor.model_for_decisions(state, [second], provider="groq", repair=True) == "openai/gpt-oss-120b"


def test_successful_parent_unlocks_child_after_unrelated_batch_failure(monkeypatch):
    state = _design_state(chained=True)
    parent, child = state["decisions"].decisions
    other = PANMigrationDecision(
        source_vdom="root", source_kind="zone", source_name="unrelated-zone",
        target_field="target_zone", mode=PANDecisionMode.REQUIRED,
    )
    decisions = PANMigrationDecisionSet((*state["decisions"].decisions, other))
    state["decisions"] = decisions
    state["decision_candidates"][other.key] = [{
        "value": "trust", "target_scope": "vsys1", "class": "STRONG",
        "strong_evidence": ["matching synthetic zone"], "supporting_evidence": [],
    }]
    state["decision_evidence"][other.key] = "TARGET"
    state["review_context"][other.key] = {"source_type": "zone"}
    graph = PANDecisionGraph((
        PANDecisionDependency(parent.key),
        PANDecisionDependency(child.key, (parent.key,)),
        PANDecisionDependency(other.key),
    ))
    state["design_session"] = replace(
        state["design_session"], decisions=decisions, dependency_graph=graph,
        unresolved=tuple(item.key for item in decisions.decisions),
    )
    original_candidates = state["decision_candidates"]
    monkeypatch.setenv("FWMIGRATE_AI_MAX_BATCH", "2")
    monkeypatch.setenv("FWMIGRATE_AI_MAX_REQUEST_BYTES", "49152")
    monkeypatch.setattr(ai_orchestrator, "discover_target_candidates", lambda _source, current, *_args, **_kwargs:
                        {item.key: original_candidates[item.key] for item in current.decisions})
    monkeypatch.setattr(ai_orchestrator, "build_review_evidence", lambda *_: {})
    monkeypatch.setattr(ai_advisor, "validate_against_target", lambda *_: ())
    monkeypatch.setattr(ai_advisor, "advisor_provider", lambda: "groq")
    monkeypatch.setattr(ai_advisor, "groq_model", lambda tier="complex": f"test-{tier}")
    monkeypatch.setattr(ai_advisor, "classify_advisor_tiers", lambda _state, keys: {key: "simple" for key in keys})
    calls = []

    def request(prepared):
        keys = tuple(prepared["by_decision"])
        calls.append(keys)
        if len(keys) > 1 or keys == (other.key,):
            raise ai_advisor.AdvisorRequestError("one request failed")
        return ai_advisor.validate_model_output(
            json.dumps({"proposals": _proposal_rows(prepared)}), prepared
        )

    monkeypatch.setattr(ai_advisor, "request_proposals", request)
    session = ai_orchestrator.build_ai_proposed_design(state)

    assert [len(item) for item in calls] == [2, 1, 1, 1]
    child_proposal = next(item for item in session.design.proposals if item.decision_key == child.key)
    assert child_proposal.dependency_values == ((parent.key, "vsys1"),)
    assert session.failures[0]["decision_keys"] == [other.key]
    assert session.summary(graph)["ai_proposed"] == 2


def test_stored_proposals_are_revalidated_before_provisional_reuse(monkeypatch):
    state = _design_state(chained=True)
    parent, child = state["decisions"].decisions
    original_candidates = state["decision_candidates"]
    monkeypatch.setattr(ai_orchestrator, "discover_target_candidates", lambda _source, decisions, *_args, **_kwargs:
                        {item.key: original_candidates[item.key] for item in decisions.decisions
                         if item.key in original_candidates})
    monkeypatch.setattr(ai_orchestrator, "build_review_evidence", lambda *_: {})
    monkeypatch.setattr(ai_advisor, "validate_against_target", lambda *_: ())
    monkeypatch.setattr(ai_advisor, "advisor_provider", lambda: "groq")
    monkeypatch.setattr(ai_advisor, "groq_model", lambda tier="complex": f"test-{tier}")
    calls = []

    def request(prepared):
        calls.append(prepared)
        return ai_advisor.validate_model_output(
            json.dumps({"proposals": _proposal_rows(prepared)}), prepared
        )

    monkeypatch.setattr(ai_advisor, "request_proposals", request)
    first = ai_orchestrator.build_ai_proposed_design(state)
    assert {item.decision_key for item in first.design.proposals} == {parent.key, child.key}

    original_candidates[parent.key] = [{
        "value": "vsys2", "target_scope": "vsys2", "class": "STRONG",
        "strong_evidence": ["replacement VSYS evidence"], "supporting_evidence": [],
    }]
    calls.clear()
    current = ai_orchestrator.build_ai_proposed_design(state, first)

    assert [tuple(item["by_decision"]) for item in calls] == [(parent.key,), (child.key,)]
    child_context = calls[1]["by_decision"][child.key]
    assert child_context["dependency_values"] == ((parent.key, "vsys2"),)
    assert next(item for item in current.design.proposals if item.decision_key == parent.key).proposed_value == "vsys2"
    assert any(row["decision_key"] == parent.key and row["failure_category"] == "CONTEXT_CHANGED"
               and row["engineer_action"] == "UNRESOLVED" for row in current.audit)
    assert any(row["decision_key"] == child.key and row["failure_category"] == "CONTEXT_CHANGED"
               and row["engineer_action"] == "UNRESOLVED" for row in current.audit)


def test_review_state_synthesizes_before_automation_and_refreshes_after(monkeypatch):
    pending = PANMigrationDecision(
        source_vdom="root", source_kind="interface", source_name="port1",
        target_field="target_interface", mode=PANDecisionMode.REQUIRED,
    )
    suggestion = PANMigrationDecision(
        source_vdom="root", source_kind="interface", source_name="port2",
        target_field="target_interface", mode=PANDecisionMode.SUGGESTED,
    )
    decisions = PANMigrationDecisionSet((pending, suggestion))
    deterministic = replace(
        pending, value="ethernet1/1", review_state=PANDecisionReviewState.CONFIRMED,
        evidence_source="DERIVED", evidence_type="AUTOMATION_VERIFIED",
    )
    resolved = PANMigrationDecisionSet((deterministic, suggestion))
    analysis = SimpleNamespace(extracted=SimpleNamespace(config=object()), derived=object())
    target_context = SimpleNamespace(
        metadata={"vendor": "palo_alto", "config_digest": "target", "device": "device-1"},
        analysis=object(), source_digest="target", selected_device="device-1", devices=("device-1",),
    )
    events = []
    monkeypatch.setattr(web, "_require_complete_collection", lambda *_: None)
    monkeypatch.setattr(web, "_clone_preview", lambda *_: analysis)
    monkeypatch.setattr(migration_review, "build_mapping_requirements", lambda *_: "requirements")
    monkeypatch.setattr(web, "_target_evidence", lambda *_: target_context)
    monkeypatch.setattr(migration_review, "build_decision_set", lambda *_: decisions)
    monkeypatch.setattr(migration_review, "reconcile_target_evidence", lambda current, *_: (current, ()))
    monkeypatch.setattr(migration_review, "build_review_evidence", lambda *_: {})
    monkeypatch.setattr(migration_review, "suggest_from_target", lambda _config, current, *_: (current, {"suggestion": True}))

    def resolve(_config, _derived, current, target, device, *, enabled_policies, **kwargs):
        events.append("resolve")
        assert current is decisions
        assert target is target_context.analysis and device == "device-1"
        assert enabled_policies == (
            web.AutomationPolicy.AUTO_APPLY_VERIFIED,
            web.AutomationPolicy.AUTO_APPLY_DERIVED,
        )
        assert kwargs["requirements"] == "requirements"
        return SimpleNamespace(decisions=resolved, dependency_graph=object())

    monkeypatch.setattr(migration_review, "resolve_design_session_until_stable", resolve)

    def discover(_config, current, *_args, **_kwargs):
        events.append("candidates")
        assert current is (resolved if "resolve" in events else decisions)
        return {}

    def synthesize(current, _results, **kwargs):
        events.append("suggestions")
        assert current is (resolved if "resolve" in events else decisions)
        assert kwargs["candidates"] == {}
        return current

    monkeypatch.setattr(migration_review, "discover_target_candidates", discover)
    monkeypatch.setattr(migration_review, "apply_review_suggestions", synthesize)
    monkeypatch.setattr(migration_review, "validate_against_target", lambda *_: ())
    monkeypatch.setattr(migration_review, "auto_review_results", lambda *_: {})
    monkeypatch.setattr(migration_review, "build_review_context", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(migration_review, "build_review_workflow", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(migration_review, "build_recommendations", lambda *_: [])
    monkeypatch.setattr(migration_review, "target_evidence_changed", lambda *_: False)

    state = web._build_migration_review_state(
        SimpleNamespace(source_digest="source"), {}, apply_deterministic=True
    )
    assert events == ["candidates", "suggestions", "resolve", "candidates", "suggestions"]
    assert state["decisions"] is resolved
    assert state["decisions"].decisions[1].review_state is PANDecisionReviewState.PENDING


def test_design_failure_details_reach_session_logs_and_audit_export(monkeypatch, caplog):
    state = _design_state(1)
    client, _ = _install_design_api(monkeypatch, state)

    class Rejected(Exception):
        status_code = 400
        request_id = "design-request-id"
        body = {"error": {
            "code": "failed_generation", "type": "invalid_request_error",
            "failed_generation": {
                "reason": "Structured output exceeded the completion budget.",
                "content": "submitted prompt and sensitive input",
            },
        }}

    def reject(prepared):
        raise ai_advisor.classify_provider_error(Rejected(), prepared=prepared, provider="groq")

    monkeypatch.setattr(ai_advisor, "request_proposals", reject)
    response = client.post("/api/migration/ai/design", json={"source": "source-preview"})

    assert response.status_code == 200
    session = response.get_json()["design_session"]
    assert session["failure_category"] == "AI_REQUEST_REJECTED"
    assert session["failures"][0]["request_id"] == "design-request-id"
    assert session["failures"][0]["safe_reason"] == "Structured output exceeded the completion budget."
    audit = session["audit"]
    assert audit[0]["event"] == "AI_REQUEST_FAILED"
    assert audit[0]["provider_code"] == "failed_generation"
    assert "submitted prompt" not in json.dumps(audit)
    assert "sensitive input" not in caplog.text
    assert "design-request-id" in caplog.text
