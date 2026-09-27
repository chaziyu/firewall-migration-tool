import io
import json
import re
from pathlib import Path

import pytest

from fwmigrate.ai.errors import AIProviderError, AIRateLimitError, AITimeoutError
from fwmigrate.ai.provider import AIStructuredResult
from fwmigrate.web import create_app

FIXTURE = Path(__file__).parent / "fixtures" / "fortigate" / "palo_alto_mvp.conf"
TARGET = Path(__file__).parent / "fixtures" / "palo_alto" / "integrated_firewall.xml"


def _preview(client, path, vendor="fortigate"):
    response = client.post("/api/preview", data={"source_vendor": vendor,
        "file": (io.BytesIO(path.read_bytes()), path.name)}, content_type="multipart/form-data")
    assert response.status_code == 200
    return response.get_json()["preview_id"]


def _preview_target_with_changed_bytes(client):
    raw = TARGET.read_bytes() + b"\n"
    response = client.post("/api/preview", data={"source_vendor": "palo_alto",
        "file": (io.BytesIO(raw), "changed-target.xml")}, content_type="multipart/form-data")
    assert response.status_code == 200
    return response.get_json()["preview_id"]


def _preview_target_with_more_changed_bytes(client):
    raw = TARGET.read_bytes() + b"\n\n"
    response = client.post("/api/preview", data={"source_vendor": "palo_alto",
        "file": (io.BytesIO(raw), "changed-target.xml")}, content_type="multipart/form-data")
    assert response.status_code == 200
    return response.get_json()["preview_id"]


class FakeProvider:
    def __init__(self): self.payload = None
    def generate_structured(self, *, system_prompt, payload, schema_name, schema):
        self.payload = payload
        if schema_name == "fg_pan_candidate_comparison":
            group = payload["group"]
            comparisons = [{"candidate_value": candidate["value"], "evidence": candidate["evidence"], "limitations": []}
                           for decision in group["decisions"] for candidate in decision["candidates"]]
            return AIStructuredResult({"title": "Candidate comparison", "summary": "Compare supplied evidence.",
                "comparisons": comparisons, "rationale": ["Only deterministic evidence was considered."],
                "missing_information": [], "limitations": []}, "groq", "test-model", "request-test", 10, 5)
        selected = next((decision for group in payload["groups"] for decision in group["decisions"]
                         if decision["allowed_values"]), None)
        results = []
        if selected:
            value = selected["allowed_values"][0]
            evidence = selected["candidates"][0]["evidence"]
            results.append({"kind": "MAPPING_RECOMMENDATION", "title": "Review mapping",
                "summary": "Review the known candidate.", "question": "", "decision_keys": [selected["key"]],
                "assignments": [{"decision_key": selected["key"], "value": value}], "evidence": evidence,
                "choices": [], "comparisons": [],
                "rationale": ["The deterministic engine supplied this candidate."],
                "missing_information": [], "limitations": []})
        return AIStructuredResult({"results": results}, "groq", "test-model", "request-test", 10, 5)


class BulkProvider:
    def generate_structured(self, *, payload, schema_name, **kwargs):
        results = []
        for group in payload["groups"]:
            for decision in group["decisions"]:
                candidate = next((item for item in decision["candidates"] if item["evidence"]), None)
                if not candidate:
                    continue
                result = {"kind": "MAPPING_RECOMMENDATION", "title": "Use supported candidate",
                    "summary": "The supplied evidence supports this candidate.", "question": "",
                    "decision_keys": [decision["key"]],
                    "assignments": [{"decision_key": decision["key"], "value": candidate["value"]}],
                    "evidence": [candidate["evidence"][0]], "choices": [], "comparisons": [],
                    "rationale": [], "missing_information": [], "limitations": []}
                results.append(result)
                if len(results) == 1:
                    # Two separately cached proposals for one decision exercise batch de-duplication.
                    results.append({**result, "title": "Repeated candidate proposal"})
                if len(results) >= 8:
                    break
            if len(results) >= 8:
                break
        return AIStructuredResult({"results": results}, "groq", "test-model", "request-test", 10, 5)


class SelectionProvider:
    def __init__(self): self.payload = None; self.calls = 0
    def generate_structured(self, *, payload, **kwargs):
        self.calls += 1
        self.payload = payload
        group = payload["group"]
        decision = next(item for item in group["decisions"] if item["allowed_values"])
        option = decision["candidates"][0]
        evidence = option["strong_evidence"][:1] or option["supporting_evidence"][:1]
        return AIStructuredResult({"decision_keys": [decision["key"]],
            "suggested_assignments": [{"decision_key": decision["key"], "value": option["value"]}],
            "rationale": ["The supplied option evidence supports this choice."], "evidence": evidence,
            "alternatives": [], "missing_information": [], "limitations": []},
            "groq", "test-model", "request-test", 10, 5)


def test_ai_disabled_isolated_from_deterministic_review(monkeypatch):
    monkeypatch.setenv("AI_ASSIST_ENABLED", "false")
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    client = create_app({"TESTING": True}).test_client()
    status = client.get("/api/migration/ai/status")
    assert status.get_json() == {"enabled": False, "available": False}
    preview_id = _preview(client, FIXTURE)
    assert client.post("/api/migration/requirements", json={"preview_id": preview_id}).status_code == 200
    disabled = client.post("/api/migration/ai/analyze", json={"preview_id": preview_id,
        "source_facts": {"injected": True}, "decision_candidates": {"fake": ["invented"]}})
    assert disabled.status_code == 503


def test_local_ai_status_is_safe_and_exposes_install_size(monkeypatch, tmp_path):
    from fwmigrate.ai import local_model
    from fwmigrate.ai.manifests import LOCAL_MODEL

    monkeypatch.delenv("AI_ASSIST_ENABLED", raising=False)
    monkeypatch.setattr(local_model, "local_ai_data_dir", lambda: tmp_path / "app-data")
    result = create_app({"TESTING": True}).test_client().get("/api/migration/ai/status").get_json()
    assert result["provider"] == "local"
    assert result["available"] is False
    assert result["local"]["download_bytes"] == LOCAL_MODEL.size_bytes
    assert not ({"api_key", "pid", "base_url", "path"} & result["local"].keys())


@pytest.mark.parametrize("error,status", [(AIRateLimitError, 429), (AITimeoutError, 504), (AIProviderError, 502)])
def test_ai_provider_error_status_is_preserved(monkeypatch, error, status):
    monkeypatch.setenv("AI_ASSIST_ENABLED", "true")
    monkeypatch.setenv("GROQ_API_KEY", "test-key")

    class FailingProvider:
        def generate_structured(self, **kwargs):
            raise error("provider failure")

    client = create_app({"TESTING": True, "AI_PROVIDER_INSTANCE": FailingProvider()}).test_client()
    preview_id = _preview(client, FIXTURE)
    target_id = _preview(client, TARGET, "palo_alto")
    response = client.post("/api/migration/ai/analyze", json={"preview_id": preview_id,
        "target_preview_id": target_id})
    assert response.status_code == status


def test_analysis_rebuilds_context_and_confirmation_records_engineer_provenance(monkeypatch):
    monkeypatch.setenv("AI_ASSIST_ENABLED", "true")
    monkeypatch.setenv("GROQ_API_KEY", "test-key")
    provider = FakeProvider()
    app = create_app({"TESTING": True, "AI_PROVIDER_INSTANCE": provider})
    client = app.test_client()
    preview_id = _preview(client, FIXTURE)
    target_id = _preview(client, TARGET, "palo_alto")
    payload = {"preview_id": preview_id, "target_preview_id": target_id}
    deterministic = client.post("/api/migration/requirements", json=payload).get_json()
    request_body = payload | {"decision_document": deterministic["decision_document"],
                               "source_facts": {"injected": "not trusted"}}
    response = client.post("/api/migration/ai/analyze", json=request_body)
    assert response.status_code == 200
    assert response.get_json()["covered_decisions"] == 1
    assert response.get_json()["omitted_decision_keys"]
    assert "source_facts" not in provider.payload
    assert "injected" not in str(provider.payload)
    assert not re.search(r"(?<![A-Za-z0-9])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?![A-Za-z0-9])", json.dumps(provider.payload))
    proposal = response.get_json()["proposals"][0]
    assert proposal["choices"]
    accepted = client.post("/api/migration/ai/confirm", json=request_body | {
        "proposal_id": proposal["proposal_id"], "choice_index": 0,
    })
    assert accepted.status_code == 200
    result = accepted.get_json()
    confirmed = [item for item in result["decisions"]["decisions"] if item["evidence_type"] == "ENGINEER_ACCEPTED_AI_SUGGESTION"]
    assert len(confirmed) == 1
    assert confirmed[0]["evidence_source"] == "ENGINEER"
    assert confirmed[0]["review_state"] == "CONFIRMED"
    assert confirmed[0]["evidence_value"]["proposal_id"] == proposal["proposal_id"]


def test_analysis_skips_ai_when_review_has_no_candidate_values(monkeypatch):
    monkeypatch.setenv("AI_ASSIST_ENABLED", "true")
    monkeypatch.setenv("GROQ_API_KEY", "test-key")

    class MustNotRun:
        def generate_structured(self, **kwargs):
            raise AssertionError("AI must not receive no-candidate design work")

    client = create_app({"TESTING": True, "AI_PROVIDER_INSTANCE": MustNotRun()}).test_client()
    preview_id = _preview(client, FIXTURE)
    response = client.post("/api/migration/ai/analyze", json={"preview_id": preview_id})
    assert response.status_code == 200
    assert response.get_json()["candidate_backed_groups"] == 0
    assert response.get_json()["insufficient_evidence"] > 0
    assert response.get_json()["proposals"] == []


def test_confirmation_rejects_stale_proposal(monkeypatch):
    monkeypatch.setenv("AI_ASSIST_ENABLED", "true")
    monkeypatch.setenv("GROQ_API_KEY", "test-key")
    provider = FakeProvider()
    client = create_app({"TESTING": True, "AI_PROVIDER_INSTANCE": provider}).test_client()
    preview_id = _preview(client, FIXTURE)
    target_id = _preview(client, TARGET, "palo_alto")
    payload = {"preview_id": preview_id, "target_preview_id": target_id}
    decisions = client.post("/api/migration/requirements", json=payload).get_json()
    request_body = payload | {"decision_document": decisions["decision_document"]}
    proposals = client.post("/api/migration/ai/analyze", json=request_body).get_json()["proposals"]
    changed_target_id = _preview_target_with_changed_bytes(client)
    stale = client.post("/api/migration/ai/confirm", json=request_body | {
        "target_preview_id": changed_target_id, "proposal_id": proposals[0]["proposal_id"], "choice_index": 0,
    })
    assert stale.status_code == 409
    assert "stale" in stale.get_json()["error"].lower()


def test_candidate_explanation_uses_server_group_without_changing_decisions(monkeypatch):
    monkeypatch.setenv("AI_ASSIST_ENABLED", "true")
    monkeypatch.setenv("GROQ_API_KEY", "test-key")
    provider = FakeProvider()
    client = create_app({"TESTING": True, "AI_PROVIDER_INSTANCE": provider}).test_client()
    preview_id = _preview(client, FIXTURE)
    target_id = _preview(client, TARGET, "palo_alto")
    payload = {"preview_id": preview_id, "target_preview_id": target_id}
    requirements = client.post("/api/migration/requirements", json=payload).get_json()
    group = next(item for item in requirements["review_groups"]
                 if item["queue"] == "CHOOSE_CANDIDATE" and item["candidates"])
    response = client.post("/api/migration/ai/explain", json=payload | {
        "decision_document": requirements["decision_document"], "source_vdom": group["source_vdom"],
        "source_kind": group["source_kind"], "source_name": group["source_name"],
        "group": {"source_name": "browser-injected"},
    })
    assert response.status_code == 200
    assert "browser-injected" not in json.dumps(provider.payload)
    assert response.get_json()["proposal"]["kind"] == "CANDIDATE_COMPARISON"
    rejected = client.post("/api/migration/ai/confirm", json=payload | {
        "decision_document": requirements["decision_document"],
        "proposal_id": response.get_json()["proposal"]["proposal_id"], "choice_index": 0,
    })
    assert rejected.status_code == 409
    assert requirements["decisions"] == client.post("/api/migration/requirements", json=payload).get_json()["decisions"]


def test_selection_uses_server_options_stages_no_decisions_and_cannot_be_confirmed(monkeypatch):
    from dataclasses import replace
    from fwmigrate import web as web_module
    from fwmigrate.conversion.fortigate_to_palo_alto.decisions import (
        PANDecisionMode, PANMigrationDecisionSet,
    )

    monkeypatch.setenv("AI_ASSIST_ENABLED", "true")
    monkeypatch.setenv("AI_PROVIDER", "groq")
    monkeypatch.setenv("GROQ_API_KEY", "test-key")
    provider = SelectionProvider()
    client = create_app({"TESTING": True, "AI_PROVIDER_INSTANCE": provider}).test_client()
    preview_id = _preview(client, FIXTURE)
    target_id = _preview(client, TARGET, "palo_alto")
    payload = {"preview_id": preview_id, "target_preview_id": target_id}
    requirements = client.post("/api/migration/requirements", json=payload).get_json()
    original_ai_state = web_module._build_ai_review_state
    def manual_ai_state(body):
        state = original_ai_state(body)
        decision = next(item for item in state["decisions"].decisions if item.target_field == "vsys")
        replacement = replace(decision, mode=PANDecisionMode.REQUIRED)
        state["decisions"] = PANMigrationDecisionSet(tuple(
            replacement if item.key == decision.key else item for item in state["decisions"].decisions))
        state["auto_decisions"][decision.key] = {"status": "MANUAL"}
        group = next(item for item in state["review_workflow"]["review_groups"] if item["source_kind"] == "vdom")
        group["queue"] = "NEEDS_INPUT"
        state["ai_selection_options"] = {decision.key: [{"value": "vsys-choice", "target_scope": "vsys:explicit",
            "strong_evidence": ["Explicit PAN VSYS"], "supporting_evidence": [], "contradictions": []}]}
        return state
    monkeypatch.setattr(web_module, "_build_ai_review_state", manual_ai_state)
    group = next(item for item in requirements["review_groups"] if item["source_kind"] == "vdom")
    body = payload | {"decision_document": requirements["decision_document"],
        "source_vdom": group["source_vdom"], "source_kind": group["source_kind"],
        "source_name": group["source_name"],
        "ai_selection_options": {"injected": [{"value": "invented"}]}}
    result = client.post("/api/migration/ai/select", json=body)
    assert result.status_code == 200, (result.get_json(), provider.payload)
    proposal = result.get_json()["proposal"]
    assert proposal["kind"] == "SELECTION_SUGGESTION"
    allowed = {value for item in provider.payload["group"]["decisions"] for value in item["allowed_values"]}
    assert proposal["choices"][0]["assignments"][0]["value"] in allowed
    assert "injected" not in json.dumps(provider.payload)
    unchanged = client.post("/api/migration/requirements", json=payload).get_json()
    assert unchanged["decisions"] == requirements["decisions"]
    rejected = client.post("/api/migration/ai/confirm", json=body | {
        "proposal_id": proposal["proposal_id"], "choice_index": 0})
    assert rejected.status_code == 409
    changed_target = _preview_target_with_changed_bytes(client)
    refreshed = client.post("/api/migration/ai/select", json=body | {"target_preview_id": changed_target})
    assert refreshed.status_code == 200
    assert provider.calls == 2
    assert refreshed.get_json()["proposal"]["context_digest"] != proposal["context_digest"]


def test_bulk_confirmation_is_atomic_and_rejects_duplicate_and_nonrecommendation_proposals(monkeypatch):
    monkeypatch.setenv("AI_ASSIST_ENABLED", "true")
    monkeypatch.setenv("GROQ_API_KEY", "test-key")
    client = create_app({"TESTING": True, "AI_PROVIDER_INSTANCE": BulkProvider()}).test_client()
    preview_id = _preview(client, FIXTURE)
    target_id = _preview_target_with_changed_bytes(client)
    payload = {"preview_id": preview_id, "target_preview_id": target_id}
    requirements = client.post("/api/migration/requirements", json=payload).get_json()
    body = payload | {"decision_document": requirements["decision_document"]}
    proposals = client.post("/api/migration/ai/analyze", json=body).get_json()["proposals"]
    by_decision = {}
    for proposal in proposals:
        by_decision.setdefault(proposal["decision_keys"][0], []).append(proposal)
    duplicate_pair = next(items[:2] for items in by_decision.values() if len(items) > 1)
    distinct = [items[0] for items in by_decision.values()]
    assert len(distinct) >= 2

    duplicate = client.post("/api/migration/ai/confirm-bulk", json=body | {
        "proposal_ids": [item["proposal_id"] for item in duplicate_pair]})
    assert duplicate.status_code == 409
    assert "same decision" in duplicate.get_json()["error"]

    stale_key = distinct[0]["decision_keys"][0]
    changed_document = json.loads(json.dumps(requirements["decision_document"]))
    stale_decision = next(item for item in changed_document["decisions"] if item["key"] == stale_key)
    stale_decision["value"] = distinct[0]["choices"][0]["assignments"][0]["value"]
    stale_decision["review_state"] = "CONFIRMED"
    refreshed_body = payload | {"decision_document": changed_document}
    refreshed = client.post("/api/migration/ai/analyze", json=refreshed_body).get_json()["proposals"]
    fresh = next(item for item in refreshed if item["decision_keys"][0] != stale_key)
    stale_one = client.post("/api/migration/ai/confirm-bulk", json=refreshed_body | {
        "proposal_ids": [distinct[0]["proposal_id"], fresh["proposal_id"]]})
    assert stale_one.status_code == 409
    assert "stale" in stale_one.get_json()["error"].lower()

    stale = client.post("/api/migration/ai/confirm-bulk", json=body | {
        "target_preview_id": _preview_target_with_more_changed_bytes(client),
        "proposal_ids": [item["proposal_id"] for item in distinct[:2]]})
    assert stale.status_code == 409
    accepted = client.post("/api/migration/ai/confirm-bulk", json=body | {
        "proposal_ids": [item["proposal_id"] for item in distinct[:2]]})
    assert accepted.status_code == 200
    confirmed = [item for item in accepted.get_json()["decisions"]["decisions"]
                 if item["evidence_type"] == "ENGINEER_ACCEPTED_AI_SUGGESTION"]
    assert len(confirmed) == 2

    comparison_client = create_app({"TESTING": True, "AI_PROVIDER_INSTANCE": FakeProvider()}).test_client()
    preview_id = _preview(comparison_client, FIXTURE)
    target_id = _preview(comparison_client, TARGET, "palo_alto")
    payload = {"preview_id": preview_id, "target_preview_id": target_id}
    requirements = comparison_client.post("/api/migration/requirements", json=payload).get_json()
    group = next(item for item in requirements["review_groups"] if item["queue"] == "CHOOSE_CANDIDATE" and item["candidates"])
    explained = comparison_client.post("/api/migration/ai/explain", json=payload | {
        "decision_document": requirements["decision_document"], "source_vdom": group["source_vdom"],
        "source_kind": group["source_kind"], "source_name": group["source_name"]}).get_json()["proposal"]
    rejected = comparison_client.post("/api/migration/ai/confirm-bulk", json=payload | {
        "decision_document": requirements["decision_document"], "proposal_ids": [explained["proposal_id"]]})
    assert rejected.status_code == 409


def test_prepare_draft_accounts_for_pending_decisions_and_rejects_stale_approval(monkeypatch):
    monkeypatch.setenv("AI_ASSIST_ENABLED", "true")
    monkeypatch.setenv("AI_PROVIDER", "groq")
    monkeypatch.setenv("GROQ_API_KEY", "test-key")
    client = create_app({"TESTING": True, "AI_PROVIDER_INSTANCE": SelectionProvider()}).test_client()
    preview_id = _preview(client, FIXTURE)
    target_id = _preview(client, TARGET, "palo_alto")
    body = {"preview_id": preview_id, "target_preview_id": target_id}
    initial = client.post("/api/migration/requirements", json=body).get_json()
    body["decision_document"] = initial["decision_document"]
    draft = None
    for _ in range(200):
        response = client.post("/api/migration/ai/prepare-draft", json=body | (
            {"draft_id": draft["draft_id"], "revision": draft["revision"]} if draft else {}))
        assert response.status_code == 200, response.get_json()
        draft = response.get_json()["draft"]
        if draft["complete"]:
            break
    assert draft["complete"]
    caught_up = client.post("/api/migration/ai/prepare-draft", json=body | {
        "draft_id": draft["draft_id"], "revision": draft["revision"] - 1})
    assert caught_up.status_code == 200
    assert caught_up.get_json()["draft"]["revision"] == draft["revision"]
    pending = {item["key"] for item in initial["decisions"]["decisions"]
               if item["review_state"] == "PENDING" and item["mode"] not in {"AUTO", "UNSUPPORTED"}}
    covered = {assignment["decision_key"] for proposal in draft["proposals"]
               for choice in proposal["choices"] for assignment in choice["assignments"]}
    blocked = {item["decision_key"] for item in draft["blockers"]}
    assert covered
    assert pending == covered | blocked
    assert not covered & blocked
    assert initial["decisions"] == client.post("/api/migration/requirements", json={
        "preview_id": preview_id, "target_preview_id": target_id}).get_json()["decisions"]
    if covered:
        stale_revision = client.post("/api/migration/ai/confirm-draft", json=body | {
            "draft_id": draft["draft_id"], "revision": draft["revision"] - 1,
            "selected_decision_keys": [next(iter(covered))]})
        assert stale_revision.status_code == 409
        if draft["dependencies"]:
            dependent = draft["dependencies"][0]["decision_key"]
            partial = client.post("/api/migration/ai/confirm-draft", json=body | {
                "draft_id": draft["draft_id"], "revision": draft["revision"],
                "selected_decision_keys": [dependent]})
            assert partial.status_code == 409
        first = draft["proposals"][0]
        chosen = [item["decision_key"] for item in first["choices"][0]["assignments"]]
        accepted = client.post("/api/migration/ai/confirm-draft", json=body | {
            "draft_id": draft["draft_id"], "revision": draft["revision"],
            "selected_decision_keys": chosen})
        assert accepted.status_code == 200, accepted.get_json()
        assert accepted.get_json()["confirmed_count"] == len(chosen)
        stale = client.post("/api/migration/ai/confirm-draft", json=body | {
            "target_preview_id": _preview_target_with_changed_bytes(client),
            "draft_id": draft["draft_id"], "revision": draft["revision"],
            "selected_decision_keys": [next(iter(covered))]})
        assert stale.status_code == 409
