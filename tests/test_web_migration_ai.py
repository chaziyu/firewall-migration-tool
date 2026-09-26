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
