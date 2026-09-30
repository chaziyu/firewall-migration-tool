import io
import pytest

import fwmigrate.web as web
from fwmigrate.deployment import (
    PANCommitResult,
    PANDeploymentResult,
    PANValidationResult,
)


MINIMAL_FORTIGATE = b"""
config firewall address
    edit "host-a"
        set subnet 192.0.2.10 255.255.255.255
    next
end
"""

CREDS = {
    "host": "192.0.2.50",
    "port": 22,
    "username": "admin",
    "password": "secret",
}


def _ready_artifact(client):
    preview = client.post(
        "/api/preview",
        data={"file": (io.BytesIO(MINIMAL_FORTIGATE), "minimal.conf")},
        content_type="multipart/form-data",
    )
    assert preview.status_code == 200
    plan = client.post("/api/migrate", json={
        "preview_id": preview.get_json()["preview_id"],
        "mapping": {"vdoms": {"root": {"vsys": "vsys1"}}},
    })
    assert plan.status_code == 200
    payload = plan.get_json()
    assert payload["plan_status"] == "READY"
    assert payload["commands"] > 0
    return payload["artifact_id"]


class _SuccessfulDeployer:
    options_seen = []

    def __init__(self, options):
        self.options = options
        type(self).options_seen.append(options)

    def deploy(self, rendered):
        return PANDeploymentResult(
            connected=True,
            commands_attempted=len(rendered.commands),
            commands_succeeded=len(rendered.commands),
            validation=PANValidationResult("71", "SUCCESS", "FIN OK"),
        )

    def validate(self):
        return PANValidationResult("72", "SUCCESS", "FIN OK")

    def commit(self):
        return PANCommitResult("73", "SUCCESS", "FIN OK")


class _FailedValidationDeployer(_SuccessfulDeployer):
    def deploy(self, rendered):
        return PANDeploymentResult(
            connected=True,
            commands_attempted=len(rendered.commands),
            commands_succeeded=len(rendered.commands),
            failure_message="candidate validation failed",
            validation=PANValidationResult("71", "FAILED", "FIN FAIL"),
        )


def test_prepare_candidate_forces_validation_and_commit_requires_bound_session(monkeypatch):
    _SuccessfulDeployer.options_seen = []
    monkeypatch.setattr(web, "PANSSHDeployer", _SuccessfulDeployer)
    client = web.create_app({"TESTING": True}).test_client()
    artifact_id = _ready_artifact(client)

    premature = client.post("/api/commit", json={**CREDS, "artifact_id": artifact_id})
    assert premature.status_code == 400
    assert "validated candidate deployment session" in premature.get_json()["error"]

    prepared = client.post("/api/deploy", json={
        **CREDS,
        "artifact_id": artifact_id,
        "validate": False,
    })
    assert prepared.status_code == 200
    payload = prepared.get_json()
    session_id = payload["deployment_session_id"]
    assert session_id
    assert payload["candidate_validated"] is True
    assert payload["result"]["validation"]["status"] == "SUCCESS"
    assert _SuccessfulDeployer.options_seen[-1].validate is True

    wrong_target = client.post("/api/validate-candidate", json={
        **CREDS,
        "host": "192.0.2.51",
        "artifact_id": artifact_id,
        "deployment_session_id": session_id,
    })
    assert wrong_target.status_code == 400
    assert "different PAN-OS target identity" in wrong_target.get_json()["error"]

    wrong_artifact = client.post("/api/commit", json={
        **CREDS,
        "artifact_id": "different-artifact",
        "deployment_session_id": session_id,
    })
    assert wrong_artifact.status_code == 400
    assert "different migration artifact" in wrong_artifact.get_json()["error"]

    revalidated = client.post("/api/validate-candidate", json={
        **CREDS,
        "artifact_id": artifact_id,
        "deployment_session_id": session_id,
    })
    assert revalidated.status_code == 200
    assert revalidated.get_json()["deployment_session_id"] == session_id
    assert revalidated.get_json()["result"]["status"] == "SUCCESS"

    committed = client.post("/api/commit", json={
        **CREDS,
        "artifact_id": artifact_id,
        "deployment_session_id": session_id,
    })
    assert committed.status_code == 200
    assert committed.get_json()["result"]["status"] == "SUCCESS"
    assert committed.get_json()["deployment_session_id"] is None

    replay = client.post("/api/commit", json={
        **CREDS,
        "artifact_id": artifact_id,
        "deployment_session_id": session_id,
    })
    assert replay.status_code == 400
    assert "missing or expired" in replay.get_json()["error"]


def test_failed_candidate_validation_never_creates_commit_session(monkeypatch):
    monkeypatch.setattr(web, "PANSSHDeployer", _FailedValidationDeployer)
    client = web.create_app({"TESTING": True}).test_client()
    artifact_id = _ready_artifact(client)

    prepared = client.post("/api/deploy", json={**CREDS, "artifact_id": artifact_id})
    assert prepared.status_code == 502
    payload = prepared.get_json()
    assert payload["candidate_validated"] is False
    assert payload["deployment_session_id"] is None
    assert payload["result"]["validation"]["status"] == "FAILED"


@pytest.mark.parametrize("failed_retry", [False, True])
def test_candidate_attempt_invalidates_all_old_sessions_for_target(monkeypatch, failed_retry):
    monkeypatch.setattr(web, "PANSSHDeployer", _SuccessfulDeployer)
    client = web.create_app({"TESTING": True}).test_client()
    artifact = _ready_artifact(client)
    old_session = client.post("/api/deploy", json={**CREDS, "artifact_id": artifact}).get_json()["deployment_session_id"]
    next_artifact = artifact if failed_retry else _ready_artifact(client)
    if failed_retry:
        monkeypatch.setattr(web, "PANSSHDeployer", _FailedValidationDeployer)
    attempted = client.post("/api/deploy", json={**CREDS, "username": "other-admin", "artifact_id": next_artifact})
    assert attempted.status_code == (502 if failed_retry else 200)
    commit = client.post("/api/commit", json={**CREDS, "artifact_id": artifact, "deployment_session_id": old_session})
    assert commit.status_code == 400
    assert "missing or expired" in commit.get_json()["error"]


def test_commit_waits_for_candidate_write_and_rejects_stale_session(monkeypatch):
    from concurrent.futures import ThreadPoolExecutor, TimeoutError
    from threading import Event

    monkeypatch.setattr(web, "PANSSHDeployer", _SuccessfulDeployer)
    app = web.create_app({"TESTING": True})
    client = app.test_client()
    artifact = _ready_artifact(client)
    session = client.post("/api/deploy", json={**CREDS, "artifact_id": artifact}).get_json()["deployment_session_id"]
    started, release, committing = Event(), Event(), Event()

    class BlockingDeployer(_FailedValidationDeployer):
        def deploy(self, rendered):
            started.set()
            assert release.wait(5)
            return super().deploy(rendered)

    monkeypatch.setattr(web, "PANSSHDeployer", BlockingDeployer)

    def commit():
        committing.set()
        return app.test_client().post("/api/commit", json={**CREDS, "artifact_id": artifact, "deployment_session_id": session})

    with ThreadPoolExecutor(max_workers=2) as pool:
        write = pool.submit(lambda: app.test_client().post("/api/deploy", json={**CREDS, "artifact_id": artifact}))
        assert started.wait(5)
        pending = pool.submit(commit)
        assert committing.wait(5)
        try:
            with pytest.raises(TimeoutError):
                pending.result(timeout=0.1)
        finally:
            release.set()
        assert write.result(timeout=5).status_code == 502
        assert pending.result(timeout=5).status_code == 400


def test_candidate_write_to_different_target_preserves_validated_session(monkeypatch):
    monkeypatch.setattr(web, "PANSSHDeployer", _SuccessfulDeployer)
    client = web.create_app({"TESTING": True}).test_client()
    artifact = _ready_artifact(client)
    session = client.post("/api/deploy", json={**CREDS, "artifact_id": artifact}).get_json()["deployment_session_id"]
    assert client.post("/api/deploy", json={**CREDS, "host": "192.0.2.51", "artifact_id": artifact}).status_code == 200
    assert client.post("/api/commit", json={**CREDS, "artifact_id": artifact,
        "deployment_session_id": session}).status_code == 200
