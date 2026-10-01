from dataclasses import FrozenInstanceError

import pytest

from fwmigrate.deployment import (
    PANCommitResult,
    PANDeploymentCommandResult,
    PANDeploymentOptions,
    PANDeploymentResult,
    PANDeploymentSession,
    PANValidationResult,
)


def test_deployment_models_defaults_and_secret_repr():
    options = PANDeploymentOptions("fw", "admin", "secret")
    result = PANDeploymentResult(False)

    assert options.port == 22
    assert options.validate is True
    with pytest.raises(TypeError):
        PANDeploymentOptions("fw", "admin", "secret", commit=True)
    assert options.job_poll_interval == 1.0
    assert options.job_poll_attempts == 60
    assert "secret" not in repr(options)
    assert result.validation.status == "NOT_RUN"
    assert PANValidationResult().status == "NOT_RUN"
    assert PANCommitResult().status == "NOT_RUN"
    assert PANDeploymentCommandResult(0, "set x", True).accepted
    session = PANDeploymentSession(
        "session-1", "artifact-1", 2, "abc123", "fw", 22, "7", 123.0,
    )
    assert session.artifact_id == "artifact-1"
    assert session.command_count == 2
    assert "secret" not in repr(session)


def test_deployment_models_are_immutable():
    with pytest.raises(FrozenInstanceError):
        PANDeploymentOptions("fw", "admin", "secret").port = 23
    with pytest.raises(FrozenInstanceError):
        PANDeploymentSession(
            "session-1", "artifact-1", 1, "abc", "fw", 22, "7", 123.0,
        ).artifact_id = "artifact-2"
