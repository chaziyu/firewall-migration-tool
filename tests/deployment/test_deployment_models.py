from dataclasses import FrozenInstanceError

import pytest

from fwmigrate.deployment import (
    PANCommitResult,
    PANDeploymentCommandResult,
    PANDeploymentOptions,
    PANDeploymentResult,
    PANValidationResult,
)


def test_deployment_models_defaults_and_secret_repr():
    options = PANDeploymentOptions("fw", "admin", "secret")
    result = PANDeploymentResult(False)

    assert options.port == 22
    assert options.validate is True
    assert options.commit is False
    assert "secret" not in repr(options)
    assert result.validation.status == "NOT_RUN"
    assert PANValidationResult().status == "NOT_RUN"
    assert PANCommitResult().status == "NOT_RUN"
    assert PANDeploymentCommandResult(0, "set x", True).accepted


def test_deployment_models_are_immutable():
    with pytest.raises(FrozenInstanceError):
        PANDeploymentOptions("fw", "admin", "secret").port = 23
