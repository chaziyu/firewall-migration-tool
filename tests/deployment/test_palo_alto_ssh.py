import sys
from types import SimpleNamespace
import pytest

from fwmigrate.deployment import PANDeploymentOptions, PANSSHDeployer
from fwmigrate.conversion.fortigate_to_palo_alto.renderer import RenderedMigration


def rendered(*commands):
    return RenderedMigration(tuple(commands), {"commands": len(commands)})


class FakeConnection:
    def __init__(self, command_responses=(), validation_responses=(), config_error=None):
        self.command_responses = iter(command_responses)
        self.validation_responses = iter(validation_responses)
        self.config_error = config_error
        self.disconnected = False
        self.commits = 0

    def config_mode(self):
        if self.config_error:
            raise self.config_error

    def send_config_set(self, commands):
        response = next(self.command_responses)
        if isinstance(response, Exception):
            raise response
        return response

    def send_command(self, command):
        response = next(self.validation_responses)
        if isinstance(response, Exception):
            raise response
        return response

    def commit(self):
        self.commits += 1
        return "Job 123"

    def disconnect(self):
        self.disconnected = True


def fake_netmiko(monkeypatch, connect):
    monkeypatch.setitem(sys.modules, "netmiko", SimpleNamespace(ConnectHandler=connect))


def test_successful_candidate_push_and_validation_without_default_commit(monkeypatch):
    connection = FakeConnection(["ok"], ["Job 42", "FIN: OK"])
    fake_netmiko(monkeypatch, lambda **kwargs: connection)

    result = PANSSHDeployer(PANDeploymentOptions("fw", "admin", "secret")).deploy(rendered("set one"))

    assert result.commands_succeeded == 1
    assert result.validation.status == "SUCCESS"
    assert result.commit.status == "NOT_RUN"
    assert connection.commits == 0
    assert connection.disconnected


def test_connection_failure_is_safe(monkeypatch):
    fake_netmiko(monkeypatch, lambda **kwargs: (_ for _ in ()).throw(RuntimeError("bad secret")))

    result = PANSSHDeployer(PANDeploymentOptions("fw", "admin", "secret")).deploy(rendered("set one"))

    assert not result.connected
    assert "secret" not in result.failure_message


def test_command_rejection_disconnects(monkeypatch):
    connection = FakeConnection(["ERROR: invalid value"])
    fake_netmiko(monkeypatch, lambda **kwargs: connection)

    result = PANSSHDeployer(PANDeploymentOptions("fw", "admin", "secret")).deploy(rendered("set one"))

    assert result.failed_command_index == 0
    assert connection.disconnected


def test_command_exception_disconnects_and_redacts_password(monkeypatch):
    connection = FakeConnection([RuntimeError("transport failed secret")])
    fake_netmiko(monkeypatch, lambda **kwargs: connection)

    result = PANSSHDeployer(PANDeploymentOptions("fw", "admin", "secret")).deploy(rendered("set one"))

    assert result.failed_command_index == 0
    assert "secret" not in result.failure_message
    assert "secret" not in repr(result)
    assert connection.disconnected


def test_validation_failure_and_timeout_disconnect(monkeypatch):
    for response in (["Job 8", "ERROR: invalid configuration"], [TimeoutError("timeout secret")]):
        connection = FakeConnection(["ok"], response)
        fake_netmiko(monkeypatch, lambda **kwargs: connection)

        result = PANSSHDeployer(PANDeploymentOptions("fw", "admin", "secret")).deploy(rendered("set one"))

        assert result.validation.status == "FAILED"
        assert "secret" not in result.validation.response
        assert connection.disconnected


def test_config_mode_failure_disconnects(monkeypatch):
    connection = FakeConnection(config_error=RuntimeError("failed secret"))
    fake_netmiko(monkeypatch, lambda **kwargs: connection)

    result = PANSSHDeployer(PANDeploymentOptions("fw", "admin", "secret")).deploy(rendered("set one"))

    assert "secret" not in result.failure_message
    assert connection.disconnected


def test_explicit_commit_runs_only_after_successful_validation(monkeypatch):
    connection = FakeConnection(["ok"], ["Job 42", "FIN: OK"])
    fake_netmiko(monkeypatch, lambda **kwargs: connection)

    result = PANSSHDeployer(PANDeploymentOptions("fw", "admin", "secret", commit=True)).deploy(rendered("set one"))

    assert result.commit.status == "SUCCESS"
    assert connection.commits == 1
    assert connection.disconnected


def test_deploy_rejects_arbitrary_commands(monkeypatch):
    with pytest.raises(TypeError, match="RenderedMigration"):
        PANSSHDeployer(PANDeploymentOptions("fw", "admin", "secret")).deploy(["set one"])
