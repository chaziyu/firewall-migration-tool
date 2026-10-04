import sys
from types import SimpleNamespace
import pytest

from fwmigrate.deployment import PANDeploymentOptions, PANSSHDeployer
from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import RenderedMigration


def rendered(*commands, plan_status="READY"):
    return RenderedMigration(tuple(commands), {"commands": len(commands), "plan_status": plan_status})


class FakeConnection:
    def __init__(self, command_responses=(), validation_responses=(), config_error=None):
        self.command_responses = iter(command_responses)
        self.validation_responses = iter(validation_responses)
        self.config_error = config_error
        self.disconnected = False
        self.commits = 0
        self.in_config_mode = False

    def config_mode(self):
        if self.config_error:
            raise self.config_error
        self.in_config_mode = True

    def exit_config_mode(self):
        self.in_config_mode = False

    def send_config_set(self, commands, **kwargs):
        assert self.in_config_mode
        assert kwargs == {"exit_config_mode": False, "strip_command": True, "strip_prompt": True}
        response = next(self.command_responses)
        if isinstance(response, Exception):
            raise response
        return response

    def send_command(self, command):
        assert self.in_config_mode == (command == "validate full")
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
    connection = FakeConnection(["ok"], ["Job 42", "FIN: OK", "FIN: OK"])
    fake_netmiko(monkeypatch, lambda **kwargs: connection)

    result = PANSSHDeployer(PANDeploymentOptions("fw", "admin", "secret")).deploy(rendered("set one"))

    assert result.commands_succeeded == 1
    assert result.validation.status == "SUCCESS"
    assert result.commit.status == "NOT_RUN"
    assert connection.commits == 0
    assert connection.disconnected


def test_zero_command_artifact_is_rejected_before_connecting(monkeypatch):
    fake_netmiko(monkeypatch, lambda **kwargs: (_ for _ in ()).throw(AssertionError("must not connect")))
    result = PANSSHDeployer(PANDeploymentOptions("fw", "admin", "secret")).deploy(rendered())
    assert not result.connected
    assert result.failure_message == "The rendered migration has no commands to deploy"


def test_partial_artifact_is_rejected_before_connecting(monkeypatch):
    fake_netmiko(monkeypatch, lambda **kwargs: (_ for _ in ()).throw(AssertionError("must not connect")))

    result = PANSSHDeployer(PANDeploymentOptions("fw", "admin", "secret")).deploy(
        rendered("set one", plan_status="PARTIAL")
    )

    assert not result.connected
    assert "requires a READY migration artifact" in result.failure_message


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


def test_validation_polls_until_finished(monkeypatch):
    connection = FakeConnection(["ok"], ["Job 8", "ACT", "PEND", "FIN: OK"])
    fake_netmiko(monkeypatch, lambda **kwargs: connection)

    result = PANSSHDeployer(PANDeploymentOptions(
        "fw", "admin", "secret", job_poll_interval=0, job_poll_attempts=3,
    )).deploy(rendered("set one"))

    assert result.validation.status == "SUCCESS"
    assert result.failure_message is None
    assert connection.disconnected


def test_validation_failure_and_transport_timeout_disconnect(monkeypatch):
    for response in (["Job 8", "ERROR: invalid configuration"], [TimeoutError("timeout secret")]):
        connection = FakeConnection(["ok"], response)
        fake_netmiko(monkeypatch, lambda **kwargs: connection)

        result = PANSSHDeployer(PANDeploymentOptions("fw", "admin", "secret")).deploy(rendered("set one"))

        assert result.validation.status == "FAILED"
        assert result.failure_message
        assert "secret" not in result.validation.response
        assert connection.disconnected


def test_validation_job_timeout_is_reported(monkeypatch):
    connection = FakeConnection(["ok"], ["Job 8", "ACT", "PEND"])
    fake_netmiko(monkeypatch, lambda **kwargs: connection)

    result = PANSSHDeployer(PANDeploymentOptions(
        "fw", "admin", "secret", job_poll_interval=0, job_poll_attempts=2,
    )).deploy(rendered("set one"))

    assert result.validation.status == "TIMEOUT"
    assert result.failure_message == "candidate validation timeout"
    assert connection.disconnected


def test_config_mode_failure_disconnects(monkeypatch):
    connection = FakeConnection(config_error=RuntimeError("failed secret"))
    fake_netmiko(monkeypatch, lambda **kwargs: connection)

    result = PANSSHDeployer(PANDeploymentOptions("fw", "admin", "secret")).deploy(rendered("set one"))

    assert "secret" not in result.failure_message
    assert connection.disconnected


def test_deploy_never_commits_and_explicit_commit_remains_available(monkeypatch):
    connection = FakeConnection(["ok"], ["Job 42", "FIN: OK", "FIN: OK"])
    fake_netmiko(monkeypatch, lambda **kwargs: connection)

    deployer = PANSSHDeployer(PANDeploymentOptions("fw", "admin", "secret"))
    result = deployer.deploy(rendered("set one"))

    assert result.commit.status == "NOT_RUN"
    assert result.validation.status == "SUCCESS"
    assert connection.commits == 0
    committed = deployer.commit()
    assert committed.status == "SUCCESS"
    assert connection.commits == 1
    assert connection.disconnected


def test_deploy_rejects_arbitrary_commands(monkeypatch):
    with pytest.raises(TypeError, match="RenderedMigration"):
        PANSSHDeployer(PANDeploymentOptions("fw", "admin", "secret")).deploy(["set one"])


@pytest.mark.parametrize("name", ["error-server", "invalid-server", "failed-server"])
def test_echoed_object_names_are_not_device_errors(name):
    command = f"set address {name} ip-netmask 192.0.2.1"
    deployer = PANSSHDeployer(PANDeploymentOptions("fw", "admin", "secret"))
    deployer.connection = FakeConnection([f"admin@fw# {command}\nadmin@fw#"])
    deployer.connection.config_mode()
    result = deployer.push_candidate(rendered(command))
    assert result.commands_succeeded == 1
    assert result.failure_message is None


def test_standalone_validation_enters_config_mode_and_polls_in_operational_mode(monkeypatch):
    connection = FakeConnection(validation_responses=["Job 4", "FIN OK"])
    fake_netmiko(monkeypatch, lambda **kwargs: connection)
    assert PANSSHDeployer(PANDeploymentOptions("fw", "admin", "secret")).validate().status == "SUCCESS"
    assert not connection.in_config_mode and connection.disconnected


@pytest.mark.parametrize("diagnostic", ["Server error : invalid address", "Invalid syntax.", "name is not a valid address"])
def test_real_device_diagnostics_still_reject_echoed_commands(diagnostic):
    command = "set address error-server ip-netmask bad"
    deployer = PANSSHDeployer(PANDeploymentOptions("fw", "admin", "secret"))
    deployer.connection = FakeConnection([f"{command}\n{diagnostic}"])
    result = deployer.push_candidate(rendered(command))
    assert result.failed_command_index == 0
    assert result.commands_succeeded == 0


def test_deployment_rejects_untrusted_host_keys_before_writing(monkeypatch):
    def connect(**options):
        assert options["ssh_strict"] is True
        assert options["system_host_keys"] is True
        raise RuntimeError("Host key not trusted")

    fake_netmiko(monkeypatch, connect)
    result = PANSSHDeployer(PANDeploymentOptions("fw", "admin", "secret")).deploy(rendered("set one"))
    assert not result.connected and result.commands_attempted == 0
    assert "Host key not trusted" in result.failure_message
