from fwmigrate.deployment.models import PANDeploymentOptions
from fwmigrate.deployment.palo_alto_ssh import PANSSHDeployer
from fwmigrate.conversion.fortigate_to_palo_alto.renderer import RenderedMigration


class _Connection:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.commands = []

    def config_mode(self):
        pass

    def send_config_set(self, commands):
        self.commands.extend(commands)
        response = next(self.responses)
        if isinstance(response, Exception):
            raise response
        return response


def test_push_candidate_stops_after_rejected_command():
    deployer = PANSSHDeployer(PANDeploymentOptions("fw", "admin", "secret"))
    deployer.connection = _Connection(["ok", "ERROR: invalid value", "ok"])

    result = deployer.push_candidate(RenderedMigration(("set one", "set two", "set three"), {}))

    assert result.failed_command_index == 1
    assert result.commands_attempted == 2
    assert result.commands_succeeded == 1
    assert [item.command for item in result.command_results] == ["set one", "set two"]
    assert deployer.connection.commands == ["set one", "set two"]


def test_command_exception_is_contextual_and_secret_safe():
    deployer = PANSSHDeployer(PANDeploymentOptions("fw", "admin", "secret"))
    deployer.connection = _Connection([RuntimeError("device rejected secret")])

    result = deployer.push_candidate(RenderedMigration(("set password secret",), {}))

    assert result.failed_command_index == 0
    assert "command 0 failed" in result.failure_message
    assert "secret" not in result.failure_message
    assert "secret" not in result.command_results[0].command
    assert "secret" not in result.command_results[0].response
