import pytest
from click.testing import CliRunner

from fwmigrate.main import cli


@pytest.mark.parametrize('command', ['deploy', 'commit'])
def test_cli_live_operations_fail_without_connecting_or_prompting(monkeypatch, tmp_path, command):
    from fwmigrate.deployment import PANSSHDeployer

    monkeypatch.setattr(PANSSHDeployer, 'connect', lambda self: pytest.fail('Disabled CLI must not connect'))
    commands = tmp_path / 'palo_alto_config.set'
    commands.write_text('set vsys vsys1 address x ip-netmask 192.0.2.1\n')
    args = [command, *([str(commands)] if command == 'deploy' else []), '--host', 'fw', '--username', 'admin']
    result = CliRunner().invoke(cli, args)
    assert result.exit_code == 1
    assert f'CLI {"deployment" if command == "deploy" else "commit"} is disabled' in result.output
    assert 'Password:' not in result.output
