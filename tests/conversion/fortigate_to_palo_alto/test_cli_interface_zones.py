import json

import pytest
from click.testing import CliRunner

from fwmigrate.main import cli


@pytest.mark.parametrize('mapped_zones', [True, False])
def test_cli_plans_interface_zones_only_from_explicit_mappings(tmp_path, mapped_zones):
    source = tmp_path / 'source.conf'
    source.write_text('''config system interface
edit lan
set type physical
set ip 192.0.2.1 255.255.255.0
next
edit wan
set type physical
set ip 203.0.113.1 255.255.255.0
next
end
config firewall policy
edit 1
set name outbound
set srcintf lan
set dstintf wan
set srcaddr all
set dstaddr all
set service ALL
set schedule always
set action accept
set nat enable
next
end
''')
    before = source.read_bytes()
    mapping = tmp_path / 'mapping.yaml'
    import yaml

    interfaces = {'lan': {'target_interface': 'ethernet1/1'}, 'wan': {'target_interface': 'ethernet1/2'}}
    if mapped_zones:
        interfaces['lan']['target_zone'] = 'trust'
        interfaces['wan']['target_zone'] = 'untrust'
    mapping.write_text(yaml.safe_dump({'vdoms': {'root': {'vsys': 'vsys2', 'virtual_router': 'VR'}},
                                      'interfaces': {'root': interfaces}}))
    output = tmp_path / 'output'
    response = CliRunner().invoke(cli, ['migrate', '--input', str(source), '--output', str(output),
        '--zone-map', str(mapping), '--automation-mode', 'REVIEW_ONLY'])
    assert response.exit_code == 0, response.output
    report = json.loads((output / 'migration_report.json').read_text())
    commands = (output / 'palo_alto_config.set').read_text().splitlines()
    zones = [row for row in report['items'] if row['source_object_type'] == 'zone']
    if mapped_zones:
        assert report['plan_status'] == 'READY'
        assert len(zones) == 2 and all(row['rendered'] for row in zones)
        assert 'set vsys vsys2 zone trust network layer3 [ ethernet1/1 ]' in commands
        assert 'set vsys vsys2 zone untrust network layer3 [ ethernet1/2 ]' in commands
        assert any('rulebase security rules outbound action allow' in command for command in commands)
        assert any('source-translation dynamic-ip-and-port interface-address interface ethernet1/2' in command
                   for command in commands)
        first_rule = next(index for index, command in enumerate(commands) if ' rulebase ' in command)
        assert all(index < first_rule for index, command in enumerate(commands) if ' zone ' in command)
    else:
        assert report['plan_status'] != 'READY'
        assert not zones and not any(' rulebase ' in command for command in commands)
    assert report['commands'] == len(commands)
    assert source.read_bytes() == before
