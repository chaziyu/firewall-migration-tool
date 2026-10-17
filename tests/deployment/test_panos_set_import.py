import pytest

from fwmigrate.deployment.panos_set_import import (
    MAX_SET_BYTES, MAX_SET_COMMANDS, MAX_SET_LINE, SetImportError, parse_set_upload,
)

COMMAND = 'set vsys vsys1 address "host name" ip-netmask 192.0.2.1/32'


def test_upload_preserves_commands_order_duplicates_and_original_lines():
    raw = ('\ufeff\r\n' + COMMAND + '\r\n\r\n' + COMMAND + '\r\n').encode()
    result = parse_set_upload(raw)
    assert result['commands'] == [COMMAND, COMMAND]
    assert result['line_numbers'] == [2, 4]
    assert result['vsys'] == ['vsys1']
    assert result['file_sha256'] != result['command_sha256']


@pytest.mark.parametrize('command', [
    'commit', 'configure', 'delete vsys vsys1 address host', 'set cli config-output-format set',
    'set system setting target-vsys vsys1', 'set address host ip-netmask 192.0.2.1',
    'set shared address host ip-netmask 192.0.2.1', 'set device-group group address host ip-netmask 192.0.2.1',
    COMMAND + '; commit', COMMAND + '\x1b[31m', COMMAND + '\t', COMMAND + '\r', COMMAND + '\u2028commit',
    'set vsys vsys1 address "unterminated ip-netmask 192.0.2.1',
    'set vsys vsys1 address host description unsupported',
    'set vsys vsys1 service-group group members [ a',
    'set mgt-config users admin password SENTINEL',
    'set network ike gateway peer authentication pre-shared-key key SENTINEL',
    'set vsys vsys1 rulebase security rules test description "password SENTINEL"',
])
def test_upload_rejects_whole_file_without_echoing_commands(command):
    with pytest.raises(SetImportError) as error:
        parse_set_upload((COMMAND + '\n' + command).encode())
    assert 'Line 2:' in str(error.value)
    assert 'SENTINEL' not in str(error.value)
    assert '192.0.2.1' not in str(error.value)


@pytest.mark.parametrize('raw', [b'', b'\n\n', b'\xff', b'x' * (MAX_SET_BYTES + 1),
    ('set vsys vsys1 rulebase security rules rule description "' + 'x' * MAX_SET_LINE + '"').encode(),
    ((COMMAND + '\n') * (MAX_SET_COMMANDS + 1)).encode(),
], ids=lambda value: str(value)[:70])
def test_upload_limits_and_encoding(raw):
    with pytest.raises(SetImportError):
        parse_set_upload(raw)


@pytest.mark.parametrize('command', [
    'set network interface ethernet ethernet1/1 layer3 ip 192.0.2.1/24',
    'set vsys vsys1 import network interface [ ethernet1/1 ]',
    'set network virtual-router default',
    'set network virtual-router default interface [ ethernet1/1 ]',
    'set network virtual-router default routing-table ip static-route route destination 0.0.0.0/0',
    'set vsys vsys1 zone outside network layer3 [ ethernet1/1 ]',
    'set vsys vsys1 service web protocol tcp port 443',
    'set vsys vsys1 schedule daily schedule-type recurring daily [ 09:00-17:00 ]',
    'set network dhcp interface ethernet1/1 server option dns primary 192.0.2.2',
    'set network ike crypto-profiles ike-crypto-profiles crypto hash [ sha256 ]',
    'set vsys vsys1 rulebase security rules "rule name" description "escaped \\"quote\\" and \\\\ path"',
    'set vsys vsys1 rulebase nat rules nat source-translation dynamic-ip-and-port interface-address interface ethernet1/1',
])
def test_supported_renderer_paths(command):
    assert parse_set_upload(command.encode())['commands'] == [command]
