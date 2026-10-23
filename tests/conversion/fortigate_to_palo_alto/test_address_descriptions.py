from copy import deepcopy
import hashlib
import io
import json

import pytest

from fwmigrate.conversion.fortigate_to_palo_alto import PANMigrationOptions, run_migration_pipeline
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter
from fwmigrate.vendors.palo_alto.source_report import PaloAltoSourceReporter


def source_text(family='address', comment='Owner A'):
    setting = '' if comment is None else f'set comment "{comment}"'
    return f'''config firewall address
edit host
set type ipmask
set subnet 192.0.2.10 255.255.255.255
{setting if family == 'address' else ''}
next
end
config firewall addrgrp
edit hosts
set member host
{setting if family == 'address_group' else ''}
next
end
'''


def migrate(text, **kwargs):
    analysis = FortiGateSourceReporter().analyze_source(text)
    original = deepcopy(analysis.extracted)
    result = run_migration_pipeline(analysis.extracted.config, analysis.derived,
        options=PANMigrationOptions(vdoms={'root': {'vsys': 'vsys1'}}),
        source_inventory=analysis.extracted.source_objects, **kwargs)
    assert analysis.extracted == original
    return result


@pytest.mark.parametrize('family', ['address', 'address_group'])
@pytest.mark.parametrize('comment', [None, '', 'Owner A'])
def test_explicit_comments_become_descriptions_without_filling_absent_values(family, comment):
    result = migrate(source_text(family, comment))
    item = (result.plan.addresses if family == 'address' else result.plan.address_groups)[0]
    assert item.description == comment
    descriptions = [command for command in result.rendered.commands if ' description ' in command]
    name = 'address host' if family == 'address' else 'address-group hosts'
    assert descriptions == ([] if comment is None else [f'set vsys vsys1 {name} description "{comment}"'])
    assert result.artifact_status == 'READY'


@pytest.mark.parametrize('family', ['address', 'address_group'])
@pytest.mark.parametrize('source_comment,target_comment,expected', [
    ('Owner A', 'Owner A', 'EXACT_MATCH'),
    ('Owner A', 'Target owner', 'NAME_CONFLICT'),
    ('Owner A', None, 'AMBIGUOUS'),
    ('', '', 'EXACT_MATCH'),
    ('', None, 'AMBIGUOUS'),
    (None, 'Target owner', 'EXACT_MATCH'),
])
def test_target_reuse_requires_preserved_explicit_source_description(family, source_comment, target_comment, expected):
    description = '' if target_comment is None else f'<description>{target_comment}</description>'
    xml = f'''<config><devices><entry name="fw"><vsys><entry name="vsys1">
<address><entry name="host"><ip-netmask>192.0.2.10/32</ip-netmask>{description if family == 'address' else ''}</entry></address>
<address-group><entry name="hosts"><static><member>host</member></static>{description if family == 'address_group' else ''}</entry></address-group>
</entry></vsys></entry></devices></config>'''
    target = PaloAltoSourceReporter().analyze_source(xml)
    original = deepcopy(target.config)
    result = migrate(source_text(family, source_comment), target=target, target_device='fw')
    row, = [row for row in result.target_object_reuse if row['family'] == family]
    assert row['status'] == expected
    assert not result.rendered.commands  # Existing objects are never overwritten.
    assert target.config == original
    if expected != 'EXACT_MATCH':
        assert any('description' in evidence for evidence in row['evidence'])


def test_cli_exports_descriptions_and_the_same_command_digest(tmp_path):
    from click.testing import CliRunner
    from fwmigrate.main import cli

    source = tmp_path / 'source.conf'
    source.write_text(source_text())
    mapping = tmp_path / 'mapping.yaml'
    mapping.write_text('vdoms:\n  root:\n    vsys: vsys1\n')
    output = tmp_path / 'output'
    response = CliRunner().invoke(cli, ['migrate', '--input', str(source), '--output', str(output),
        '--zone-map', str(mapping), '--automation-mode', 'REVIEW_ONLY'])
    assert response.exit_code == 0, response.output
    commands = (output / 'palo_alto_config.set').read_text()
    assert 'set vsys vsys1 address host description "Owner A"' in commands
    report = json.loads((output / 'migration_report.json').read_text())
    assert report['command_sha256'] == hashlib.sha256(commands.encode()).hexdigest()


@pytest.mark.parametrize('family', ['address', 'address_group'])
@pytest.mark.parametrize('comment', ['bad\x01value', 'bad\tvalue', 'x' * 1024],
                         ids=['control', 'tab', 'over-limit'])
def test_unrenderable_descriptions_remain_evidence_without_aborting_export(family, comment):
    result = migrate(source_text(family, comment))
    item = (result.plan.addresses if family == 'address' else result.plan.address_groups)[0]
    assert item.description == comment
    assert any(issue.code == 'invalid_target_description' for issue in result.validation.issues)
    assert not any(' description ' in command or 'address-group hosts ' in command
                   for command in result.rendered.commands)
    assert any('address host ' in command for command in result.rendered.commands) == (family == 'address_group')


def test_description_limit_and_escaped_newline_remain_renderable():
    result = migrate(source_text(comment='x' * 1023))
    assert result.artifact_status == 'READY'
    result = migrate(source_text(comment='First line\nSecond line'))
    assert 'set vsys vsys1 address host description "First line\\nSecond line"' in result.rendered.commands


def test_signed_web_artifact_preview_and_download_preserve_descriptions():
    from fwmigrate.web import create_app
    from tests.approved_design import approved_migrate

    client = create_app({'TESTING': True}).test_client()
    preview = client.post('/api/preview', data={'file': (io.BytesIO(source_text().encode()), 'source.conf')})
    assert preview.status_code == 200
    response = approved_migrate(client, json={'source': preview.get_json()['source_evidence'],
        'workflow_mode': 'OFFLINE_EXPORT', 'mapping': {'vdoms': {'root': {'vsys': 'vsys1'}}}})
    assert response.status_code == 200
    artifact = response.get_json()['artifact']
    assert 'set vsys vsys1 address host description "Owner A"' in artifact['commands']
    body = {'artifact': artifact}
    command_preview = client.post('/api/migration/command-preview', json=body)
    download = client.post('/api/migration/download', json=body)
    assert command_preview.status_code == download.status_code == 200
    assert command_preview.get_json()['commands'] == artifact['commands']
    assert hashlib.sha256(download.data).hexdigest() == artifact['command_sha256']


@pytest.mark.parametrize('family', ['address', 'address_group'])
def test_invalid_description_remains_a_manual_task_before_placement_is_resolved(family):
    from fwmigrate.web import create_app

    client = create_app({'TESTING': True}).test_client()
    text = source_text(family, 'invalid\x01comment')
    preview = client.post('/api/preview', data={'file': (io.BytesIO(text.encode()), 'source.conf')})
    assert preview.status_code == 200
    prepared = client.post('/api/migration/design/prepare', json={
        'source': preview.get_json()['source_evidence'], 'workflow_mode': 'OFFLINE_EXPORT'})
    assert prepared.status_code == 200
    draft = prepared.get_json()['draft']
    row, = [row for row in draft['configuration'] if row['source_kind'] == family]
    assert row['status'] == 'UNSUPPORTED'
    assert any('unsafe CLI controls' in reason for reason in row['blocking_reasons'])
    assert any(row['category'] == 'MANUAL' and 'unsafe CLI controls' in row['explanation']
               for row in draft['issues'])
