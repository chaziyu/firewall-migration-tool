from copy import deepcopy
import io

import pytest

from fwmigrate.conversion.fortigate_to_palo_alto import PANMigrationOptions, run_migration_pipeline
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter
from fwmigrate.vendors.palo_alto.source_report import PaloAltoSourceReporter


def source_text(comment='Service owner', *, split=False, group_comment=None):
    setting = '' if comment is None else f'set comment "{comment}"'
    group_setting = '' if group_comment is None else f'set comment "{group_comment}"'
    return f'''config firewall service custom
edit web
set protocol TCP/UDP/SCTP
set tcp-portrange 443:1024-65535
{'set udp-portrange 53' if split else ''}
{setting}
next
end
config firewall service group
edit web-services
set member web
{group_setting}
next
end
config firewall policy
edit 1
set name service-consumer
set srcintf any
set dstintf any
set srcaddr all
set dstaddr all
set service web-services
set schedule always
set action accept
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


@pytest.mark.parametrize('comment', [None, '', 'Service owner'])
@pytest.mark.parametrize('split', [False, True])
def test_source_service_comments_survive_normalization_and_rendering(comment, split):
    result = migrate(source_text(comment, split=split))
    assert result.artifact_status == 'READY'
    assert len(result.plan.services) == (2 if split else 1)
    assert all(item.description == comment for item in result.plan.services)
    descriptions = [command for command in result.rendered.commands if ' description ' in command]
    assert len(descriptions) == (len(result.plan.services) if comment is not None else 0)
    assert not any('service-group' in command for command in descriptions)
    assert any('rulebase security' in command for command in result.rendered.commands)


@pytest.mark.parametrize('comment', ['', 'Group owner'])
def test_native_service_group_comment_requires_manual_review_without_invented_cli(comment):
    result = migrate(source_text(group_comment=comment))
    group, = result.plan.service_groups
    assert group.status.value == 'UNSUPPORTED'
    assert any('comment' in warning and 'manual metadata review' in warning for warning in group.warnings)
    assert result.artifact_status == 'PARTIAL'
    assert not any('service-group' in command or 'rulebase security' in command for command in result.rendered.commands)
    assert any('service web description' in command for command in result.rendered.commands)


@pytest.mark.parametrize('target_comment,expected', [('Service owner', 'EXACT_MATCH'),
    ('Other owner', 'NAME_CONFLICT'), (None, 'AMBIGUOUS')])
def test_service_reuse_cannot_discard_a_source_comment(target_comment, expected):
    description = '' if target_comment is None else f'<description>{target_comment}</description>'
    target = PaloAltoSourceReporter().analyze_source(f'''<config><devices><entry name="fw"><vsys><entry name="vsys1">
<service><entry name="web"><protocol><tcp><port>443</port><source-port>1024-65535</source-port></tcp></protocol>{description}</entry></service>
</entry></vsys></entry></devices></config>''')
    result = migrate(source_text(), target=target, target_device='fw')
    row, = [row for row in result.target_object_reuse if row['family'] == 'service']
    assert row['status'] == expected
    assert not any('service web ' in command for command in result.rendered.commands)


def test_web_draft_reports_native_service_group_comment_as_manual_work():
    from fwmigrate.web import create_app

    client = create_app({'TESTING': True}).test_client()
    text = source_text(group_comment='Group owner')
    preview = client.post('/api/preview', data={'file': (io.BytesIO(text.encode()), 'source.conf')})
    assert preview.status_code == 200
    prepared = client.post('/api/migration/design/prepare', json={
        'source': preview.get_json()['source_evidence'], 'workflow_mode': 'OFFLINE_EXPORT'})
    assert prepared.status_code == 200
    rows = [row for row in prepared.get_json()['draft']['configuration'] if row['source_kind'] == 'service_group']
    assert len(rows) == 1 and rows[0]['status'] == 'UNSUPPORTED'
    assert any('manual metadata review' in reason for reason in rows[0]['blocking_reasons'])


@pytest.mark.parametrize('comment', ['bad\x01comment', 'bad\tcomment', 'x' * 1024],
                         ids=['control', 'tab', 'over-limit'])
def test_invalid_service_description_blocks_service_group_and_policy(comment):
    result = migrate(source_text(comment))
    service, = result.plan.services
    assert service.description == comment and service.status.value == 'UNSUPPORTED'
    assert any('unsafe CLI controls' in warning for warning in service.warnings)
    assert not result.rendered.commands
