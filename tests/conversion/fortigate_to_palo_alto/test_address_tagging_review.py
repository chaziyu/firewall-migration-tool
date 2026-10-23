from copy import deepcopy
import json

import pytest

from fwmigrate.conversion.fortigate_to_palo_alto import PANMigrationOptions, run_migration_pipeline
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter


def source_text(family, settings):
    address = '''config firewall address
edit host
set type ipmask
set subnet 192.0.2.10 255.255.255.255
%s
next
end
'''
    group = '''config firewall addrgrp
edit hosts
set member host
%s
next
end
'''
    return ((address % (settings if family == 'address' else ''))
            + (group % (settings if family == 'address_group' else '')) + '''config firewall policy
edit 1
set name tagged-consumer
set srcintf any
set dstintf any
set srcaddr hosts
set dstaddr all
set service ALL
set schedule always
set action accept
next
end
''')


def migrate(text, inventory=True):
    analysis = FortiGateSourceReporter().analyze_source(text)
    original = deepcopy(analysis.extracted)
    result = run_migration_pipeline(analysis.extracted.config, analysis.derived,
        options=PANMigrationOptions(vdoms={'root': {'vsys': 'vsys1'}}),
        source_inventory=analysis.extracted.source_objects if inventory else None)
    assert analysis.extracted == original
    return result


@pytest.mark.parametrize('family', ['address', 'address_group'])
@pytest.mark.parametrize('settings', ['set category asset\nset tags staff',
                                      'set password private-tagging-value'])
@pytest.mark.parametrize('inventory', [False, True])
def test_nested_tagging_needs_review_and_blocks_transitive_consumers(family, settings, inventory):
    baseline = migrate(source_text(family, ''), inventory)
    assert baseline.artifact_status == 'READY'
    assert any('rulebase security' in command for command in baseline.rendered.commands)
    tagging = f'config tagging\nedit label\n{settings}\nnext\nend'
    result = migrate(source_text(family, tagging), inventory)
    item = (result.plan.addresses if family == 'address' else result.plan.address_groups)[0]
    assert item.status.value == 'MANUAL_REVIEW'
    assert any('tagging' in warning and 'manual metadata review' in warning for warning in item.warnings)
    assert result.artifact_status == 'PARTIAL'
    assert not any('address-group hosts ' in command or 'rulebase security' in command
                   for command in result.rendered.commands)
    assert any('address host ' in command for command in result.rendered.commands) == (family == 'address_group')
    assert 'private-tagging-value' not in json.dumps(result.rendered.report)


@pytest.mark.parametrize('family', ['address', 'address_group'])
def test_tagging_review_is_visible_in_web_draft(family):
    import io
    from fwmigrate.web import create_app

    client = create_app({'TESTING': True}).test_client()
    text = source_text(family, 'config tagging\nedit label\nset tags staff\nnext\nend')
    preview = client.post('/api/preview', data={'file': (io.BytesIO(text.encode()), 'source.conf')})
    assert preview.status_code == 200
    response = client.post('/api/migration/design/prepare', json={
        'source': preview.get_json()['source_evidence'], 'workflow_mode': 'OFFLINE_EXPORT'})
    assert response.status_code == 200
    rows = [row for row in response.get_json()['draft']['configuration'] if row['source_kind'] == family]
    assert len(rows) == 1 and rows[0]['status'] == 'UNSUPPORTED'
    assert any('tagging' in reason for reason in rows[0]['blocking_reasons'])
