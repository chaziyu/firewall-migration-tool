from copy import deepcopy
import io

import pytest

from fwmigrate.conversion.fortigate_to_palo_alto import PANMigrationOptions, run_migration_pipeline
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter


def source_text(expiration=''):
    return f'''config firewall schedule onetime
edit maintenance
set start 01:00 2026/12/25
set end 02:00 2026/12/25
{expiration}
next
end
config firewall policy
edit 1
set name scheduled-consumer
set srcintf any
set dstintf any
set srcaddr all
set dstaddr all
set service ALL
set schedule maintenance
set action accept
next
end
'''


def migrate(text):
    analysis = FortiGateSourceReporter().analyze_source(text)
    original = deepcopy(analysis.extracted)
    result = run_migration_pipeline(analysis.extracted.config, analysis.derived,
        options=PANMigrationOptions(vdoms={'root': {'vsys': 'vsys1'}}),
        source_inventory=analysis.extracted.source_objects)
    assert analysis.extracted == original
    return result


@pytest.mark.parametrize('days', [0, 3, 100])
def test_explicit_expiration_notification_is_not_silently_discarded(days):
    baseline = migrate(source_text())
    assert baseline.artifact_status == 'READY'
    assert any('rulebase security' in command for command in baseline.rendered.commands)
    result = migrate(source_text(f'set expiration-days {days}'))
    schedule, = result.plan.schedules
    assert schedule.status.value == 'MANUAL_REVIEW'
    assert any('expiration-days' in warning and 'notification' in warning for warning in schedule.warnings)
    assert result.artifact_status != 'READY'
    assert not result.rendered.commands


def test_unset_expiration_is_preserved_without_inventing_a_notification():
    result = migrate(source_text('unset expiration-days'))
    assert result.artifact_status == 'READY'
    assert not any('expiration-days' in warning for item in result.plan.schedules for warning in item.warnings)


def test_web_review_exposes_expiration_notification_requirement():
    from fwmigrate.web import create_app

    client = create_app({'TESTING': True}).test_client()
    text = source_text('set expiration-days 3')
    preview = client.post('/api/preview', data={'file': (io.BytesIO(text.encode()), 'source.conf')})
    assert preview.status_code == 200
    response = client.post('/api/migration/design/prepare', json={
        'source': preview.get_json()['source_evidence'], 'workflow_mode': 'OFFLINE_EXPORT'})
    assert response.status_code == 200
    rows = [row for row in response.get_json()['draft']['configuration'] if row['family'] == 'schedule']
    assert len(rows) == 1 and rows[0]['status'] == 'UNSUPPORTED'
    assert any('expiration-days' in reason for reason in rows[0]['blocking_reasons'])
