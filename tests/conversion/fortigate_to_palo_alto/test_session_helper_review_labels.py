import io
import json

from fwmigrate.conversion.fortigate_to_palo_alto.coverage import build_migration_coverage
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter


SOURCE = '''config system session-helper
edit 1
set name sip
set port 5060
set protocol 17
set password synthetic-secret-value
next
edit 2
set name sip
set port 5061
set protocol 6
next
end
'''


def test_native_ids_and_searchable_helper_types_are_both_preserved():
    source = FortiGateSourceReporter().analyze_source(SOURCE).extracted.config
    original = source.model_dump()
    rows = build_migration_coverage(source)['unplanned']
    assert {row['source_name'] for row in rows} == {'1', '2'}
    assert all('sip' in row['reason'] and 'system session-helper' in row['reason'] for row in rows)
    assert all(row['source_vdom'] == 'root' and row['readiness'] == 'UNSUPPORTED' for row in rows)
    assert 'synthetic-secret-value' not in json.dumps(rows)
    assert source.model_dump() == original


def test_missing_helper_type_is_not_filled_with_an_assumed_type():
    source = FortiGateSourceReporter().analyze_source('config system session-helper\nedit 1\nset port 5060\nnext\nend\n').extracted.config
    row, = build_migration_coverage(source)['unplanned']
    assert row['source_name'] == '1'
    assert 'sip' not in row['reason'] and 'None' not in row['reason']


def test_labels_preserve_native_id_collisions_across_source_scopes():
    text = 'config global\n' + SOURCE + 'end\nconfig vdom\nedit blue\n' + SOURCE + 'next\nend\n'
    source = FortiGateSourceReporter().analyze_source(text).extracted.config
    rows = build_migration_coverage(source)['unplanned']
    assert {(row['source_vdom'], row['source_name']) for row in rows} == {(None, '1'), (None, '2'), ('blue', '1'), ('blue', '2')}
    assert all('sip' in row['reason'] for row in rows)


def test_browser_review_tasks_include_helper_type_without_changing_identity():
    from fwmigrate.web import create_app

    client = create_app({'TESTING': True}).test_client()
    preview = client.post('/api/preview', data={'file': (io.BytesIO(SOURCE.encode()), 'source.conf')})
    assert preview.status_code == 200
    response = client.post('/api/migration/design/prepare', json={
        'source': preview.get_json()['source_evidence'], 'workflow_mode': 'OFFLINE_EXPORT'})
    assert response.status_code == 200
    draft = response.get_json()['draft']
    rows = [row for row in draft['configuration'] if row['source_kind'] == 'session_helper']
    assert {row['source_name'] for row in rows} == {'1', '2'}
    assert all('sip' in ' '.join(row['blocking_reasons']) and row['status'] == 'UNSUPPORTED' for row in rows)
    tasks = [row for row in draft['issues'] if row['source_kind'] == 'session_helper']
    assert {row['source_name'] for row in tasks} == {'1', '2'}
    assert all('sip' in row['explanation'] for row in tasks)
    assert 'synthetic-secret-value' not in json.dumps(draft)
