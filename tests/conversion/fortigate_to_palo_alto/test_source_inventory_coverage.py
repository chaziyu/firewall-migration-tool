import json
from copy import deepcopy

from fwmigrate.conversion.fortigate_to_palo_alto import PANMigrationOptions, run_migration_pipeline
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter


SOURCE = '''config firewall address
edit host
set type ipmask
set subnet 192.0.2.1 255.255.255.255
next
end
config firewall future-feature
edit object
set password private-source-value
config nested
edit leaf
set enabled yes
next
end
next
end
config system empty-future-section
end
'''


def test_preserved_native_records_prevent_complete_migration_without_exposing_values():
    analysis = FortiGateSourceReporter().analyze_source(SOURCE)
    original = deepcopy(analysis.extracted)
    result = run_migration_pipeline(analysis.extracted.config, analysis.derived,
        options=PANMigrationOptions(vdoms={'root': {'vsys': 'vsys1'}}),
        source_inventory=analysis.extracted.source_objects)
    assert result.artifact_status == 'PARTIAL'
    rows = result.coverage['unplanned']
    assert len(rows) == 2 and result.coverage['inventory_available']
    assert {row['source_path'] for row in rows} == {'firewall future-feature', 'firewall future-feature nested'}
    assert all(row['status'] == 'SOURCE_ONLY' and row['readiness'] == 'UNSUPPORTED' for row in rows)
    assert all(row['source_scope'] == 'vdom' and row['source_vdom'] == 'root' for row in rows)
    assert next(row for row in rows if row['parent_objects'])['parent_objects'] == ['object']
    assert all(row['source_line'] for row in rows)
    assert len({row['source_name'] for row in rows}) == 2
    assert 'private-source-value' not in json.dumps(result.rendered.report)
    assert all('commands' not in row and 'values' not in row for row in rows)
    assert result.rendered.commands == ('set vsys vsys1 address host ip-netmask 192.0.2.1/32',)
    assert analysis.extracted == original


def test_native_inventory_scope_and_parent_identity_remain_distinct():
    source = '''config global
config system future-setting
set setting value
end
end
config vdom
edit root
config firewall future-feature
edit one
config nested
edit same
set setting value
next
end
next
edit two
config nested
edit same
set setting value
next
end
next
end
next
edit blue
config firewall future-feature
edit one
set setting value
next
end
next
end
'''
    analysis = FortiGateSourceReporter().analyze_source(source)
    result = run_migration_pipeline(analysis.extracted.config, analysis.derived,
        source_inventory=analysis.extracted.source_objects)
    rows = result.coverage['unplanned']
    assert any(row['source_scope'] == 'global' and row['source_vdom'] is None for row in rows)
    assert any(row['source_vdom'] == 'blue' for row in rows)
    nested = [row for row in rows if row['source_path'] == 'firewall future-feature nested']
    assert len(nested) == 2 and len({row['source_name'] for row in nested}) == 2
    assert {tuple(row['parent_objects']) for row in nested} == {('one',), ('two',)}


def test_cli_carries_native_inventory_into_the_export_report(tmp_path):
    from click.testing import CliRunner
    from fwmigrate.main import cli

    source = tmp_path / 'source.conf'
    source.write_text(SOURCE)
    mapping = tmp_path / 'mapping.yaml'
    mapping.write_text('vdoms:\n  root:\n    vsys: vsys1\n')
    output = tmp_path / 'output'
    response = CliRunner().invoke(cli, ['migrate', '--input', str(source), '--output', str(output),
        '--zone-map', str(mapping), '--automation-mode', 'REVIEW_ONLY'])
    assert response.exit_code == 0, response.output
    report = (output / 'migration_report.json').read_text()
    assert 'private-source-value' not in report
    assert json.loads(report)['coverage']['unplanned_count'] == 2
    assert 'Plan status: PARTIAL' in response.output
    assert 'Unplanned source configuration: 2 (0 recommendation-only, 2 source-only)' in response.output


def test_web_draft_and_signed_artifact_keep_native_records_as_manual_work():
    import io
    from fwmigrate.web import create_app
    from tests.approved_design import approved_migrate

    client = create_app({'TESTING': True}).test_client()
    preview = client.post('/api/preview', data={'file': (io.BytesIO(SOURCE.encode()), 'source.conf')})
    assert preview.status_code == 200
    payload = {'source': preview.get_json()['source_evidence']}
    prepared = client.post('/api/migration/design/prepare', json=payload)
    assert prepared.status_code == 200
    payload['decision_document'] = prepared.get_json()['decision_document']
    draft = prepared.get_json()['draft']
    gaps = [row for row in draft['configuration'] if row['source_kind'] == 'source_section']
    assert len(gaps) == 2 and all(row['status'] == 'UNSUPPORTED' and row['operation'] is None for row in gaps)
    approval = client.post('/api/migration/design/approve', json={**payload,
        'draft': draft, 'draft_digest': draft['digest'], 'selected_groups': [gaps[0]['group_key']]})
    assert approval.status_code == 409
    response = approved_migrate(client, json=payload)
    assert response.status_code == 200
    body = response.get_json()
    report = body['artifact']['report']
    assert report['coverage']['inventory_available']
    assert report['coverage']['unplanned_count'] == 2 and report['plan_status'] == 'PARTIAL'
    assert 'private-source-value' not in json.dumps(report)
