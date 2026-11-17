import io
from fwmigrate.conversion.fortigate_to_palo_alto.coverage import build_migration_coverage
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter
import json
from copy import deepcopy
from fwmigrate.conversion.fortigate_to_palo_alto import PANMigrationOptions, run_migration_pipeline
import pytest
from fwmigrate.conversion.fortigate_to_palo_alto.planner import FortiGateToPaloAltoPlanner
from fwmigrate.conversion.fortigate_to_palo_alto.requirements import build_mapping_requirements

# --- test_coverage_identity.py ---
SOURCE = '''config system session-helper
edit 1
set name sip
set port 5060
set protocol 17
next
edit 2
set name sip
set port 5061
set protocol 6
next
end
config firewall region
edit 12
set name repeated
next
edit 13
set name repeated
next
end
config firewall vendor-mac
edit 21
set name repeated
next
end
config vpn ssl web realm
edit staff
set virtual-host vpn.example.test
next
end
config vpn ssl web user-bookmark
edit staff-owner
set custom-lang en
next
end
config vpn ssl web user-group-bookmark
edit group-owner
set custom-lang en
next
end
'''


def identities(text):
    config = FortiGateSourceReporter().analyze_source(text).extracted.config
    rows = build_migration_coverage(config)['unplanned']
    return {(row['source_vdom'], row['source_kind'], row['source_name']) for row in rows}, rows


def test_coverage_uses_native_edit_keys_instead_of_labels_or_list_offsets():
    found, rows = identities(SOURCE)
    assert found == {('root', 'session_helper', '1'), ('root', 'session_helper', '2'),
                     (None, 'firewall_region', '12'), (None, 'firewall_region', '13'),
                     (None, 'vendor_mac', '21'), ('root', 'ssl_vpn_realm', 'staff'),
                     ('root', 'ssl_vpn_user_bookmark', 'staff-owner'),
                     ('root', 'ssl_vpn_user_group_bookmark', 'group-owner')}
    assert len(found) == len(rows)


def test_native_identities_keep_global_and_vdom_scopes_distinct():
    helpers = SOURCE.partition('config firewall region')[0]
    text = ('config global\nconfig system session-helper\nedit 1\nset name sip\nnext\nend\nend\n'
            + 'config vdom\nedit root\n' + helpers + 'next\nedit blue\n' + helpers + 'next\nend\n')
    found, rows = identities(text)
    assert (None, 'session_helper', '1') in found
    assert ('root', 'session_helper', '1') in found
    assert ('blue', 'session_helper', '1') in found
    assert len(found) == len(rows)


def test_unparsed_native_ids_and_singleton_paths_are_not_replaced_by_offsets():
    found, _ = identities('''config system session-helper
edit not-a-number
set name sip
next
end
config ips settings
set ips-packet-quota 10
end
config router setting
set hostname lab
end
''')
    assert ('root', 'session_helper', 'not-a-number') in found
    assert ('root', 'ips_settings', 'ips_settings') in found
    assert ('root', 'router_settings', 'router_settings') in found


def test_web_manual_tasks_preserve_each_native_helper_id():
    from fwmigrate.web import create_app

    client = create_app({'TESTING': True}).test_client()
    preview = client.post('/api/preview', data={'file': (io.BytesIO(SOURCE.encode()), 'source.conf')})
    assert preview.status_code == 200
    prepared = client.post('/api/migration/design/prepare', json={
        'source': preview.get_json()['source_evidence'], 'workflow_mode': 'OFFLINE_EXPORT'})
    assert prepared.status_code == 200
    body = prepared.get_json()['draft']
    rows = [row for row in body['configuration'] if row['source_kind'] == 'session_helper']
    assert {row['source_name'] for row in rows} == {'1', '2'}
    assert all(row['status'] == 'UNSUPPORTED' and row['operation'] is None for row in rows)
    tasks = [row for row in body['issues'] if row['source_kind'] == 'session_helper']
    assert {row['source_name'] for row in tasks} == {'1', '2'}

# --- test_source_inventory_coverage.py ---
_INVENTORY_SOURCE = '''config firewall address
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
    analysis = FortiGateSourceReporter().analyze_source(_INVENTORY_SOURCE)
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
    source.write_text(_INVENTORY_SOURCE)
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
    preview = client.post('/api/preview', data={'file': (io.BytesIO(_INVENTORY_SOURCE.encode()), 'source.conf')})
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

# --- test_source_ownership.py ---
def test_unknown_interface_ownership_cannot_become_root_migration_input():
    analysis = FortiGateSourceReporter().analyze_source('''config global
    config system interface
        edit unassigned
        next
    end
end
''')
    source = analysis.extracted.config
    assert source.interfaces[0].vdom is None
    with pytest.raises(ValueError, match="VDOM ownership is unresolved"):
        build_mapping_requirements(source, analysis.derived, include_configuration=True)
    with pytest.raises(ValueError, match="VDOM ownership is unresolved"):
        FortiGateToPaloAltoPlanner().plan(source, analysis.derived)

# --- test_zone_coverage.py ---
_ZONE_SOURCE = '''config system interface
edit lan
set type physical
set ip 192.0.2.1 255.255.255.0
next
end
config system zone
edit unused
set interface lan
next
end
'''


def migrate(text=_ZONE_SOURCE, mapped=True):
    analysis = FortiGateSourceReporter().analyze_source(text)
    original = deepcopy(analysis.extracted)
    result = run_migration_pipeline(analysis.extracted.config, analysis.derived,
        options=PANMigrationOptions(vdoms={'root': {'vsys': 'vsys1', 'virtual_router': 'VR'}},
            interfaces={'root': {'lan': {'target_interface': 'ethernet1/1', 'target_zone': 'trust'}}},
            zones={'root': {'unused': {'target_zone': 'trust'}}} if mapped else None),
        source_inventory=analysis.extracted.source_objects, include_interface_zones=True)
    assert analysis.extracted == original
    return result


@pytest.mark.parametrize('mapped', [False, True])
def test_unused_zone_is_planned_from_explicit_mapping_or_stays_visible(mapped):
    result = migrate(mapped=mapped)
    if mapped:
        assert len(result.plan.zones) == 1
        assert result.artifact_status == 'READY' and result.coverage['complete']
        assert 'set vsys vsys1 zone trust network layer3 [ ethernet1/1 ]' in result.rendered.commands
    else:
        row, = result.coverage['unplanned']
        assert row['source_kind'] == 'zone' and row['source_name'] == 'unused'
        assert row['source_vdom'] == 'root' and row['readiness'] == 'PENDING'
        assert result.artifact_status != 'READY' and not result.plan.zones
        assert not any(' zone ' in command for command in result.rendered.commands)


def test_unclassified_zone_setting_blocks_zone_and_dependent_policy():
    policy = '''config firewall policy
edit 1
set srcintf unused
set dstintf any
set srcaddr all
set dstaddr all
set service ALL
set schedule always
set action accept
next
end
'''
    baseline = migrate(_ZONE_SOURCE + policy)
    assert any('rulebase security' in command for command in baseline.rendered.commands)
    source = _ZONE_SOURCE.replace('set interface lan', 'set interface lan\nset future-policy-match enable')
    result = migrate(source + policy)
    assert result.plan.zones[0].status.value == 'MANUAL_REVIEW'
    assert any('future-policy-match' in warning for warning in result.plan.zones[0].warnings)
    assert result.artifact_status == 'PARTIAL'
    assert not any(' zone ' in command or 'rulebase security' in command for command in result.rendered.commands)


def test_source_zone_tagging_is_reported_for_manual_metadata_review():
    source = _ZONE_SOURCE.replace('set interface lan', '''set interface lan
config tagging
edit label
set category asset
set tags staff
next
end''')
    result = migrate(source)
    zone, = result.plan.zones
    assert zone.status.value == 'MANUAL_REVIEW'
    assert any('tagging' in warning for warning in zone.warnings)
    assert result.artifact_status == 'PARTIAL'
    assert not any(' zone ' in command for command in result.rendered.commands)
