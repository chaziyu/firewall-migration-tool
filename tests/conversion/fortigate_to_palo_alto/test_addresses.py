from fwmigrate.conversion.fortigate_to_palo_alto import FortiGateToPaloAltoPlanner, PANMigrationOptions, PANMigrationStatus
from fwmigrate.vendors.fortigate.model.address import FGAddress, FGAddressGroup
from fwmigrate.vendors.fortigate.model.source import FGConfig
import pytest
from copy import deepcopy
import hashlib
import io
import json
from fwmigrate.conversion.fortigate_to_palo_alto import run_migration_pipeline
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter
from fwmigrate.vendors.palo_alto.source_report import PaloAltoSourceReporter
from fwmigrate.conversion.fortigate_to_palo_alto.planning.addresses import address_references
from fwmigrate.conversion.fortigate_to_palo_alto.planning.naming import allocate_plan_names
from fwmigrate.vendors.fortigate.model.interface import FGInterface
from fwmigrate.vendors.fortigate.model.policy import FGPolicy
from fwmigrate.conversion.fortigate_to_palo_alto.decisions import PANMigrationDecisionSet
from fwmigrate.conversion.fortigate_to_palo_alto.plan_dependencies import build_plan_dependency_index, item_key
from fwmigrate.vendors.fortigate.derived import build_derived_views
from dataclasses import replace
from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import PANSetRenderer
from fwmigrate.conversion.fortigate_to_palo_alto.requirements import build_mapping_requirements
from fwmigrate.conversion.fortigate_to_palo_alto.planning.policies import _zones
from fwmigrate.conversion.fortigate_to_palo_alto.planning.nat import _policy_zones, _target_zone
from fwmigrate.conversion.fortigate_to_palo_alto.target.name_validation import zone_name_issue
from fwmigrate.conversion.fortigate_to_palo_alto.models import PANMigrationPlan, PlannedZone
from fwmigrate.conversion.fortigate_to_palo_alto.validation import validate_plan

# --- test_addresses.py ---
def test_address_representations_and_static_group_are_preserved():
    source = FGConfig(
        addresses=[
            FGAddress(name="net", vdom="root", subnet="10.0.0.0 255.255.255.0"),
            FGAddress(name="range", vdom="root", start_ip="10.0.0.1", end_ip="10.0.0.9"),
            FGAddress(name="fqdn", vdom="root", fqdn="example.com"),
            FGAddress(name="wildcard", vdom="root", wildcard="10.0.0.0/255.255.0.0"),
        ],
        address_groups=[FGAddressGroup(name="servers", vdom="root", members=["net", "fqdn"])],
    )
    plan = FortiGateToPaloAltoPlanner().plan(
        source,
        object(),
        options=PANMigrationOptions(vdoms={"root": {"vsys": "vsys1"}}),
    )

    assert [(item.address_type, item.value) for item in plan.addresses] == [
        ("ip-netmask", "10.0.0.0/24"),
        ("ip-range", "10.0.0.1-10.0.0.9"),
        ("fqdn", "example.com"),
        ("ip-wildcard", "10.0.0.0/255.255.0.0"),
    ]
    assert plan.address_groups[0].members == ("net", "fqdn")
    assert all(item.status is PANMigrationStatus.SUPPORTED for item in plan.addresses)


def test_missing_vsys_mapping_is_reviewable_and_does_not_invent_target_scope():
    source = FGConfig(addresses=[FGAddress(name="net", subnet="10.0.0.0 255.255.255.0")])

    plan = FortiGateToPaloAltoPlanner().plan(source, object())

    assert plan.addresses[0].status is PANMigrationStatus.MANUAL_REVIEW
    assert plan.issues[0].code == "missing_vsys_mapping"


@pytest.mark.parametrize('fields,kind,value,supported', [
    ({'type': 'fqdn', 'fqdn': 'example.org', 'subnet': '192.0.2.0/24'}, 'fqdn', 'example.org', True),
    ({'type': 'ipmask', 'fqdn': 'example.org', 'subnet': '192.0.2.0/24'}, 'ip-netmask', '192.0.2.0/24', True),
    ({'fqdn': 'example.org', 'subnet': '192.0.2.0/24'}, None, None, False),
    ({'type': 'fqdn', 'subnet': '192.0.2.0/24'}, None, None, False),
    ({'type': 'future', 'subnet': '192.0.2.0/24'}, None, None, False),
    ({'type': 'fqdn', 'fqdn': 'example.org', 'raw_extra': {'future-match': 'enable'}}, 'fqdn', 'example.org', False),
    ({'fqdn': 'example.org', 'raw_extra': {'color': '2', 'uuid': 'metadata'}}, 'fqdn', 'example.org', True),
])
def test_address_type_selects_active_value_without_mutating_source(fields, kind, value, supported):
    source = FGConfig(addresses=[FGAddress(name='host', **fields)])
    before = source.model_dump()
    plan = FortiGateToPaloAltoPlanner().plan(source, object(),
        options=PANMigrationOptions(vdoms={'root': {'vsys': 'vsys1'}}))
    item = plan.addresses[0]
    assert (item.address_type, item.value) == (kind, value)
    assert (item.status is PANMigrationStatus.SUPPORTED) == supported
    assert source.model_dump() == before


@pytest.mark.parametrize('fields', [{'type': 'folder'}, {'raw_extra': {'future-control': 'enable'}},
                                   {'allow_routing': 'enable'}])
def test_static_group_rejects_unrepresented_settings(fields):
    source = FGConfig(address_groups=[FGAddressGroup(name='group', members=['host'], **fields)])
    plan = FortiGateToPaloAltoPlanner().plan(source, object(),
        options=PANMigrationOptions(vdoms={'root': {'vsys': 'vsys1'}}))
    assert plan.address_groups[0].status is not PANMigrationStatus.SUPPORTED

# --- test_address_descriptions.py ---
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

# --- test_address_family_automation.py ---
def test_ipv6_all_does_not_shadow_ipv4_builtin():
    source = FGConfig(addresses=[FGAddress(name='all', address_family='ipv6', ip6='::/0')])
    assert address_references(source, 'root', ['all']) == ('0.0.0.0/0',)


def test_cli_pipeline_keeps_ipv6_inventory_without_blocking_ipv4_address():
    source = FGConfig(addresses=[FGAddress(name='all', subnet='0.0.0.0/0'),
                                 FGAddress(name='all', address_family='ipv6', ip6='::/0')])
    result = run_migration_pipeline(source, build_derived_views(source),
        options=PANMigrationOptions(vdoms={'root': {'vsys': 'vsys1'}}), workflow_mode='OFFLINE_EXPORT')
    assert any(' address all ip-netmask 0.0.0.0/0' in line for line in result.rendered.commands)
    assert len(result.rendered.report['items']) == 2


def test_address_families_keep_distinct_identity_and_ipv4_group_binding():
    source = FGConfig(addresses=[
        FGAddress(name='all', address_family='ipv4', subnet='0.0.0.0/0'),
        FGAddress(name='all', address_family='ipv6', ip6='::/0'),
    ], address_groups=[FGAddressGroup(name='clients', members=['all'])])
    before = source.model_dump()
    options = PANMigrationOptions(vdoms={'root': {'vsys': 'vsys1'}})
    plan = allocate_plan_names(FortiGateToPaloAltoPlanner().plan(source, object(), options))
    ipv4, ipv6 = plan.addresses
    assert ipv4.target_name != ipv6.target_name
    assert ipv4.source_kind != ipv6.source_kind
    assert plan.address_groups[0].members == (ipv4.target_name,)
    assert plan.address_groups[0].status is PANMigrationStatus.SUPPORTED
    assert ipv6.status is PANMigrationStatus.UNSUPPORTED
    assert source.model_dump() == before


def test_association_requires_consistent_nested_policy_interface_scope():
    address = FGAddress(name='host', subnet='192.0.2.1/32', associated_interface='port1', allow_routing='enable')
    source = FGConfig(addresses=[address], interfaces=[FGInterface(name='port1')],
        address_groups=[FGAddressGroup(name='clients', members=['host'])],
        policies=[FGPolicy(policy_id=1, srcaddr=['clients'], srcintf=['port1'])])
    options = PANMigrationOptions(vdoms={'root': {'vsys': 'vsys1'}})
    plan = FortiGateToPaloAltoPlanner().plan(source, object(), options)
    assert plan.addresses[0].status is PANMigrationStatus.SUPPORTED
    source.policies[0].srcintf = ['port2']
    plan = FortiGateToPaloAltoPlanner().plan(source, object(), options)
    assert plan.addresses[0].status is PANMigrationStatus.UNSUPPORTED


def test_interface_subnet_requires_static_evidence_and_propagates_interface_dependency():
    source = FGConfig(addresses=[FGAddress(name='connected', type='interface-subnet', raw_extra={'interface': 'port1'})],
        interfaces=[FGInterface(name='port1', type='physical', ip='192.0.2.10 255.255.255.0')])
    options = PANMigrationOptions(vdoms={'root': {'vsys': 'vsys1', 'virtual_router': 'VR'}},
        interfaces={'root': {'port1': {'target_interface': 'ethernet1/1', 'target_zone': 'inside'}}})
    plan = FortiGateToPaloAltoPlanner().plan(source, object(), options)
    assert plan.addresses[0].value == '192.0.2.0/24'
    assert plan.addresses[0].status is PANMigrationStatus.SUPPORTED
    index = build_plan_dependency_index(plan, PANMigrationDecisionSet())
    assert item_key(plan.addresses[0]) in index.dependents_by_item[item_key(plan.interfaces[0])]
    missing = replace(plan, interfaces=())
    assert not any(' address connected ' in command for command in PANSetRenderer().render(missing).commands)
    invalid = replace(plan, interfaces=(replace(plan.interfaces[0], status=PANMigrationStatus.UNSUPPORTED),))
    assert not any(' address connected ' in command for command in PANSetRenderer().render(invalid).commands)
    mismatched = replace(plan, addresses=(replace(plan.addresses[0], value='198.51.100.0/24'),))
    assert not any(' address connected ' in command for command in PANSetRenderer().render(mismatched).commands)
    source.interfaces[0].mode = 'dhcp'
    assert FortiGateToPaloAltoPlanner().plan(source, object(), options).addresses[0].status is PANMigrationStatus.UNSUPPORTED


def test_pan_os_11_1_does_not_imply_pa820_hardware_ports():
    source = FGConfig(interfaces=[FGInterface(name='port1', type='physical', ip='192.0.2.1/24')])
    fields = {'vdoms': {'root': {'vsys': 'vsys1', 'virtual_router': 'VR'}},
              'interfaces': {'root': {'port1': {'target_interface': 'ethernet1/20', 'target_zone': 'inside'}}}}
    generic = PANMigrationOptions(**fields, conversion_settings={'panos_version': '11.1'})
    interface, = FortiGateToPaloAltoPlanner().plan(source, object(), generic).interfaces
    assert interface.status is PANMigrationStatus.SUPPORTED
    assert 'target_model' not in generic.conversion_settings
    bounded = PANMigrationOptions(**fields, conversion_settings={'panos_version': '11.1', 'target_model': 'PA-820'})
    interface, = FortiGateToPaloAltoPlanner().plan(source, object(), bounded).interfaces
    assert interface.status is PANMigrationStatus.MANUAL_REVIEW

# --- test_address_tagging_review.py ---
def _tagging_source_text(family, settings):
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


def _tagging_migrate(text, inventory=True):
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
    baseline = _tagging_migrate(_tagging_source_text(family, ''), inventory)
    assert baseline.artifact_status == 'READY'
    assert any('rulebase security' in command for command in baseline.rendered.commands)
    tagging = f'config tagging\nedit label\n{settings}\nnext\nend'
    result = _tagging_migrate(_tagging_source_text(family, tagging), inventory)
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
    text = _tagging_source_text(family, 'config tagging\nedit label\nset tags staff\nnext\nend')
    preview = client.post('/api/preview', data={'file': (io.BytesIO(text.encode()), 'source.conf')})
    assert preview.status_code == 200
    response = client.post('/api/migration/design/prepare', json={
        'source': preview.get_json()['source_evidence'], 'workflow_mode': 'OFFLINE_EXPORT'})
    assert response.status_code == 200
    rows = [row for row in response.get_json()['draft']['configuration'] if row['source_kind'] == family]
    assert len(rows) == 1 and rows[0]['status'] == 'UNSUPPORTED'
    assert any('tagging' in reason for reason in rows[0]['blocking_reasons'])

# --- test_wildcard_and_zone_names.py ---
def test_explicit_wildcard_needs_no_mapping_and_absence_is_not_any():
    source = FGConfig(policies=[FGPolicy(srcintf=['any'], dstintf=['port1'])])
    required = build_mapping_requirements(source, object())
    assert [r['source_name'] for r in required['interfaces']] == ['port1']
    options = PANMigrationOptions()
    warnings = []
    assert _zones(['any'], 'root', options, warnings) == ('any',)
    assert _zones([], 'root', options, warnings) == ()
    assert _zones(['any', 'port1'], 'root', options, warnings) == ()
    assert warnings == ['mixed wildcard and named policy interfaces require manual review']
    assert _policy_zones(source.policies[0], ['any'], options) == ('any',)
    assert _target_zone(options, 'root', 'any', ()) is None
    assert _policy_zones(source.policies[0], ['any', 'port1'], options) == ()


@pytest.mark.parametrize('name', ['EN UAT', 'root-Hong Leong Bank', 'a'*31])
def test_documented_zone_names_are_valid(name):
    assert zone_name_issue(name) is None


@pytest.mark.parametrize('name', ['', ' ', 'a'*32, 'zone/name', 'zone:name', 'zone\nname'])
def test_invalid_zone_names_block_planned_configuration(name):
    assert zone_name_issue(name)
    plan = PANMigrationPlan(zones=(PlannedZone(source_object_type='zone', source_name=name, target_name=name, target_vsys='vsys1'),))
    assert any(issue.code == 'invalid_zone_name' for issue in validate_plan(plan).issues)
