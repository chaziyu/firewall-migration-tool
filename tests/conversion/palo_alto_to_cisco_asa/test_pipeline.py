from dataclasses import replace
from pathlib import Path

import pytest

from fwmigrate.conversion.palo_alto_to_cisco_asa.application import approve_design, build_artifact, build_review, verify_export_artifact
from fwmigrate.conversion.palo_alto_to_cisco_asa.options import ASAMigrationOptions
from fwmigrate.conversion.palo_alto_to_cisco_asa.plan_dependencies import TRAFFIC
from fwmigrate.conversion.palo_alto_to_cisco_asa.planner import PaloAltoToCiscoASAPlanner
from fwmigrate.conversion.palo_alto_to_cisco_asa.rendering.renderer import ASACLIRenderer
from fwmigrate.vendors.palo_alto.source_report import PaloAltoSourceReporter
from fwmigrate.vendors.palo_alto.source_model import pan_scope_identity
from fwmigrate.vendors.cisco_asa.source_report import CiscoASASourceReporter


FIXTURE = Path(__file__).parents[2] / 'fixtures/palo_alto/asa_policy_explicit.xml'


def analysis_options(text=None):
    analysis = PaloAltoSourceReporter().analyze_source(text or FIXTURE.read_text(encoding='utf-8'))
    scope = next(scope for scope in analysis.config.scopes if scope.kind == 'vsys')
    options = ASAMigrationOptions(source_scope=pan_scope_identity(scope),
        interfaces={'ethernet1/1': {'target_interface': 'GigabitEthernet0/0', 'nameif': 'inside', 'security_level': 100},
                    'ethernet1/2': {'target_interface': 'GigabitEthernet0/1', 'nameif': 'outside', 'security_level': 0}},
        new_target_confirmed=True, routing_complete=True)
    return analysis, options


def plan(analysis, options):
    return PaloAltoToCiscoASAPlanner().plan(analysis.config, analysis.derived, options)


def all_ready(review):
    return [row.key for row in review['plan'].items if not row.blockers]


def test_supported_policy_is_atomic_preserves_ports_order_and_roundtrips():
    analysis, options = analysis_options()
    before = analysis.config.model_dump_json()
    migration = plan(analysis, options)
    policy = next(row for row in migration.items if row.family == 'policy')
    assert not policy.blockers, policy.blockers
    assert dict(policy.settings)['egress_zones'] == ('outside',)
    review = build_review(analysis, options, 'a'*64)
    with pytest.raises(ValueError, match='missing dependencies'):
        approve_design(review, review['draft'], [policy.key])
    approval = approve_design(review, review['draft'], all_ready(review))
    assert {row.key for row in migration.items if row.family in TRAFFIC} <= set(approval['selected_items'])
    artifact = build_artifact(analysis, options, 'a'*64, approval)
    text = artifact['command_text']
    assert 'permit tcp object inside-net range 1024 65535 object app-server eq 443' in text
    assert 'object app-server range 8443 8444' in text
    assert text.index('extended permit') < text.index('extended deny ip any4 any4') < text.index('access-group') < text.index(' no shutdown')
    native = CiscoASASourceReporter().analyze_source(text)
    # The source parser treats CLI re-entry for final activation as duplicate snapshot sections.
    assert [(issue.category, issue.message) for issue in native.validation.issues if issue.severity == 'error'] == [
        ('interface', 'Duplicate interface definition'), ('interface', 'Duplicate interface definition')]
    assert [row.raw_line for row in native.config.access_rules] == [line for line in text.splitlines() if line.startswith('access-list ')]
    assert [row.raw_line for row in native.config.acl_bindings] == [line for line in text.splitlines() if line.startswith('access-group ')]
    assert all(row.source_port.values == ['1024', '65535'] for row in native.config.access_rules if row.action == 'permit')
    assert [row.destination_port.values for row in native.config.access_rules if row.action == 'permit'] == [['443'], ['8443', '8444']]
    assert verify_export_artifact(artifact) is artifact
    assert analysis.config.model_dump_json() == before
    assert all(command.strip().split()[0] not in {'write', 'clear', 'changeto', 'copy'} for command in text.splitlines())


@pytest.mark.parametrize('change', ['cross-zone','uncovered','nat','appid','default','logging','incomplete','equal-security','mapping','zone-protection','sdwan','named-always'])
def test_unproven_traffic_never_emits_interfaces_acl_or_routes(change):
    analysis, options = analysis_options()
    source = analysis.config
    if change == 'cross-zone':
        source.addresses[1].ip_netmask = '192.0.2.0/23'
    elif change == 'uncovered':
        source.virtual_routers[0].static_routes = []
        source.addresses[1].ip_netmask = '203.0.113.20'
    elif change == 'nat':
        source.nat_rules[0].disabled = 'no'
    elif change == 'appid':
        source.security_rules[0].application = ['web-browsing']
    elif change == 'default':
        source.default_security_rules = []
    elif change == 'logging':
        source.security_rules[0].log_end = 'yes'
    elif change == 'incomplete':
        options = replace(options, routing_complete=False)
    elif change == 'equal-security':
        options = replace(options, interfaces={**options.interfaces, 'ethernet1/2': {'target_interface':'GigabitEthernet0/1','nameif':'outside','security_level':100}})
    elif change == 'zone-protection':
        source.zones[0].zone_protection_profile = 'inspection'
    elif change == 'sdwan':
        source.interfaces[0].sdwan_enabled = 'yes'
    elif change == 'named-always':
        source.security_rules[0].schedule = 'always'
    else:
        options = replace(options, interfaces={})
    migration = plan(analysis, options)
    assert all(row.blockers for row in migration.items if row.family in TRAFFIC)
    text = ASACLIRenderer().render(migration).command_text
    assert not any(line.startswith(('interface ', 'route ', 'access-list ', 'access-group ', 'same-security')) for line in text.splitlines())
    assert 'object network inside-net' in text


def test_explicit_unrestricted_zone_and_same_interface_choices_stay_reviewed():
    analysis, options = analysis_options()
    analysis.config.security_rules[0].to_zones = ['any']
    migration = plan(analysis, options)
    assert not next(row for row in migration.items if row.family == 'policy').blockers
    analysis.config.security_rules[0].destination = ['any']
    assert next(row for row in plan(analysis, options).items if row.family == 'policy').blockers
    options = replace(options, permit_intra_interface=True, permit_inter_interface=True)
    assert not next(row for row in plan(analysis, options).items if row.family == 'policy').blockers


def test_failed_predecessor_blocks_successor_and_incomplete_selection_cannot_render():
    analysis, options = analysis_options()
    first = analysis.config.security_rules[0]
    second = first.model_copy(deep=True)
    second.name = 'later-allow'
    second.source_order = first.source_order + 1
    second.source_path += '/later'
    first.application = ['unknown-app']
    analysis.config.security_rules.append(second)
    assert all(row.blockers for row in plan(analysis, options).items if row.family == 'policy')
    first.application = ['any']
    options = replace(options, ace_limit=1)
    assert all(row.blockers for row in plan(analysis, options).items if row.family in TRAFFIC)


def test_approval_expires_and_option_source_changes_revoke_artifact_generation():
    analysis, options = analysis_options()
    review = build_review(analysis, options, 'a'*64)
    approval = approve_design(review, review['draft'], all_ready(review))
    with pytest.raises(ValueError):
        build_artifact(analysis, replace(options, permit_intra_interface=True), 'a'*64, approval)
    with pytest.raises(ValueError):
        build_artifact(analysis, options, 'b'*64, approval)
    for expires in (0, float('nan'), float('inf')):
        with pytest.raises(ValueError):
            build_artifact(analysis, options, 'a'*64, {**approval, 'expires_at': expires})


def test_cli_uses_the_same_validation_gate_as_the_web_path(tmp_path):
    import json
    import yaml
    from fwmigrate.conversion.palo_alto_to_cisco_asa.application.cli import run_cli
    from fwmigrate.source_reporting.builtin import register_builtin_source_reporters

    register_builtin_source_reporters()
    _, options = analysis_options()
    mapping = tmp_path / 'mapping.yaml'
    mapping.write_text(yaml.safe_dump(options.to_dict()), encoding='utf-8')
    folder = tmp_path / 'valid'
    run_cli(input_path=FIXTURE, output_path=folder, format='cfg', mapping_path=mapping, target_config_path=None)
    assert 'access-group PAN_inside in interface inside' in (folder/'asa_config.cfg').read_text()
    bad = tmp_path / 'invalid.xml'
    bad.write_text(FIXTURE.read_text(encoding='utf-8').replace('<source-user>', '<schedule>nonexistent</schedule><source-user>'), encoding='utf-8')
    folder = tmp_path / 'invalid'
    run_cli(input_path=bad, output_path=folder, format='cfg', mapping_path=mapping, target_config_path=None)
    assert (folder/'asa_config.cfg').read_bytes() == b''
    assert json.loads((folder/'migration_report.json').read_text())['plan_status'] == 'BLOCKED'


def test_coverage_keeps_identical_names_in_other_vsys_manual():
    from fwmigrate.conversion.palo_alto_to_cisco_asa.review.coverage import build_coverage
    from fwmigrate.vendors.palo_alto.source_model import PANScope, PANSourceRecord

    analysis, options = analysis_options()
    migration = plan(analysis, options)
    address = next(row for row in migration.items if row.family == 'address')
    scope = next(row for row in analysis.config.scopes if row.kind == 'vsys')
    rows = [PANSourceRecord(kind='address', name=address.source_name, source_path=address.source_path, scope=scope),
            PANSourceRecord(kind='address', name=address.source_name, source_path=address.source_path,
                            scope=PANScope(kind='vsys',name='other',device_name=scope.device_name))]
    assert build_coverage(migration, rows) == {'source_records':2, 'planned_records':1, 'manual_records':1}
