from dataclasses import replace
import hashlib
import json
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5
import xml.etree.ElementTree as ET

import pytest

from fwmigrate.conversion.palo_alto_to_checkpoint.application import approve_design, build_artifact, build_review, verify_export_artifact
from fwmigrate.conversion.palo_alto_to_checkpoint.options import CPMigrationOptions
from fwmigrate.conversion.palo_alto_to_checkpoint.plan_dependencies import dispositions
from fwmigrate.conversion.palo_alto_to_checkpoint.planner import PaloAltoToCheckPointPlanner
from fwmigrate.conversion.palo_alto_to_checkpoint.rendering.management import MANAGEMENT_FILE, BINDINGS_FILE, COMMANDS_FILE, GAIA_FILE
from fwmigrate.vendors.checkpoint.source_report import CheckPointSourceReporter
from fwmigrate.vendors.palo_alto.source_report import PaloAltoSourceReporter


FIXTURE = Path(__file__).parents[2] / 'fixtures/palo_alto/checkpoint_policy_explicit.xml'
SCHEMA = Path(__file__).parents[2] / 'fixtures/checkpoint/panos_target_api_1_8_1_fields.json'


def analyze(text=None):
    return PaloAltoSourceReporter().analyze_source(text or FIXTURE.read_text(encoding='utf-8'))


def ready(review):
    return [row['key'] for row in review['report']['items'] if row['render_disposition'] in {'CREATE', 'REUSE'}]


def artifact(analysis=None, options=None, **target):
    analysis = analysis or analyze()
    review = build_review(analysis, options or {}, 'source', **target)
    approval = approve_design(review, review['draft'], ready(review))
    built = build_artifact(analysis, options or {}, 'source', approval, **target)
    return review, approval, verify_export_artifact(built)


def resolve(value, bindings):
    if isinstance(value, dict):
        if set(value) == {'$response_binding'}:
            return bindings[value['$response_binding']]
        return {key: resolve(child, bindings) for key, child in value.items()}
    if isinstance(value, list):
        return [resolve(child, bindings) for child in value]
    return value


def test_native_uid_dependencies_ports_order_and_official_request_fields():
    analysis = analyze()
    before = analysis.config.model_dump_json()
    review, _, built = artifact(analysis)
    schema = json.loads(SCHEMA.read_text())['commands']
    spec = json.loads(built['files'][MANAGEMENT_FILE]['content'])
    bindings, seen = {}, set()
    for operation in spec['operations']:
        assert set(operation['depends_on']) <= seen
        body = resolve(operation['request_body_template'], bindings)
        allowed = schema[operation['path']]
        assert set(body) <= set(allowed)
        for key, value in body.items():
            kind = 'boolean' if type(value) is bool else 'integer' if type(value) is int else (
                'string' if isinstance(value, str) else 'list' if isinstance(value, list) else 'object')
            assert kind in allowed[key], (key, kind, allowed[key])
        if operation['path'].endswith('add-service-tcp'):
            assert body['source-port'] == '1024-65535'
            assert body['port'] in {'443', '8443-8444'}
            assert body['match-by-protocol-signature'] is False
            assert body['match-for-any'] is False
        binding = operation['response_binding']
        assert binding['json_pointer'] in {'/uid', '/access-layers/0/uid'}
        bindings[binding['binding_id']] = str(uuid5(NAMESPACE_URL, operation['operation_id']))
        seen.add(operation['operation_id'])
    planned = [row for row in review['plan'].items if row.family == 'policy']
    assert len(planned) == 2 and not any(row.blockers for row in planned)
    emitted = [op for op in spec['operations'] if op['operation_id'] in {row.key for row in planned}]
    assert [op['operation_id'] for op in emitted] == [row.key for row in planned]
    assert emitted[1]['request_body_template']['position'] == {'below': {'$response_binding': planned[0].key + '.uid'}}
    assert analysis.config.model_dump_json() == before
    assert built['files'][GAIA_FILE]['content'] == ''
    assert 'source_vdom' not in json.dumps(built)
    assert all(op['path'].rsplit('/', 1)[-1] not in {'login', 'publish', 'install-policy'} for op in spec['operations'])
    for line in built['files'][COMMANDS_FILE]['content'].splitlines():
        if 'mgmt_cli -s ' in line:
            assert not any(word in line for word in (' login ', ' publish ', ' install-policy ', 'set-if-exists'))
    manifest = json.loads(built['files'][BINDINGS_FILE]['content'])
    for name, record in manifest['files'].items():
        raw = built['files'][name]['content'].encode()
        assert len(raw) == record['byte_count']
        assert hashlib.sha256(raw).hexdigest() == record['sha256']
    assert manifest['deferred_application_bindings'] == ['management_target', 'management_domain', 'install_on']


@pytest.mark.parametrize(('field', 'value'), [
    ('from/member', 'inside'), ('application/member', 'ssl'), ('log-end', 'yes'),
    ('action', 'deny'), ('negate-source', 'yes'), ('rule-type', 'intrazone'), ('schedule', 'always'),
])
def test_unproved_policy_or_predecessor_never_becomes_an_enabled_request(field, value):
    tree = ET.fromstring(FIXTURE.read_text(encoding='utf-8'))
    rule = tree.find('.//vsys/entry/rulebase/security/rules/entry')
    node = rule.find(field)
    if node is None:
        node = ET.SubElement(rule, field)
    node.text = value
    review = build_review(analyze(ET.tostring(tree, encoding='unicode')), {}, 'source')
    state = dispositions(review['plan'])
    policies = [row for row in review['plan'].items if row.family == 'policy']
    assert policies and all(state[row.key] == 'BLOCK' for row in policies)
    assert not {row.key for row in policies} & {row['operation_id'] for row in json.loads(review['rendered'].management_text)['operations']}


def test_default_nat_zone_protection_and_unknown_version_fail_closed():
    original = analyze()
    for config in [
        original.config.model_copy(update={'default_security_rules': []}),
        original.config.model_copy(update={'nat_rules': [row.model_copy(update={'disabled': 'no'}) for row in original.config.nat_rules]}),
        original.config.model_copy(update={'zones': [row.model_copy(update={'raw_extra': {'zone-protection-profile': 'unknown'}}) for row in original.config.zones]}),
    ]:
        plan = PaloAltoToCheckPointPlanner().plan(config, original.derived, {})
        state = dispositions(plan)
        assert all(state[row.key] == 'BLOCK' for row in plan.items if row.family == 'policy')
    changed = FIXTURE.read_text().replace('version="11.1.0"', 'version="unknown"')
    assert changed != FIXTURE.read_text()
    review = build_review(analyze(changed), {}, 'source')
    assert all(row['render_disposition'] == 'BLOCK' for row in review['report']['items'] if row['family'] == 'policy')


def test_strict_dependency_approval_expiry_and_context_binding():
    analysis = analyze()
    review = build_review(analysis, {}, 'source')
    policy = next(row for row in review['plan'].items if row.family == 'policy')
    with pytest.raises(ValueError, match='dependency'):
        approve_design(review, review['draft'], [policy.key])
    approval = approve_design(review, review['draft'], ready(review))
    for expires in [0, float('nan'), float('inf')]:
        with pytest.raises(ValueError):
            build_artifact(analysis, {}, 'source', {**approval, 'expires_at': expires})
    for source, options in [('changed', {}), ('source', {'policy_package': 'another'})]:
        with pytest.raises(ValueError):
            build_artifact(analysis, options, source, approval)
    built = build_artifact(analysis, {}, 'source', approval)
    for expires in [0, float('nan'), float('inf')]:
        with pytest.raises(ValueError):
            verify_export_artifact({**built, 'expires_at': expires})


def target_snapshot(review):
    domain, server = 'Lab', 'management.example'
    responses = []
    for row in review['plan'].items:
        if row.family != 'address':
            continue
        op = dict(row.settings)['management_operation']
        body = {key: value for key, value in op['request_body_template'].items() if key != 'details-level'}
        kind = op['path'].removeprefix('/web_api/add-')
        command = {'host': 'show-hosts', 'network': 'show-networks', 'address-range': 'show-address-ranges'}[kind]
        obj = {**body, 'type': kind, 'uid': str(uuid5(NAMESPACE_URL, row.key))}
        responses.append({'command': command, 'domain': domain, 'data': {'objects': [obj], 'from': 1, 'to': 1, 'total': 1}})
    return {'format': 'checkpoint-export-v1', 'api_version': '1.8.1', 'management_server': server,
            'domain': domain, 'selected_domain': domain, 'responses': responses}


def destination(snapshot, families=('objects', 'services', 'nat')):
    text = json.dumps(snapshot)
    return {'target': CheckPointSourceReporter().analyze_source(text), 'target_source_text': text,
            'target_metadata': {'context': 'Lab', 'version': '1.8.1', 'mode': 'management', 'complete_families': list(families)}}


def test_existing_snapshot_uid_reuse_completeness_nat_collision_and_domain():
    analysis = analyze()
    options = CPMigrationOptions(target_mode='existing', management_target='management.example', management_domain='Lab')
    initial = build_review(analysis, options, 'source')
    assert not ready(initial)
    snapshot = target_snapshot(initial)
    target = destination(snapshot)
    review, _, built = artifact(analysis, options, **target)
    assert sum(row['render_disposition'] == 'REUSE' for row in review['report']['items']) == 2
    assert all(row['render_disposition'] == 'BLOCK' for row in review['report']['items'] if row['family'] == 'policy')
    spec = json.loads(built['files'][MANAGEMENT_FILE]['content'])
    assert not any(row['path'].endswith(('add-host', 'add-network')) for row in spec['operations'])
    assert COMMANDS_FILE not in built['files']
    assert any(isinstance(ref, str) for op in spec['operations'] if op['path'].endswith('add-group') for ref in op['request_body_template']['members'])
    incomplete = build_review(analysis, options, 'source', **destination(snapshot, ('objects',)))
    assert not ready(incomplete)
    damaged = json.loads(json.dumps(snapshot))
    damaged['responses'][0]['data']['objects'][0]['nat-settings'] = {'auto-rule': True}
    compared = build_review(analysis, options, 'source', **destination(damaged))
    assert any('TARGET_OBJECT_COLLISION_OR_EQUIVALENCE_UNKNOWN' in row['blockers'] for row in compared['report']['items'])
    for field, value in [('management_server', 'foreign'), ('api_version', '1.9')]:
        with pytest.raises(ValueError):
            build_review(analysis, options, 'source', **destination({**snapshot, field: value}))
    foreign = json.loads(json.dumps(snapshot))
    foreign['responses'][0]['domain'] = 'Foreign'
    with pytest.raises(ValueError):
        build_review(analysis, options, 'source', **destination(foreign))


def test_layer_configuration_cannot_point_at_an_existing_uid():
    analysis = analyze()
    review = build_review(analysis, {}, 'source')
    from fwmigrate.conversion.palo_alto_to_checkpoint.plan_dependencies import validate_plan
    rows = []
    for row in review['plan'].items:
        if row.family == 'layer':
            op = dict(dict(row.settings)['management_operation'])
            op['request_body_template'] = {**op['request_body_template'], 'uid': 'existing-layer'}
            row = replace(row, settings=(('management_operation', op),))
        rows.append(row)
    with pytest.raises(ValueError, match='newly created'):
        validate_plan(replace(review['plan'], items=tuple(rows)))


def test_group_uid_reuse_and_duplicate_target_uid_are_checked():
    analysis = analyze()
    options = CPMigrationOptions(target_mode='existing', management_target='management.example', management_domain='Lab')
    initial = build_review(analysis, options, 'source')
    snapshot = target_snapshot(initial)
    group = next(row for row in initial['plan'].items if row.family == 'address_group')
    body = dict(group.settings)['management_operation']['request_body_template']
    group_body = {key: value for key, value in body.items() if key != 'details-level'}
    group_body['members'] = [str(uuid5(NAMESPACE_URL, key)) for key in group.dependencies]
    snapshot['responses'].append({'command': 'show-groups', 'domain': 'Lab', 'data': {
        'objects': [{**group_body, 'type': 'group', 'uid': str(uuid5(NAMESPACE_URL, group.key))}],
        'from': 1, 'to': 1, 'total': 1}})
    compared = build_review(analysis, options, 'source', **destination(snapshot))
    assert next(row for row in compared['report']['items'] if row['key'] == group.key)['render_disposition'] == 'REUSE'
    snapshot['responses'][1]['data']['objects'][0]['uid'] = snapshot['responses'][0]['data']['objects'][0]['uid']
    with pytest.raises(ValueError):
        build_review(analysis, options, 'source', **destination(snapshot))


def test_cycles_are_rejected_without_mutating_native_source():
    analysis = analyze()
    group = analysis.config.address_groups[0].model_copy(update={'static_members': [analysis.config.address_groups[0].name]})
    source = analysis.config.model_copy(update={'address_groups': [group]})
    before = source.model_dump_json()
    with pytest.raises(ValueError, match='cycle'):
        PaloAltoToCheckPointPlanner().plan(source, analysis.derived, {})
    assert source.model_dump_json() == before


def test_cli_uses_native_validation_and_separate_review_files(tmp_path):
    from click.testing import CliRunner
    from fwmigrate.main import cli
    folder = tmp_path / 'review'
    result = CliRunner().invoke(cli, ['migrate', '--input', str(FIXTURE), '--output', str(folder),
        '--source-vendor', 'palo_alto', '--target-vendor', 'checkpoint', '--format', 'json'])
    assert result.exit_code == 0, result.output
    report = json.loads((folder / 'migration_report.json').read_text())
    assert report['pair_id'] == 'palo_alto_to_checkpoint'
    assert report['management_operation_count'] == 15
    assert report['cli_output_is_unapproved_review_material'] is True
    bad = tmp_path / 'invalid.xml'
    bad.write_text(FIXTURE.read_text().replace('<source-user>', '<schedule>nonexistent</schedule><source-user>'), encoding='utf-8')
    from fwmigrate.conversion.palo_alto_to_checkpoint.application.cli import run_cli
    folder = tmp_path / 'invalid'
    run_cli(input_path=bad, output_path=folder, format='json', mapping_path=None, target_config_path=None)
    assert json.loads((folder / MANAGEMENT_FILE).read_text())['operation_count'] == 0
    assert json.loads((folder / 'migration_report.json').read_text())['plan_status'] == 'BLOCKED'
