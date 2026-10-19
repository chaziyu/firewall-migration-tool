from copy import deepcopy
from types import SimpleNamespace
from dataclasses import replace
import pytest

from fwmigrate.conversion.fortigate_to_palo_alto.application.decision_documents import build_decision_document, load_decision_document
from fwmigrate.conversion.fortigate_to_palo_alto.application.review import build_review_state
from fwmigrate.conversion.fortigate_to_palo_alto.design.deterministic import build_deterministic_draft, approve_draft
from fwmigrate.conversion.fortigate_to_palo_alto.decisions import PANDecisionReviewState, PANMigrationDecisionSet, make_decision_key
from fwmigrate.vendors.fortigate.model.source import FGConfig
from fwmigrate.vendors.fortigate.model.interface import FGInterface
from fwmigrate.vendors.fortigate.model.zone import FGZone
from fwmigrate.vendors.fortigate.model.address import FGAddress
from fwmigrate.conversion.fortigate_to_palo_alto.design.draft import draft_issues


def derived():
    return SimpleNamespace(services=SimpleNamespace(services=(), groups=()), nat=(),
                           topology=SimpleNamespace(interfaces=(), vpns=()))


def test_source_defects_and_task_counts_are_reported_without_repair():
    config = FGConfig(interfaces=[FGInterface(name='wan1', type='physical', ip='invalid diagnostic text')])
    original = deepcopy(config)
    result, _ = draft(config, workflow_mode='OFFLINE_EXPORT')
    body = result.to_dict()
    assert len(body['source_issues']) == 1
    assert body['source_issues'][0]['code'] == 'SOURCE_INTERFACE_IPV4_INVALID'
    assert body['source_issues'][0]['affected_keys']
    assert body['task_summary']['manual_items'] == sum(row['status'] == 'UNSUPPORTED' for row in body['configuration'])
    assert config == original
    assert not any(row['status'] == 'READY' for row in body['configuration'] if row['family'] == 'interface')
    from fwmigrate.conversion.fortigate_to_palo_alto.validation import validate_source_interfaces
    assert validate_source_interfaces(FGConfig(interfaces=[FGInterface(name='bare', ip='192.0.2.1')]))


def test_issue_routes_are_scoped_and_unknown_work_stays_read_only():
    findings = [
        {'code': 'VPN_PARAMETERS_REQUIRED', 'source_vdom': 'root', 'source_kind': 'ipsec_phase1',
         'fields': ['dh_group'], 'member_keys': ['root/ipsec_phase1/shared'], 'message': 'Review VPN values.'},
        {'code': 'VPN_PARAMETERS_REQUIRED', 'source_vdom': 'branch', 'source_kind': 'ipsec_phase1',
         'fields': ['dh_group'], 'member_keys': ['branch/ipsec_phase1/shared'], 'message': 'Review VPN values.'},
        {'code': 'SOURCE_INTERFACE_IPV4_INVALID', 'source_vdom': 'root', 'source_name': 'wan1',
         'message': 'Correct the source address.'},
        {'code': 'UNKNOWN_UNSUPPORTED', 'source_vdom': 'root', 'source_name': 'feature',
         'message': 'Separate work.'},
    ]
    issues = draft_issues([], [], findings)
    vpn = [issue for issue in issues if issue['code'] == 'VPN_PARAMETERS_REQUIRED']
    assert len(vpn) == 2
    assert all(issue['action']['kind'] == 'EDIT_SETTINGS' and issue['action']['section'] == 'vpn' for issue in vpn)
    assert {issue['action']['source_vdom'] for issue in vpn} == {'root', 'branch'}
    assert vpn[0]['affected_keys'] == ['root/ipsec_phase1/shared']
    source = next(issue for issue in issues if issue['code'] == 'SOURCE_INTERFACE_IPV4_INVALID')
    assert source['action'] == {'kind': 'REVIEW_SOURCE'}
    assert draft_issues([], []) == []


def test_port_pool_exhaustion_scope_and_manual_overrides():
    config = FGConfig(interfaces=[FGInterface(name=f'port{number}', type='physical') for number in range(1, 24)])
    settings = {'target_model': 'PA-820', 'panos_version': '11.1'}
    result, _ = draft(config, workflow_mode='OFFLINE_EXPORT', conversion_settings=settings)
    ports = [row for row in result.decisions if row.target_field == 'target_interface']
    assert sum(bool(row.proposed_value) for row in ports) == 12
    assert all(row.proposed_value != 'ethernet1/13' for row in ports)
    key = make_decision_key('root', 'interface', 'port1', 'target_interface')
    invalid, _ = draft(config, {key: 'ethernet1/13'}, workflow_mode='OFFLINE_EXPORT', conversion_settings=settings)
    assert next(row for row in invalid.decisions if row.decision_key == key).status == 'CONFLICT'
    excluded, _ = draft(config, workflow_mode='OFFLINE_EXPORT', conversion_settings={**settings, 'excluded_interfaces': ['root/port1']})
    assert next(row for row in excluded.decisions if row.decision_key == key).status == 'UNSUPPORTED'
    assert next(row for row in excluded.configuration if row['source_name'] == 'port1' and row['family'] == 'interface')['status'] == 'UNSUPPORTED'


def test_bounded_port_pool_proposes_referenced_or_addressed_interfaces_before_unused_ports():
    config = FGConfig(interfaces=[FGInterface(name=f'port{number}', type='physical') for number in range(1, 14)]
        + [FGInterface(name='wan', type='physical', ip='192.0.2.1/24')])
    result, _ = draft(config, workflow_mode='OFFLINE_EXPORT', conversion_settings={'target_model': 'PA-820'})
    assert next(row for row in result.decisions if row.source_name == 'wan' and row.target_field == 'target_interface').proposed_value == 'ethernet1/1'
    assert any(row.source_name.startswith('port') and not row.proposed_value for row in result.decisions if row.target_field == 'target_interface')


def test_source_only_coverage_is_visible_and_cannot_be_approved():
    from fwmigrate.vendors.fortigate.model.vip import FGVIPGroup
    config = FGConfig(addresses=[FGAddress(name='net', subnet='192.0.2.0 255.255.255.0')],
                      vip_groups=[FGVIPGroup(name='unsupported-group', vdom='blue')])
    result, decisions = draft(config)
    gap = next(row for row in result.configuration if row['source_kind'] == 'vip_group')
    assert gap['source_vdom'] == 'blue' and gap['source_name'] == 'unsupported-group'
    assert gap['status'] == 'UNSUPPORTED' and gap['operation'] is None
    assert 'Manual implementation required' in gap['blocking_reasons'][-1]
    with pytest.raises(ValueError, match='blocked'):
        approve_draft(decisions, result, [gap['group_key']])
    without_gap, _ = draft(FGConfig(addresses=config.addresses))
    assert result.to_dict()['digest'] != without_gap.to_dict()['digest']


def test_missing_vsys_mapping_is_not_counted_as_manual_work():
    config = FGConfig(addresses=[FGAddress(name='net', subnet='192.0.2.0 255.255.255.0'),
                                FGAddress(name='manual', wildcard_fqdn='*.example.com')])
    result, decisions = draft(config)
    address = next(row for row in result.configuration if row['source_name'] == 'net')
    manual = next(row for row in result.configuration if row['source_name'] == 'manual')
    assert address['status'] == 'NEEDS_INPUT'
    assert manual['status'] == 'UNSUPPORTED'
    assert result.to_dict()['readiness']['coverage'] == {'supported': 0, 'manual': 1}
    with pytest.raises(ValueError, match='blocked'):
        approve_draft(decisions, result, [address['group_key']])


def test_recommendation_only_work_is_visible_as_manual_work_before_approval():
    from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter
    analysis = FortiGateSourceReporter().analyze_source('''config user local
 edit manual-user
  set type password
 next
end
''')
    config = analysis.extracted.config
    state = build_review_state(config, analysis.derived, 'source', include_configuration=True)
    result = build_deterministic_draft(config, analysis.derived, state['decisions'], source_digest='source')
    gap = next(row for row in result.configuration if row['source_kind'] == 'local_user')
    assert gap['status'] == 'UNSUPPORTED' and gap['source_name'] == 'manual-user'
    assert 'review guidance' in gap['blocking_reasons'][0]
    with pytest.raises(ValueError, match='blocked'):
        approve_draft(state['decisions'], result, [gap['group_key']])


def draft(config, overrides=None, **kwargs):
    views = derived()
    state = build_review_state(config, views, 'source', include_configuration=True)
    return build_deterministic_draft(config, views, state['decisions'], source_digest='source',
                                     overrides=overrides, **kwargs), state['decisions']


@pytest.mark.parametrize('members,operation', [(['ethernet1/1'], 'CONFIGURE'), (['ethernet1/1', 'ethernet1/2'], 'REUSE')])
def test_consolidated_zone_classification_reaches_all_draft_mapping_rows(members, operation):
    from fwmigrate.vendors.palo_alto.native import build_derived_views
    from fwmigrate.vendors.palo_alto.source_builder import build_panos_config
    config = FGConfig(interfaces=[FGInterface(name=name, type='physical') for name in ('lan1', 'lan2')],
        zones=[FGZone(name=name, members=[member]) for name, member in (('first', 'lan1'), ('second', 'lan2'))])
    membership = ''.join(f'<member>{name}</member>' for name in members)
    pan_config = build_panos_config(f"""<config><devices><entry name='dev'><vsys><entry name='vsys1'>
      <zone><entry name='trust'><network><layer3>{membership}</layer3></network></entry></zone>
    </entry></vsys></entry></devices></config>""")
    target = SimpleNamespace(config=pan_config, derived=build_derived_views(pan_config))
    overrides = {make_decision_key('root', 'vdom', 'root', 'vsys'): 'vsys1',
        make_decision_key('root', 'vdom', 'root', 'virtual_router'): 'vr'}
    overrides.update({make_decision_key('root', 'interface', name, 'target_interface'): f'ethernet1/{number}'
        for number, name in enumerate(('lan1', 'lan2'), 1)})
    overrides.update({make_decision_key('root', 'zone', name, 'target_zone'): 'trust' for name in ('first', 'second')})
    result, decisions = draft(config, overrides, target=target, target_device='dev', reference_role='DESTINATION')
    rows = [row for row in result.decisions if row.source_kind == 'zone']
    assert len(rows) == 2 and all(row.operation == operation for row in rows)
    zones = [row for row in result.configuration if row['family'] == 'zone']
    assert len(zones) == 1
    assert {row.decision_key for row in rows} <= set(zones[0]['dependencies'])
    assert len(zones[0]['configuration']['source_contributors']) == 2
    changed, _ = draft(config, {**overrides, rows[1].decision_key: 'other'}, target=target,
        target_device='dev', reference_role='DESTINATION')
    assert changed.to_dict()['digest'] != result.to_dict()['digest']
    assert all(row.review_state is PANDecisionReviewState.PENDING for row in decisions.decisions)


def test_offline_proposals_preserve_vdoms_and_do_not_confirm_ownership():
    config = FGConfig(interfaces=[FGInterface(name='port', vdom=name, type='physical') for name in ('b', 'a')])
    result, decisions = draft(config, workflow_mode='OFFLINE_EXPORT')
    assert result.to_dict() == draft(config, workflow_mode='OFFLINE_EXPORT')[0].to_dict()
    scopes = {row.source_vdom: row.proposed_value for row in result.decisions if row.target_field == 'vsys'}
    assert scopes == {'a': 'vsys1', 'b': 'vsys2'}
    assert not decisions.to_options().vdoms
    assert all(not row.approved for row in result.decisions)
    assert {row.source_vdom: row.proposed_value for row in result.decisions if row.target_field == 'target_interface'} == {
        'a': 'ethernet1/1', 'b': 'ethernet1/2'}
    conflict, _ = draft(config, {make_decision_key(vdom, 'vdom', vdom, 'vsys'): 'vsys1'
                                  for vdom in ('a', 'b')}, workflow_mode='OFFLINE_EXPORT')
    assert all(row.status == 'CONFLICT' for row in conflict.decisions if row.target_field == 'vsys')


def test_offline_port_proposals_use_natural_order_and_preserve_explicit_allocations():
    config = FGConfig(interfaces=[FGInterface(name=name, type='physical') for name in ('port10', 'port2', 'port1')])
    original = deepcopy(config)
    key = make_decision_key('root', 'interface', 'port1', 'target_interface')
    result, decisions = draft(config, {key: 'ethernet1/2'}, workflow_mode='OFFLINE_EXPORT')
    ports = {row.source_name: row for row in result.decisions if row.target_field == 'target_interface'}
    assert {name: row.proposed_value for name, row in ports.items()} == {
        'port1': 'ethernet1/2', 'port2': 'ethernet1/1', 'port10': 'ethernet1/3'}
    assert all(row.status == 'READY' and not row.approved for row in ports.values())
    assert 'unverified' in ports['port2'].evidence[0]
    assert ports['port1'].evidence == ('Explicit engineer allocation',)
    assert not decisions.to_options().interfaces
    assert config == original
    reordered = FGConfig(interfaces=list(reversed(config.interfaces)))
    again, _ = draft(reordered, {key: 'ethernet1/2'}, workflow_mode='OFFLINE_EXPORT')
    assert {row.source_name: row.proposed_value for row in again.decisions if row.target_field == 'target_interface'} == {
        name: row.proposed_value for name, row in ports.items()}


def test_offline_ports_preserve_confirmed_values_and_reserve_explicit_subinterface_parents():
    config = FGConfig(interfaces=[FGInterface(name='port1', type='physical'), FGInterface(name='port2', type='physical'),
                                 FGInterface(name='vlan10', interface='port1', vlanid=10)])
    views = derived()
    state = build_review_state(config, views, 'source', include_configuration=True)
    port = make_decision_key('root', 'interface', 'port1', 'target_interface')
    vlan = make_decision_key('root', 'interface', 'vlan10', 'target_interface')
    decisions = PANMigrationDecisionSet(tuple(replace(row, value='ethernet1/3',
        review_state=PANDecisionReviewState.CONFIRMED) if row.key == port else row for row in state['decisions'].decisions))
    result = build_deterministic_draft(config, views, decisions, source_digest='source', workflow_mode='OFFLINE_EXPORT',
        overrides={vlan: 'ethernet1/1.10'})
    ports = {row.source_name: row for row in result.decisions if row.target_field == 'target_interface'}
    assert ports['port1'].proposed_value == 'ethernet1/3' and ports['port1'].approved
    assert ports['port2'].proposed_value == 'ethernet1/2'
    assert ports['vlan10'].proposed_value == 'ethernet1/1.10'
    assert not ports['port2'].approved


@pytest.mark.parametrize('kind', [None, 'tunnel', 'redundant', 'switch'])
def test_offline_port_allocator_does_not_guess_missing_or_unsupported_interface_types(kind):
    config = FGConfig(interfaces=[FGInterface(name='port1', type=kind)])
    result, _ = draft(config, workflow_mode='OFFLINE_EXPORT')
    port = next(row for row in result.decisions if row.target_field == 'target_interface')
    assert port.proposed_value is None and port.status == ('UNSUPPORTED' if kind == 'tunnel' else 'NEEDS_INPUT')


def test_destination_aware_draft_does_not_allocate_physical_ports_without_evidence():
    config = FGConfig(interfaces=[FGInterface(name='port1', type='physical')])
    result, _ = draft(config)
    assert next(row for row in result.decisions if row.target_field == 'target_interface').proposed_value is None


def test_automatic_port_proposals_keep_explicit_duplicate_edits_blocked():
    config = FGConfig(interfaces=[FGInterface(name='port1', type='physical'), FGInterface(name='port2', type='physical')])
    values = {make_decision_key('root', 'interface', name, 'target_interface'): 'ethernet1/1' for name in ('port1', 'port2')}
    result, decisions = draft(config, values, workflow_mode='OFFLINE_EXPORT')
    ports = [row for row in result.decisions if row.target_field == 'target_interface']
    assert all(row.proposed_value == 'ethernet1/1' and row.status == 'CONFLICT' for row in ports)
    with pytest.raises(ValueError, match='blocked'):
        approve_draft(decisions, result, [row.decision_key for row in ports])


def test_offline_invalid_object_names_receive_reviewable_stable_proposals():
    config = FGConfig(addresses=[FGAddress(name='x' * 64, subnet='192.0.2.1 255.255.255.255')])
    result, decisions = draft(config, workflow_mode='OFFLINE_EXPORT')
    row = next(row for row in result.configuration if row['family'] == 'address')
    assert row['status'] == 'READY'
    assert len(row['target_name']) <= 63 and row['source_name'] == 'x' * 64
    assert row['target_name'] == draft(config, workflow_mode='OFFLINE_EXPORT')[0].configuration[0]['target_name']
    assert all(not decision.approved for decision in result.decisions)


def test_offline_virtual_router_name_constraints_block_dependent_topology():
    config = FGConfig(interfaces=[FGInterface(name='port1', type='physical')])
    result, _ = draft(config, {
        make_decision_key('root', 'interface', 'port1', 'target_interface'): 'ethernet1/1',
        make_decision_key('root', 'vdom', 'root', 'virtual_router'): 'x' * 32,
    }, workflow_mode='OFFLINE_EXPORT')
    assert next(row.status for row in result.decisions if row.target_field == 'virtual_router') == 'CONFLICT'
    assert next(row.status for row in result.decisions if row.target_field == 'target_interface') == 'NEEDS_INPUT'


def test_source_only_draft_is_repeatable_serializable_and_keeps_options_empty():
    config = FGConfig(interfaces=[FGInterface(name='port1', type='physical', ip='192.0.2.1 255.255.255.0'),
                                 FGInterface(name='vlan10', interface='port1', vlanid=10)],
                      addresses=[FGAddress(name='net', subnet='192.0.2.0 255.255.255.0')])
    original = deepcopy(config)
    values = {make_decision_key('root', 'vdom', 'root', 'vsys'): 'vsys1',
              make_decision_key('root', 'interface', 'port1', 'target_interface'): 'ethernet1/1'}
    result, decisions = draft(config, values)
    again, _ = draft(config, values)
    assert result.to_dict() == again.to_dict()
    assert config == original
    assert not decisions.to_options().vdoms and not decisions.to_options().interfaces
    assert not result.to_dict()['destination_verified']
    assert any(row.proposed_value == 'ethernet1/1.10' for row in result.decisions)
    assert {row['family'] for row in result.configuration} >= {'interface', 'zone', 'address'}
    assert all(row.operation != 'REUSE' for row in result.decisions)
    assert result.to_dict()['digest'] != draft(config, {**values,
        make_decision_key('root', 'interface', 'port1', 'target_interface'): 'ethernet1/2'})[0].to_dict()['digest']


@pytest.mark.parametrize('version', [1, 2, 3])
def test_old_documents_do_not_gain_creation_permissions(version):
    config = FGConfig(addresses=[FGAddress(name='a', subnet='192.0.2.1 255.255.255.255')])
    _, pending = draft(config)
    confirmed = PANMigrationDecisionSet(tuple(replace(row, value='vsys1',
        review_state=PANDecisionReviewState.CONFIRMED, approved_operation='CREATE',
        approval_context={'source_digest': 'source'}) for row in pending.decisions))
    document = build_decision_document('source', confirmed)
    assert document['format_version'] == 4
    assert load_decision_document(document, 'source') == confirmed
    document['format_version'] = version
    loaded = load_decision_document(document, 'source')
    assert all(row.approved_operation is None and row.approval_context is None for row in loaded.decisions)
    assert loaded.to_options().vdoms['root'].vsys == 'vsys1'


def test_explicit_source_zone_mapping_propagates_without_inventing_source_membership():
    config = FGConfig(interfaces=[FGInterface(name='port1', type='physical')],
                      zones=[FGZone(name='inside', members=['port1'])])
    values = {make_decision_key('root', 'vdom', 'root', 'vsys'): 'vsys1',
              make_decision_key('root', 'interface', 'port1', 'target_interface'): 'ethernet1/1',
              make_decision_key('root', 'zone', 'inside', 'target_zone'): 'trust'}
    result, _ = draft(config, values)
    member = next(row for row in result.decisions if row.source_kind == 'interface' and row.target_field == 'target_zone')
    assert member.proposed_value == 'trust'
    assert make_decision_key('root', 'zone', 'inside', 'target_zone') in member.dependencies
    assert any(row['family'] == 'zone' and row['target_name'] == 'trust' for row in result.configuration)
    assert config.zones[0].members == ['port1']


def test_whole_draft_contested_ports_and_multi_vdom_identity():
    config = FGConfig(interfaces=[FGInterface(name='port', vdom=name, type='physical') for name in ('a', 'b')])
    values = {make_decision_key(vdom, 'vdom', vdom, 'vsys'): f'vsys{index}'
              for index, vdom in enumerate(('a', 'b'), 1)}
    values.update({make_decision_key(vdom, 'interface', 'port', 'target_interface'): 'ethernet1/1'
                   for vdom in ('a', 'b')})
    result, decisions = draft(config, values)
    ports = [row for row in result.decisions if row.target_field == 'target_interface']
    assert len(ports) == 2 and len({row.decision_key for row in ports}) == 2
    assert all(row.status == 'CONFLICT' for row in ports)
    with pytest.raises(ValueError):
        approve_draft(decisions, result, [row.decision_key for row in ports])


def test_dependency_index_preserves_backward_edges_cycles_order_and_vdom_isolation():
    from fwmigrate.conversion.fortigate_to_palo_alto.models import PANMigrationPlan
    from fwmigrate.conversion.fortigate_to_palo_alto.plan_dependencies import build_plan_dependency_index, item_key

    def item(kind, name, target, vdom='root', **fields):
        return SimpleNamespace(source_object_type=kind, source_kind=kind, source_name=name,
            source_vdom=vdom, source_policy_id=None, target_vsys='vsys1' if vdom == 'root' else 'vsys2',
            target_name=target, **fields)

    child = item('interface', 'vlan10', 'ethernet1/1.10', parent='ethernet1/1')
    branch = item('interface', 'port1', 'ethernet1/1', vdom='branch')
    parent = item('interface', 'port1', 'ethernet1/1', parent='ethernet1/1.20')
    grandchild = item('interface', 'vlan20', 'ethernet1/1.20', parent='ethernet1/1.10')
    zone = item('zone', 'trust', 'trust', interfaces=('ethernet1/1.20',))
    rule = item('security_rule', 'allow', 'allow', sources=(), destinations=(), services=(),
                from_zones=('trust',), to_zones=(), schedule=None, disabled=False)
    plan = PANMigrationPlan(interfaces=(child, branch, parent, grandchild), zones=(zone,), security_rules=(rule,))
    decision = SimpleNamespace(key='root-port', source_vdom='root', source_kind='interface',
                               source_name='port1', target_field='target_interface', value='ethernet1/1')
    index = build_plan_dependency_index(plan, SimpleNamespace(decisions=(decision,)))
    expected = tuple(item_key(row) for row in (parent, child, grandchild, zone, rule))
    assert index.item_keys_by_decision[decision.key] == expected
    assert index.decision_keys_by_item[item_key(branch)] == ()
    assert all(index.decision_keys_by_item[key] == (decision.key,) for key in expected)
    assert index.dependents_by_item[item_key(grandchild)] == (item_key(parent), item_key(zone))


def test_populated_target_rulebase_placement_blocker_is_visible_in_draft():
    from fwmigrate.vendors.fortigate.model.policy import FGPolicy
    from fwmigrate.vendors.palo_alto.native import build_derived_views
    from fwmigrate.vendors.palo_alto.source_builder import build_panos_config

    config = FGConfig(policies=[FGPolicy(policy_id=1, name="new", srcintf=["lan"], dstintf=["wan"],
        srcaddr=["all"], dstaddr=["all"], service=["ALL"], schedule="always", action="accept")])
    pan_config = build_panos_config("""<config><devices><entry name='dev'><vsys><entry name='vsys1'>
      <rulebase><security><rules><entry name='existing'/></rules></security></rulebase>
    </entry></vsys></entry></devices></config>""")
    target = SimpleNamespace(config=pan_config, derived=build_derived_views(pan_config))
    views = derived()
    state = build_review_state(config, views, "source", include_configuration=True)
    result = build_deterministic_draft(config, views, state["decisions"], source_digest="source",
        target=target, target_device="dev", reference_role="DESTINATION")

    assert any(item["code"] == "TARGET_RULE_PLACEMENT_UNVERIFIED" for item in result.findings)
    planned = next(item for item in result.configuration if item["family"] == "security_rule")
    assert "TARGET_RULE_PLACEMENT_UNVERIFIED" in planned["blocking_reasons"]
