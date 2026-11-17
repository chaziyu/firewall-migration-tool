from types import SimpleNamespace
import pytest
from fwmigrate.conversion.fortigate_to_palo_alto.automation import run_automation_until_stable
from fwmigrate.conversion.fortigate_to_palo_alto.decisions import PANDecisionMode, PANDecisionReviewState, PANMigrationDecision, PANMigrationDecisionSet, make_decision_key
from fwmigrate.conversion.fortigate_to_palo_alto.design import PANDecisionDependency, PANDecisionGraph, resolve_design_session_until_stable
from fwmigrate.conversion.fortigate_to_palo_alto.design.graph import build_decision_graph
from copy import deepcopy
from dataclasses import replace
from fwmigrate.conversion.fortigate_to_palo_alto.application.decision_documents import build_decision_document, load_decision_document
from fwmigrate.conversion.fortigate_to_palo_alto.application.review import build_review_state
from fwmigrate.conversion.fortigate_to_palo_alto.design.deterministic import build_deterministic_draft, approve_draft
from fwmigrate.vendors.fortigate.model.source import FGConfig
from fwmigrate.vendors.fortigate.model.interface import FGInterface
from fwmigrate.vendors.fortigate.model.zone import FGZone
from fwmigrate.vendors.fortigate.model.address import FGAddress
from fwmigrate.conversion.fortigate_to_palo_alto.design.draft import draft_issues
from fwmigrate.conversion.fortigate_to_palo_alto.review.review_evidence import build_review_evidence
from fwmigrate.vendors.fortigate.derived import build_derived_views
from fwmigrate.vendors.fortigate.model.policy import FGPolicy
from fwmigrate.vendors.fortigate.model.route_static import FGStaticRoute
from fwmigrate.conversion.fortigate_to_palo_alto.auto_decisions import classify_auto_decisions
from fwmigrate.conversion.fortigate_to_palo_alto.pipeline import run_migration_pipeline
from fwmigrate.conversion.fortigate_to_palo_alto.review.review_suggestions import apply_review_suggestions
from fwmigrate.conversion.fortigate_to_palo_alto.target.target_suggestions import discover_target_candidates
from fwmigrate.vendors.palo_alto.relationships.topology import PANInterfaceTopologyEntry
from fwmigrate.vendors.palo_alto.source_model import PANScope, pan_scope_identity
from fwmigrate.conversion.fortigate_to_palo_alto.review.review_workflow import build_review_workflow
import json
from fwmigrate.conversion.fortigate_to_palo_alto import build_recommendations
from fwmigrate.conversion.fortigate_to_palo_alto.interface_candidates import viable_candidate
from fwmigrate.vendors.fortigate.model.dhcp import FGDHCPIPRange, FGDHCPReservedAddress, FGDHCPServer
from fwmigrate.vendors.fortigate.model.external_resource import FGExternalResource
from fwmigrate.vendors.fortigate.model.ips import FGIPSSensor, FGIPSSensorEntry
from fwmigrate.vendors.fortigate.model.sdwan import FGSDWAN, FGSDWANHealthCheck, FGSDWANMember
from fwmigrate.vendors.fortigate.model.user import FGLocalUser
from fwmigrate.vendors.fortigate.model.vpn import FGIPsecPhase1, FGIPsecPhase2
from fwmigrate.vendors.fortigate.model.vpn_ssl import FGSSLVPNPortal
from fwmigrate.conversion.fortigate_to_palo_alto.models import PANMigrationPlan, PANMigrationStatus, PlannedSecurityRule
from fwmigrate.conversion.fortigate_to_palo_alto.recommendations.support_guidance import build_support_guidance
from fwmigrate.conversion.fortigate_to_palo_alto.validation import validate_plan

# --- test_design_session.py ---
def _decision(kind, name, field, *, mode=PANDecisionMode.REQUIRED, value=None, state=PANDecisionReviewState.PENDING):
    return PANMigrationDecision(
        source_vdom="root",
        source_kind=kind,
        source_name=name,
        target_field=field,
        value=value,
        mode=mode,
        review_state=state,
    )


def test_graph_orders_vdom_interface_and_zone_decisions_and_finds_ready_wave():
    config = SimpleNamespace(
        interfaces=[SimpleNamespace(vdom="root", name="port1", interface=None)],
        zones=[SimpleNamespace(vdom="root", name="inside", members=["port1"])],
    )
    decisions = PANMigrationDecisionSet((
        _decision("vdom", "root", "vsys"),
        _decision("vdom", "root", "virtual_router"),
        _decision("interface", "port1", "target_interface"),
        _decision("interface", "port1", "target_zone"),
        _decision("zone", "inside", "target_zone"),
    ))
    requirements = {"vdoms": [{"source_vdom": "root", "requires": ["vsys", "virtual_router"]}]}

    graph = build_decision_graph(config, SimpleNamespace(), decisions, requirements)
    order = graph.topological_order()
    assert order.index(make_decision_key("root", "vdom", "root", "vsys")) < order.index(
        make_decision_key("root", "interface", "port1", "target_interface")
    )
    assert set(graph.ready_decision_keys(decisions)) == {
        make_decision_key("root", "vdom", "root", "vsys"),
        make_decision_key("root", "vdom", "root", "virtual_router"),
    }


def test_graph_rejects_cycles_and_unknown_dependencies():
    with pytest.raises(ValueError, match="cycle"):
        PANDecisionGraph((
            PANDecisionDependency("a", ("b",)),
            PANDecisionDependency("b", ("a",)),
        ))
    with pytest.raises(ValueError, match="existing decisions"):
        PANDecisionGraph((PANDecisionDependency("a", ("missing",)),))


def test_design_resolver_preserves_legacy_options_and_source():
    config = SimpleNamespace(interfaces=[], zones=[])
    derived = SimpleNamespace()
    decisions = PANMigrationDecisionSet((
        _decision("vdom", "root", "vsys", mode=PANDecisionMode.REQUIRED,
                  value="vsys1", state=PANDecisionReviewState.CONFIRMED),
        _decision("zone", "inside", "target_zone", mode=PANDecisionMode.UNSUPPORTED),
    ))
    original = decisions.to_dict()
    previous = run_automation_until_stable(config, derived, decisions)

    session = resolve_design_session_until_stable(
        config,
        derived,
        decisions,
        requirements={"vdoms": [], "interfaces": []},
    )

    assert session.decisions.to_options() == previous.decisions.to_options()
    assert session.decisions.to_dict() == original
    assert session.resolved == (decisions.decisions[0].key,)
    assert session.unsupported == (decisions.decisions[1].key,)
    assert session.stable

# --- test_deterministic_draft.py ---
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


def test_bounded_port_pool_preserves_numbered_ports_before_named_ports():
    config = FGConfig(interfaces=[FGInterface(name=f'port{number}', type='physical') for number in range(1, 14)]
        + [FGInterface(name='wan', type='physical', ip='192.0.2.1/24')])
    result, _ = draft(config, workflow_mode='OFFLINE_EXPORT', conversion_settings={'target_model': 'PA-820'})
    assert next(row for row in result.decisions if row.source_name == 'wan' and row.target_field == 'target_interface').proposed_value is None
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


def test_offline_numbered_port_collisions_require_explicit_allocations():
    config = FGConfig(interfaces=[FGInterface(name=name, type='physical') for name in ('port10', 'port2', 'port1')])
    original = deepcopy(config)
    key = make_decision_key('root', 'interface', 'port1', 'target_interface')
    result, decisions = draft(config, {key: 'ethernet1/2'}, workflow_mode='OFFLINE_EXPORT')
    ports = {row.source_name: row for row in result.decisions if row.target_field == 'target_interface'}
    assert {name: row.proposed_value for name, row in ports.items()} == {
        'port1': 'ethernet1/2', 'port2': None, 'port10': 'ethernet1/10'}
    assert all(not row.approved for row in ports.values())
    assert ports['port2'].status == 'NEEDS_INPUT'
    assert 'Choose a distinct target port' in ports['port2'].evidence[0]
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


def test_numbered_ports_reserve_gaps_before_named_ports_and_preserve_vlan_tags():
    config = FGConfig(interfaces=[FGInterface(name=name, type='physical') for name in ('wan', 'port10', 'dmz', 'port2')]
        + [FGInterface(name='vlan20', interface='port10', vlanid=20)])
    original = deepcopy(config)
    result, _ = draft(config, workflow_mode='OFFLINE_EXPORT')
    ports = {row.source_name: row.proposed_value for row in result.decisions if row.target_field == 'target_interface'}
    assert ports == {'wan': 'ethernet1/3', 'port10': 'ethernet1/10', 'dmz': 'ethernet1/1', 'port2': 'ethernet1/2', 'vlan20': 'ethernet1/10.20'}
    assert config == original
    again, _ = draft(FGConfig(interfaces=list(reversed(config.interfaces))), workflow_mode='OFFLINE_EXPORT')
    assert ports == {row.source_name: row.proposed_value for row in again.decisions if row.target_field == 'target_interface'}


def test_duplicate_numbered_ports_across_vdoms_stay_unresolved_until_explicit_choice():
    config = FGConfig(interfaces=[FGInterface(name='port2', vdom=vdom, type='physical') for vdom in ('blue', 'root')]
        + [FGInterface(name='dmz', type='physical')])
    result, _ = draft(config, workflow_mode='OFFLINE_EXPORT')
    ports = [row for row in result.decisions if row.target_field == 'target_interface']
    assert all(row.status == 'NEEDS_INPUT' and row.proposed_value is None for row in ports if row.source_name == 'port2')
    assert next(row for row in ports if row.source_name == 'dmz').proposed_value == 'ethernet1/1'
    override = {make_decision_key('blue', 'interface', 'port2', 'target_interface'): 'ethernet1/5'}
    resolved, _ = draft(config, override, workflow_mode='OFFLINE_EXPORT')
    assert {row.source_vdom: row.proposed_value for row in resolved.decisions if row.source_name == 'port2' and row.target_field == 'target_interface'} == {'blue': 'ethernet1/5', 'root': 'ethernet1/2'}


def test_remaining_bounded_ports_prioritize_used_named_interfaces():
    config = FGConfig(interfaces=[FGInterface(name=f'port{number}', type='physical') for number in range(1, 12)]
        + [FGInterface(name='a-unused', type='physical'), FGInterface(name='z-used', type='physical', ip='192.0.2.1/24')])
    result, _ = draft(config, workflow_mode='OFFLINE_EXPORT', conversion_settings={'target_model': 'PA-820'})
    ports = {row.source_name: row.proposed_value for row in result.decisions if row.target_field == 'target_interface'}
    assert ports['z-used'] == 'ethernet1/12'
    assert ports['a-unused'] is None

# --- test_review_evidence.py ---
def test_review_evidence_keeps_source_and_derived_facts_separate_and_safe():
    config = FGConfig(
        interfaces=[FGInterface(name="port1", type="physical", explicit_fields={"type"},
                                raw_extra={"password": "never-export", "psksecret": "never-export"})],
        zones=[FGZone(name="inside", members=["port1"])],
        policies=[FGPolicy(policy_id=1, srcintf=["port1"], dstintf=["port1"])],
        static_routes=[FGStaticRoute(seq_num=1, device="port1")],
    )
    result = build_review_evidence(config, build_derived_views(config))[("root", "port1")]
    assert result["source_explicit"] == {"type": "physical", "zone_membership": ["inside"]}
    assert result["derived_relationships"]["policy_source_reference_count"] == 1
    assert result["derived_relationships"]["policy_destination_reference_count"] == 1
    assert result["derived_relationships"]["static_route_usage"] == 1
    assert "never-export" not in repr(result)
    assert "psksecret" not in repr(result).casefold()

# --- test_review_suggestions.py ---
def _target(names=("ethernet1/1",), *, zones=("trust",), vsys=("vsys1",)):
    scope = PANScope(kind="device", name="dev", device_name="dev")
    items = [SimpleNamespace(name=name, scope=scope, interface_family="ethernet", tag=None,
        parent=None, ipv4_addresses=["192.0.2.1/24"], comment=None) for name in names]
    return SimpleNamespace(config=SimpleNamespace(interfaces=items, interface_units=[], zones=[],
        virtual_routers=[], scopes=[]), derived=SimpleNamespace(interface_topology=[
            PANInterfaceTopologyEntry(item.name, pan_scope_identity(scope), zones=zones,
                imported_vsys=vsys, virtual_routers=("vr-main",)) for item in items]))


def test_verified_interface_prefills_without_becoming_options_or_commands():
    config = FGConfig(interfaces=[FGInterface(name="lan", type="physical", ip="192.0.2.1/24")],
        static_routes=[FGStaticRoute(seq_num=1, device="lan", dst="0.0.0.0/0", gateway="192.0.2.254")])
    target = _target()
    state = build_review_state(config, build_derived_views(config), "source", target=target, target_device="dev")
    decisions = state["decisions"]
    interface = next(item for item in decisions.decisions if item.target_field == "target_interface")
    assert interface.suggested_value == "ethernet1/1" and interface.evidence_source == "TARGET"
    assert all(item.value is None and item.review_state is PANDecisionReviewState.PENDING for item in decisions.decisions)
    assert decisions.to_options().interfaces == decisions.to_options().vdoms == {}
    assert state["design_session"].decisions == decisions
    result = run_migration_pipeline(config, build_derived_views(config), decisions=decisions)
    assert result.rendered.commands == ()
    assert all(group["queue"] == "READY_TO_CONFIRM" for group in state["review_workflow"]["review_groups"])


def test_confirmed_source_zone_refresh_prefills_member_with_derived_provenance():
    config = FGConfig(interfaces=[FGInterface(name="lan")],
        zones=[FGZone(name="USERS", members=["lan"], explicit_fields={"members"})],
        policies=[FGPolicy(policy_id=1, srcintf=["lan"]), FGPolicy(policy_id=2, srcintf=["USERS"])])
    first = build_review_state(config, build_derived_views(config), "source")
    previous = PANMigrationDecisionSet(tuple(item.confirm("TRUST") if item.source_kind == "zone" else item
        for item in first["decisions"].decisions))
    state = build_review_state(config, build_derived_views(config), "source",
        previous_document=build_decision_document("source", previous))
    member = next(item for item in state["decisions"].decisions if item.source_kind == "interface" and item.target_field == "target_zone")
    assert member.suggested_value == "TRUST" and member.value is None
    assert member.evidence_source == "DERIVED" and member.evidence_target_digest is None
    assert member.review_state is PANDecisionReviewState.PENDING
    assert state["decisions"].to_options().interfaces == {}


@pytest.mark.parametrize("names", [("ethernet1/1", "ethernet1/2"), ("ethernet1/1", "ethernet1/1")])
def test_ambiguous_interfaces_have_candidates_without_prefill(names):
    config = FGConfig(interfaces=[FGInterface(name="lan", ip="192.0.2.1/24")])
    decision = PANMigrationDecision("root", "interface", "lan", "target_interface")
    decisions = PANMigrationDecisionSet((decision,))
    target = _target(names)
    results = classify_auto_decisions(config, None, decisions, target, "dev")
    updated = apply_review_suggestions(decisions, results,
        candidates=discover_target_candidates(config, decisions, target, "dev"))
    assert updated.decisions[0].suggested_value is None


def test_confirmed_and_unsupported_decisions_survive_suggestion_recomputation():
    pending = PANMigrationDecision("root", "interface", "lan", "target_zone")
    decisions = PANMigrationDecisionSet((pending.confirm("chosen"), replace(pending,
        source_name="other", mode=PANDecisionMode.UNSUPPORTED)))
    results = {item.key: {"status": "DERIVED", "value": "trust", "reason": "new evidence"} for item in decisions.decisions}
    assert apply_review_suggestions(decisions, results) == decisions


def test_target_zone_derivation_is_pending_and_target_backed():
    config = FGConfig(interfaces=[FGInterface(name="lan", ip="192.0.2.1/24")])
    decision = PANMigrationDecision("root", "interface", "lan", "target_zone")
    decisions = PANMigrationDecisionSet((decision,))
    results = classify_auto_decisions(config, None, decisions, _target(), "dev")
    updated = apply_review_suggestions(decisions, results).decisions[0]
    assert updated.suggested_value == "trust" and updated.evidence_source == "TARGET"
    assert updated.evidence_type == "REVIEW_DERIVED_SUGGESTION" and updated.value is None


def test_confirmed_parent_refresh_unlocks_vlan_child_without_confirmation():
    config = FGConfig(interfaces=[FGInterface(name="lan", type="physical", ip="192.0.2.1/24"),
        FGInterface(name="vlan100", type="vlan", interface="lan", vlanid=100)],
        static_routes=[FGStaticRoute(seq_num=1, device="vlan100", dst="0.0.0.0/0")])
    target = _target(zones=())
    child = SimpleNamespace(name="ethernet1/1.100", scope=target.config.interfaces[0].scope,
        interface_family="ethernet", tag="100", parent="ethernet1/1", ipv4_addresses=[], comment=None)
    target.config.interface_units.append(child)
    target.derived.interface_topology.append(PANInterfaceTopologyEntry(child.name,
        pan_scope_identity(child.scope), parent=child.parent, imported_vsys=("vsys1",), virtual_routers=("vr-main",)))
    first = build_review_state(config, build_derived_views(config), "source", target=target, target_device="dev")
    previous = PANMigrationDecisionSet(tuple(item.confirm("ethernet1/1")
        if item.source_name == "lan" and item.target_field == "target_interface" else item
        for item in first["decisions"].decisions))
    child_before = next(item for item in previous.decisions if item.source_name == "vlan100")
    assert child_before.suggested_value is None
    refreshed = build_review_state(config, build_derived_views(config), "source", target=target, target_device="dev",
        previous_document=build_decision_document("source", previous))
    child_after = next(item for item in refreshed["decisions"].decisions if item.key == child_before.key)
    assert child_after.suggested_value == child.name and child_after.value is None
    assert child_after.review_state is PANDecisionReviewState.PENDING


def test_refresh_recomputes_pending_target_suggestions_and_removes_absent_evidence():
    config = FGConfig(interfaces=[FGInterface(name="lan", type="physical", ip="192.0.2.1/24")],
        static_routes=[FGStaticRoute(seq_num=1, device="lan", dst="0.0.0.0/0")])
    derived = build_derived_views(config)
    metadata = {"vendor": "palo_alto", "config_digest": "first", "device": "dev"}
    first = build_review_state(config, derived, "source", target=_target(), target_device="dev", target_metadata=metadata)
    document = build_decision_document("source", first["decisions"], metadata)
    refreshed = build_review_state(config, derived, "source", previous_document=document,
        target=_target(("ethernet1/2",)), target_device="dev", target_metadata={**metadata, "config_digest": "second"})
    interface = next(item for item in refreshed["decisions"].decisions if item.target_field == "target_interface")
    assert interface.suggested_value == "ethernet1/2" and interface.review_state is PANDecisionReviewState.PENDING
    assert refreshed["target_evidence_changed"]
    removed = build_review_state(config, derived, "source", previous_document=document)
    assert all(item.suggested_value is None and item.value is None for item in removed["decisions"].decisions)


def test_confirmed_review_mappings_produce_the_same_rendering_as_explicit_options():
    config = FGConfig(interfaces=[FGInterface(name="lan", type="physical", ip="192.0.2.1/24")],
        static_routes=[FGStaticRoute(seq_num=1, device="lan", dst="0.0.0.0/0", gateway="192.0.2.254")])
    derived = build_derived_views(config)
    state = build_review_state(config, derived, "source", target=_target(), target_device="dev")
    confirmed = PANMigrationDecisionSet(tuple(item.confirm(item.suggested_value) for item in state["decisions"].decisions))
    reviewed = run_migration_pipeline(config, derived, decisions=confirmed)
    explicit = run_migration_pipeline(config, derived, options=confirmed.to_options())
    assert reviewed.rendered.commands and reviewed.rendered.commands == explicit.rendered.commands
    assert reviewed.plan == explicit.plan

# --- test_review_workflow.py ---
def test_conflicting_groups_show_all_owners_and_reserved_candidates_are_not_actionable():
    from fwmigrate.conversion.fortigate_to_palo_alto.application.review import decision_evidence
    from fwmigrate.conversion.fortigate_to_palo_alto.target.target_validation import validate_against_target

    config = FGConfig()
    decisions = PANMigrationDecisionSet(tuple(PANMigrationDecision(vdom, "interface", "port1", "target_interface",
        value="ethernet1/1", review_state=PANDecisionReviewState.CONFIRMED) for vdom in ("root", "branch")))
    findings = validate_against_target(config, decisions, None, None)
    workflow = build_review_workflow(config, decisions, candidates={}, context={},
        decision_evidence=decision_evidence(decisions, findings), target_warnings={}, target_findings=findings)
    assert all(group['queue'] == 'CONFLICT' and len(group['conflicts'][0]['evidence']) == 2
               and 'root / port1' in group['next_action'] and 'branch / port1' in group['next_action']
               for group in workflow['review_groups'])
    pending = PANMigrationDecision("root", "interface", "port2", "target_interface",
        suggested_value="ethernet1/1", mode=PANDecisionMode.SUGGESTED)
    workflow = build_review_workflow(config, PANMigrationDecisionSet((pending,)), context={}, decision_evidence={}, target_warnings={},
        candidates={pending.key: [{'value': 'ethernet1/1', 'class': 'STRONG', 'available': False}]})
    assert workflow['review_groups'][0]['queue'] == 'NEEDS_INPUT'


def test_review_workflow_groups_decisions_classifies_queues_and_orders_vdom_first():
    config = FGConfig(interfaces=[FGInterface(name="lan", type="vlan", interface="agg1")])
    decisions = PANMigrationDecisionSet((
        PANMigrationDecision("root", "interface", "lan", "target_interface"),
        PANMigrationDecision("root", "interface", "lan", "target_zone", suggested_value="TRUST", mode=PANDecisionMode.SUGGESTED),
        PANMigrationDecision("root", "interface", "agg1", "target_interface", suggested_value="ae1", mode=PANDecisionMode.SUGGESTED),
        PANMigrationDecision("root", "vdom", "root", "vsys"),
        PANMigrationDecision("root", "interface", "auto0", "target_interface", value="ethernet1/1", mode=PANDecisionMode.AUTO),
    ))
    target_key = decisions.decisions[0].key
    workflow = build_review_workflow(config, decisions, candidates={target_key: [{"value": "ethernet1/2", "class": "POSSIBLE"}]},
        context={"root": {"source_type": "vlan"}}, decision_evidence={}, target_warnings={})
    groups = workflow["review_groups"]
    assert groups[0]["source_kind"] == "vdom"
    lan = next(item for item in groups if item["source_name"] == "lan")
    assert len(lan["decision_keys"]) == 2
    assert lan["queue"] == "CHOOSE_CANDIDATE"
    assert workflow["review_summary"] == {
        "auto_resolved": 1, "ready_to_confirm": 2, "choose_candidate": 1,
        "needs_input": 1, "conflicts": 0, "confirmed": 0,
    }


def test_review_workflow_groups_parent_choice_with_affected_vlan_children():
    config = FGConfig(interfaces=[FGInterface(name="agg1", type="aggregate"),
        FGInterface(name="vlan100", type="vlan", interface="agg1", vlanid=100),
        FGInterface(name="vlan200", type="vlan", interface="agg1", vlanid=200)])
    decision = PANMigrationDecision("root", "interface", "agg1", "target_interface")
    workflow = build_review_workflow(config, PANMigrationDecisionSet((decision,)),
        candidates={decision.key: [{"value": "ae1", "class": "STRONG"}]},
        context={}, decision_evidence={}, target_warnings={})
    assert workflow["architecture_questions"] == [{"type": "AGGREGATE_MAPPING", "source_vdom": "root",
        "source_name": "agg1", "decision_key": decision.key, "candidates": ["ae1"],
        "affected_count": 2, "affected": ["vlan100", "vlan200"]}]

# --- test_recommendations.py ---
def test_recommendations_are_immutable_source_safe_and_feature_scoped():
    config = FGConfig(
        dhcp_servers=[FGDHCPServer(id=1, interface="port3", default_gateway="10.0.0.1", ip_ranges=[FGDHCPIPRange(start_ip="10.0.0.10", end_ip="10.0.0.20")], reserved_addresses=[FGDHCPReservedAddress(ip="10.0.0.11", mac="aa:bb")])],
        local_users=[FGLocalUser(name="alice", password_configured=True)],
        ipsec_phase1=[FGIPsecPhase1(name="vpn-a", interface="port1", psk_configured=True, proposal=["aes256-sha256"])],
        ipsec_phase2=[FGIPsecPhase2(name="vpn-a-p2", phase1name="vpn-a", src_start_ip="10.1.0.1", src_end_ip="10.1.0.10", dst_subnet="10.2.0.0/24")],
        ips_sensors=[FGIPSSensor(name="ips-a", entries=[FGIPSSensorEntry(cve=["CVE-1"], action="drop")])],
        sdwans=[FGSDWAN(members=[FGSDWANMember(seq_num=1, interface="port1")], health_checks=[FGSDWANHealthCheck(name="hc", server="198.51.100.1")])],
        ssl_vpn_portals=[FGSSLVPNPortal(name="employees", split_tunneling="enable")],
        external_resources=[FGExternalResource(name="feed", resource="https://example.test/feed", type="category", refresh_rate=60)],
    )
    before = deepcopy(config.model_dump())
    decisions = PANMigrationDecisionSet((PANMigrationDecision("root", "interface", "port3", "target_interface"),))
    recommendations = build_recommendations(config, SimpleNamespace(), decisions)

    assert isinstance(recommendations, tuple)
    assert {item.family for item in recommendations} == {"VPN", "Users/Admin", "Security", "SD-WAN", "SSL VPN", "External Resource"}
    serialized = json.dumps([item.to_dict() for item in recommendations])
    assert "aa:bb" not in serialized
    assert "CVE-1" not in serialized
    assert "https://example.test/feed" in serialized
    assert config.model_dump() == before
    assert all("confirmed" not in item.to_dict() and "planner_value" not in item.to_dict() for item in recommendations)


def test_target_candidate_evidence_requires_strong_noncontradicting_facts():
    source = SimpleNamespace(name="vlan100", alias="Users", description=None, type="vlan", vlanid=100, ip="10.0.0.1/24")
    target = SimpleNamespace(name="ethernet1/1.100", comment="Users", interface_family="vlan", tag="100", parent="ethernet1/1", ipv4_addresses=["10.0.0.2/24"])
    topology = SimpleNamespace(parent="ethernet1/1")
    valid, strong, supporting, contradictions = viable_candidate(source, target, topology, "ethernet1/1")
    assert valid
    assert "same subnet + VLAN + confirmed parent" in strong
    assert "VLAN 100" in supporting
    assert not contradictions

    mismatch = SimpleNamespace(**{**target.__dict__, "tag": "200"})
    assert viable_candidate(source, mismatch, topology, "ethernet1/1")[0] is False

# --- test_support_guidance.py ---
def test_indexed_guidance_preserves_first_source_match_and_duplicate_message_handling():
    from fwmigrate.conversion.fortigate_to_palo_alto.models import PlannedAddress, MigrationIssue, MigrationSourceRef
    first = PlannedAddress(source_vdom='root', source_kind='address', source_name='same')
    other = PlannedSecurityRule(source_vdom='root', source_kind='policy', source_name='same')
    blue = PlannedAddress(source_vdom='blue', source_kind='address', source_name='same')
    plan = PANMigrationPlan(addresses=(first, blue), security_rules=(other,))
    message = "missing target interface mapping for 'wan'"
    validation = SimpleNamespace(issues=(
        MigrationIssue('missing_route_interface', message, source=MigrationSourceRef('root', 'policy', 'same')),
        MigrationIssue('planned_item_warning', message, source=MigrationSourceRef('blue', 'address', 'same'))))
    result = build_support_guidance(plan, validation, PANMigrationDecisionSet())
    assert len(result) == 1
    assert (result[0].source_vdom, result[0].source_kind, result[0].source_name) == ('root', 'address', 'same')
    assert result[0].why == message


def test_shared_source_correction_groups_dependents_but_preserves_scope():
    from fwmigrate.conversion.fortigate_to_palo_alto.recommendations.support_guidance import _warning_guidance, shared_action_groups
    warning = "Outgoing interface 'wan1' has an explicit ip value that could not be parsed safely"
    rows = []
    for vdom, name in (('root', 'one'), ('root', 'two'), ('blue', 'one')):
        item = PlannedSecurityRule(source_vdom=vdom, source_kind='source_nat', source_name=name)
        cause = _warning_guidance(item, warning, ()).to_dict()
        assert cause['automation_category'] == 'SOURCE_CORRECTION'
        rows.append({'status': 'UNSUPPORTED', 'source_vdom': vdom, 'group_key': f'{vdom}/{name}', 'causes': [cause, cause]})
    groups = shared_action_groups(rows)
    assert len(groups) == 2
    assert groups[0]['member_keys'] == ['root/one', 'root/two']
    assert groups[1]['member_keys'] == ['blue/one']


def test_missing_zone_guidance_links_existing_decision():
    item = PlannedSecurityRule(source_vdom="root", source_kind="policy", source_name="42",
                               status=PANMigrationStatus.MANUAL_REVIEW,
                               warnings=("missing target zone mapping for 'wan'",))
    plan = PANMigrationPlan(security_rules=(item,))
    validation = validate_plan(plan)
    decisions = PANMigrationDecisionSet.from_dict({"decisions": [{
        "source_vdom": "root", "source_kind": "interface", "source_name": "wan",
        "target_field": "target_zone", "mode": "REQUIRED", "review_state": "PENDING",
    }]})
    guidance = build_support_guidance(plan, validation, decisions)
    assert guidance[0].resolution_type == "MISSING_MAPPING"
    assert guidance[0].decision_key == decisions.decisions[0].key


def test_vip_load_balancing_guidance_requires_manual_target_design():
    item = PlannedSecurityRule(source_vdom="root", source_kind="policy", source_name="42",
                               status=PANMigrationStatus.MANUAL_REVIEW,
                               warnings=("VIP load-balancing semantics unsupported",))
    guidance = build_support_guidance(PANMigrationPlan(security_rules=(item,)), None,
                                      PANMigrationDecisionSet())
    assert guidance[0].resolution_type == "MANUAL_TARGET_DESIGN"


def test_virtual_router_guidance_links_vdom_decision():
    item = SimpleNamespace(source_vdom="root", source_kind="route", source_name="default",
                           status=PANMigrationStatus.MANUAL_REVIEW,
                           warnings=("missing target virtual-router mapping",))
    decisions = PANMigrationDecisionSet.from_dict({"decisions": [{
        "source_vdom": "root", "source_kind": "vdom", "source_name": "root",
        "target_field": "virtual_router", "mode": "REQUIRED", "review_state": "PENDING",
    }]})
    guidance = build_support_guidance(PANMigrationPlan(static_routes=(item,)), None, decisions)
    assert guidance[0].decision_key == decisions.decisions[0].key


def test_converter_feature_guidance_has_no_decision_key():
    item = SimpleNamespace(source_vdom="root", source_kind="service", source_name="dns",
                           status=PANMigrationStatus.UNSUPPORTED,
                           warnings=("Internet Service matching is unsupported",))
    guidance = build_support_guidance(PANMigrationPlan(services=(item,)), None,
                                      PANMigrationDecisionSet())
    assert guidance[0].resolution_type == "CONVERTER_FEATURE"
    assert guidance[0].decision_key is None


@pytest.mark.parametrize(("warning", "code", "resolution"), [
    ("missing target interface mapping for 'wan'", "MISSING_TARGET_INTERFACE", "MISSING_MAPPING"),
    ("multiple possible egress interfaces", "AMBIGUOUS_NAT_EGRESS", "AMBIGUOUS_SOURCE"),
    ("schedule group is unsupported", "SCHEDULE_GROUP_UNSUPPORTED", "CONVERTER_FEATURE"),
    ("service negation is unsupported", "SERVICE_NEGATION_UNSUPPORTED", "CONVERTER_FEATURE"),
    ("unsupported service protocol", "SERVICE_UNSUPPORTED", "CONVERTER_FEATURE"),
    ("Internet Service matching is unsupported", "INTERNET_SERVICE_UNSUPPORTED", "CONVERTER_FEATURE"),
    ("user and group matching is unsupported", "USER_GROUP_UNSUPPORTED", "MANUAL_TARGET_DESIGN"),
    ("inspection settings are unsupported", "INSPECTION_UNSUPPORTED", "MANUAL_TARGET_DESIGN"),
    ("unsupported source or dynamic routing", "ROUTE_SEMANTICS_UNSUPPORTED", "CONVERTER_FEATURE"),
    ("VIP requires explicit mapping", "VIP_MAPPING_REQUIRED", "MISSING_MAPPING"),
])
def test_guidance_classifies_remaining_supported_blockers(warning, code, resolution):
    item = SimpleNamespace(source_vdom="root", source_kind="policy", source_name="42",
                           status=PANMigrationStatus.MANUAL_REVIEW, warnings=(warning,))
    guidance = build_support_guidance(PANMigrationPlan(security_rules=(item,)), None,
                                      PANMigrationDecisionSet())
    assert guidance[0].code == code
    assert guidance[0].resolution_type == resolution
    assert guidance[0].decision_key is None
