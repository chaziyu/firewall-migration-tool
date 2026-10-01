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


def derived():
    return SimpleNamespace(services=SimpleNamespace(services=(), groups=()), nat=(),
                           topology=SimpleNamespace(interfaces=(), vpns=()))


def draft(config, overrides=None, **kwargs):
    views = derived()
    state = build_review_state(config, views, 'source', include_configuration=True)
    return build_deterministic_draft(config, views, state['decisions'], source_digest='source',
                                     overrides=overrides, **kwargs), state['decisions']


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
