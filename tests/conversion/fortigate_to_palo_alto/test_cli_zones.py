from fwmigrate.conversion.fortigate_to_palo_alto.models import (
    PANMigrationPlan, PANMigrationStatus, PlannedZone,
)
from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import PANSetRenderer
from dataclasses import replace
import pytest
from fwmigrate.conversion.fortigate_to_palo_alto import PANMigrationOptions
from fwmigrate.conversion.fortigate_to_palo_alto.planner import FortiGateToPaloAltoPlanner
from fwmigrate.conversion.fortigate_to_palo_alto.decisions import build_decision_set, PANDecisionReviewState, PANMigrationDecisionSet
from fwmigrate.conversion.fortigate_to_palo_alto.plan_dependencies import build_plan_dependency_index, item_key
from fwmigrate.vendors.fortigate.model.source import FGConfig
from fwmigrate.vendors.fortigate.model.interface import FGInterface
from fwmigrate.vendors.fortigate.model.zone import FGZone
from fwmigrate.vendors.fortigate.model.policy import FGPolicy
from fwmigrate.vendors.fortigate.derived import build_derived_views
from fwmigrate.conversion.fortigate_to_palo_alto.requirements import build_mapping_requirements


@pytest.mark.parametrize('named_second', [False, True])
@pytest.mark.parametrize('missing_member', [False, True])
def test_zone_consolidation_retains_members_decisions_and_blockers(named_second, missing_member):
    source = FGConfig(interfaces=[FGInterface(name=name, type='physical') for name in ('lan1', 'lan2')],
        zones=[FGZone(name='first', members=['lan1'])] + ([FGZone(name='second', members=['lan2'])] if named_second else []),
        policies=[FGPolicy(policy_id=1, srcintf=['first'], dstintf=['any'], srcaddr=['all'], dstaddr=['all'],
            service=['ALL'], action='accept', schedule='always')])
    original = source.model_dump()
    derived = build_derived_views(source)
    options = PANMigrationOptions(vdoms={'root': {'vsys': 'vsys1', 'virtual_router': 'vr'}},
        interfaces={'root': {'lan1': {'target_interface': 'ethernet1/1'},
            'lan2': {'target_interface': None if missing_member else 'ethernet1/2', 'target_zone': 'trust'}}},
        zones={'root': {'first': {'target_zone': 'trust'}, 'second': {'target_zone': 'trust'}}})
    plan = FortiGateToPaloAltoPlanner().plan(source, derived, options, include_configuration=True)
    assert len(plan.zones) == 1
    zone = plan.zones[0]
    assert {ref.source_name for ref in zone.source_contributors} == {'first', 'second' if named_second else 'lan2'}
    decisions = build_decision_set(source, derived, build_mapping_requirements(source, derived, include_configuration=True))
    index = build_plan_dependency_index(plan, decisions)
    for ref in zone.source_contributors:
        keys = [row.key for row in decisions.decisions if row.source_kind == ref.source_kind and row.source_name == ref.source_name]
        assert keys and all(item_key(zone) in index.item_keys_by_decision[key] for key in keys)
    artifact = PANSetRenderer().render(plan)
    assert zone.status is PANMigrationStatus.MANUAL_REVIEW
    assert not any(' zone trust ' in command or 'rulebase security' in command for command in artifact.commands)
    if not missing_member:
        assert zone.interfaces == ('ethernet1/1', 'ethernet1/2')
        assert any('intra-zone' in warning for warning in zone.warnings)
    assert source.model_dump() == original


def test_additive_zone_requires_every_contributor_approval():
    from fwmigrate.conversion.fortigate_to_palo_alto.models import MigrationSourceRef
    from fwmigrate.conversion.fortigate_to_palo_alto.decisions import PANMigrationDecision
    from fwmigrate.conversion.fortigate_to_palo_alto.target.target_plan_validation import assess_target_plan, PANRenderDisposition
    zone = PlannedZone(source_vdom='root', source_kind='zone', source_object_type='zone', source_name='first',
        target_vsys='vsys1', target_name='trust', status=PANMigrationStatus.SUPPORTED,
        source_contributors=tuple(MigrationSourceRef('root', 'zone', name) for name in ('first', 'second')))
    decisions = PANMigrationDecisionSet(tuple(PANMigrationDecision('root', 'zone', name, 'target_zone', value='trust',
        review_state=PANDecisionReviewState.CONFIRMED, approved_operation='CONFIGURE') for name in ('first', 'second')))
    plan = PANMigrationPlan(zones=(zone,))
    classification = ({'family': 'zone', 'source_vdom': 'root', 'source_kind': 'zone', 'source_name': 'first',
        'target_vsys': 'vsys1', 'target_name': 'trust', 'status': 'ADDITIVE'},)
    for approved, expected in ((decisions, PANRenderDisposition.CONFIGURE),
                              (replace(decisions, decisions=decisions.decisions[:1]), PANRenderDisposition.BLOCK)):
        dispositions, _ = assess_target_plan(plan, classification, (), approved, build_plan_dependency_index(plan, approved))
        assert dispositions[item_key(zone)] is expected


def test_zones_from_different_vdoms_are_not_consolidated():
    from fwmigrate.conversion.fortigate_to_palo_alto.planning.topology import plan_topology
    from fwmigrate.conversion.fortigate_to_palo_alto.validation import validate_plan
    source = FGConfig(zones=[FGZone(vdom=vdom, name='inside') for vdom in ('a', 'b')])
    options = PANMigrationOptions(vdoms={vdom: {'vsys': 'vsys1'} for vdom in ('a', 'b')},
        zones={vdom: {'inside': {'target_zone': 'trust'}} for vdom in ('a', 'b')})
    zones = plan_topology(source, build_derived_views(source), options)
    assert len(zones) == 2
    plan = PANMigrationPlan(zones=zones)
    assert any(issue.code == 'duplicate_target_name' for issue in validate_plan(plan).issues)
    assert not PANSetRenderer().render(plan).commands


def test_zone_interface_membership_commands():
    plan = PANMigrationPlan(zones=(
        PlannedZone(source_object_type="zone", source_name="trust", target_vsys="vsys1",
                    status=PANMigrationStatus.SUPPORTED, interfaces=("ethernet1/1", "ethernet1/3")),
    ))

    assert PANSetRenderer().render(plan).commands == (
        "set vsys vsys1 zone trust network layer3 [ ethernet1/1 ethernet1/3 ]",
    )
