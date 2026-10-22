from copy import deepcopy
from types import SimpleNamespace

import pytest

from fwmigrate.conversion.fortigate_to_palo_alto import PANMigrationOptions, run_migration_pipeline
from fwmigrate.conversion.fortigate_to_palo_alto.decisions import PANMigrationDecisionSet
from fwmigrate.conversion.fortigate_to_palo_alto.recommendations.sdwan_suggestions import build_sdwan_recommendations
from fwmigrate.vendors.fortigate.model.sdwan import FGSDWAN, FGSDWANZone
from fwmigrate.vendors.fortigate.model.source import FGConfig
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter


def test_zone_only_sdwan_source_stays_visible_in_migration_coverage():
    analysis = FortiGateSourceReporter().analyze_source('''config system sdwan
config zone
edit "virtual-wan-link"
next
end
end
''')
    source = analysis.extracted.config
    before = deepcopy(source)
    result = run_migration_pipeline(source, analysis.derived,
        options=PANMigrationOptions(vdoms={'root': {'vsys': 'vsys1'}}))
    row, = result.coverage['unplanned']
    assert row['source_kind'] == 'sdwan_zone'
    assert row['source_name'] == 'virtual-wan-link' and row['source_vdom'] == 'root'
    assert row['status'] == 'RECOMMENDATION_ONLY' and row['readiness'] == 'MANUAL_DESIGN'
    assert 'SD-WAN' in row['reason']
    assert result.artifact_status == 'PARTIAL' and not result.coverage['complete']
    assert result.rendered.report['coverage'] == result.coverage
    assert not result.rendered.commands
    assert source == before
    recommendation, = result.recommendations
    assert not any('status' in fact or 'load balance' in fact for fact in recommendation.evidence)

    from fwmigrate.conversion.fortigate_to_palo_alto.application.review import build_review_state
    from fwmigrate.conversion.fortigate_to_palo_alto.design.deterministic import approve_draft, build_deterministic_draft

    state = build_review_state(source, analysis.derived, 'source', include_configuration=True)
    draft = build_deterministic_draft(source, analysis.derived, state['decisions'], source_digest='source')
    gap, = (row for row in draft.configuration if row['source_kind'] == 'sdwan_zone')
    assert gap['status'] == 'UNSUPPORTED' and gap['operation'] is None
    assert 'SD-WAN' in gap['blocking_reasons'][0]
    assert any('SD-WAN' in issue['explanation'] for issue in draft.to_dict()['issues'])
    with pytest.raises(ValueError, match='blocked'):
        approve_draft(state['decisions'], draft, [gap['group_key']])


@pytest.mark.parametrize('status', ['enable', 'disable'])
def test_explicit_sdwan_settings_require_manual_design_even_without_children(status):
    analysis = FortiGateSourceReporter().analyze_source(f'''config system sdwan
set status {status}
set load-balance-mode source-ip-based
end
''')
    result = run_migration_pipeline(analysis.extracted.config, analysis.derived)
    row, = result.coverage['unplanned']
    assert row['source_kind'] == 'sdwan_settings' and row['source_vdom'] == 'root'
    recommendation, = result.recommendations
    assert f'status = {status}' in recommendation.evidence
    assert 'load balance mode = source-ip-based' in recommendation.evidence
    assert recommendation.readiness.value == 'MANUAL_DESIGN'
    assert not result.rendered.commands


def test_sdwan_zone_recommendations_preserve_scope_and_do_not_expose_raw_values():
    source = FGConfig(sdwans=[FGSDWAN(vdom=vdom, raw_extra={'future-auth-token': 'private-value'},
        zones=[FGSDWANZone(name='same', minimum_sla_meet_members=2,
                          raw_extra={'future-setting': 'private-zone-value'})]) for vdom in ('root', 'branch')])
    before = deepcopy(source)
    rows = build_sdwan_recommendations(source, SimpleNamespace(), PANMigrationDecisionSet())
    assert len(rows) == 4 and len({row.key for row in rows}) == 4
    zones = [row for row in rows if row.source_kind == 'sdwan_zone']
    assert {(row.source_vdom, row.source_name) for row in zones} == {('root', 'same'), ('branch', 'same')}
    assert all('minimum sla meet members = 2' in row.evidence for row in zones)
    assert all(row.readiness.value == 'MANUAL_DESIGN' for row in rows)
    assert 'private-value' not in str([row.to_dict() for row in rows])
    assert 'private-zone-value' not in str([row.to_dict() for row in rows])
    assert source == before


def test_empty_sdwan_section_does_not_infer_settings_or_manual_work():
    source = FGConfig(sdwans=[FGSDWAN()])
    assert not build_sdwan_recommendations(source, SimpleNamespace(), PANMigrationDecisionSet())
