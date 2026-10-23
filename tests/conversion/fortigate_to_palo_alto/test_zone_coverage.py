from copy import deepcopy

import pytest

from fwmigrate.conversion.fortigate_to_palo_alto import PANMigrationOptions, run_migration_pipeline
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter


SOURCE = '''config system interface
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


def migrate(text=SOURCE, mapped=True):
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
    baseline = migrate(SOURCE + policy)
    assert any('rulebase security' in command for command in baseline.rendered.commands)
    source = SOURCE.replace('set interface lan', 'set interface lan\nset future-policy-match enable')
    result = migrate(source + policy)
    assert result.plan.zones[0].status.value == 'MANUAL_REVIEW'
    assert any('future-policy-match' in warning for warning in result.plan.zones[0].warnings)
    assert result.artifact_status == 'PARTIAL'
    assert not any(' zone ' in command or 'rulebase security' in command for command in result.rendered.commands)


def test_source_zone_tagging_is_reported_for_manual_metadata_review():
    source = SOURCE.replace('set interface lan', '''set interface lan
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
