import pytest

from fwmigrate.conversion.fortigate_to_palo_alto.requirements import build_mapping_requirements
from fwmigrate.conversion.fortigate_to_palo_alto.planning.policies import _zones
from fwmigrate.conversion.fortigate_to_palo_alto.planning.nat import _policy_zones, _target_zone
from fwmigrate.conversion.fortigate_to_palo_alto.options import PANMigrationOptions
from fwmigrate.conversion.fortigate_to_palo_alto.target.name_validation import zone_name_issue
from fwmigrate.conversion.fortigate_to_palo_alto.models import PANMigrationPlan, PlannedZone
from fwmigrate.conversion.fortigate_to_palo_alto.validation import validate_plan
from fwmigrate.vendors.fortigate.model.source import FGConfig
from fwmigrate.vendors.fortigate.model.policy import FGPolicy


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
