from fwmigrate.conversion.fortigate_to_palo_alto.models import PANMigrationPlan
from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import PANSetRenderer


def test_documentation_baseline_never_claims_device_or_other_release_validation():
    report = PANSetRenderer().render(PANMigrationPlan()).report
    assert report['cli_compatibility'] == {
        'reference_version': '11.1', 'verification': 'DOCUMENTED_SYNTAX',
        'device_validation': 'UNVERIFIED', 'other_versions': 'UNVERIFIED',
    }
