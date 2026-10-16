from fwmigrate.conversion.fortigate_to_palo_alto.models import PANMigrationPlan
from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import PANSetRenderer
import hashlib
import pytest
from fwmigrate.conversion.fortigate_to_palo_alto.models import PANMigrationStatus, PlannedStaticRoute
from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import _v


def test_documentation_baseline_never_claims_device_or_other_release_validation():
    report = PANSetRenderer().render(PANMigrationPlan()).report
    assert report['cli_compatibility'] == {
        'reference_version': '11.1', 'verification': 'DOCUMENTED_SYNTAX',
        'device_validation': 'UNVERIFIED', 'other_versions': 'UNVERIFIED',
    }


@pytest.mark.parametrize('control', ['\r', '\r\n', '\0', '\x1b', '\t', '\x7f', '\x85', '\u2028', '\u2029'])
def test_renderer_rejects_terminal_controls(control):
    with pytest.raises(ValueError, match='unsafe control character'):
        _v('description' + control + 'next command')


def test_renderer_preserves_valid_escaping_and_artifact_identity(tmp_path):
    description = 'Café "quoted" \\ path\nsecond line'
    assert _v(description) == '"Café \\"quoted\\" \\\\ path\\nsecond line"'
    plan = PANMigrationPlan(static_routes=(PlannedStaticRoute(source_object_type='static_route', source_name='1',
        status=PANMigrationStatus.SUPPORTED, virtual_router='vr', destination='192.0.2.0/24',
        nexthop_type='discard', description=description),))
    renderer = PANSetRenderer()
    artifact = renderer.render(plan)
    renderer.write_files(artifact, tmp_path)
    exported = (tmp_path / 'palo_alto_config.set').read_text(encoding='utf-8')
    assert exported == '\n'.join(artifact.commands)
    assert artifact.report['commands'] == len(artifact.commands)
    assert artifact.report['command_sha256'] == hashlib.sha256(exported.encode()).hexdigest()
