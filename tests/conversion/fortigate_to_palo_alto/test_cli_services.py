from fwmigrate.conversion.fortigate_to_palo_alto.models import (
    PANMigrationPlan, PANMigrationStatus, PlannedService,
)
from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import PANSetRenderer
import pytest


def test_tcp_destination_tcp_source_and_udp_service_commands():
    plan = PANMigrationPlan(services=(
        PlannedService(source_object_type="service", source_name="https", target_vsys="vsys1",
                       status=PANMigrationStatus.SUPPORTED, protocol="tcp", destination_port="443"),
        PlannedService(source_object_type="service", source_name="tcp-source", target_vsys="vsys1",
                       status=PANMigrationStatus.SUPPORTED, protocol="tcp", source_port="1024-65535",
                       destination_port="443"),
        PlannedService(source_object_type="service", source_name="dns", target_vsys="vsys1",
                       status=PANMigrationStatus.SUPPORTED, protocol="udp", destination_port="53"),
    ))

    assert PANSetRenderer().render(plan).commands == (
        "set vsys vsys1 service https protocol tcp",
        "set vsys vsys1 service https protocol tcp port 443",
        "set vsys vsys1 service tcp-source protocol tcp",
        "set vsys vsys1 service tcp-source protocol tcp port 443",
        "set vsys vsys1 service tcp-source protocol tcp source-port 1024-65535",
        "set vsys vsys1 service dns protocol udp",
        "set vsys vsys1 service dns protocol udp port 53",
    )


@pytest.mark.parametrize('port,valid', [('70000', False), ('65536', False), ('-1', False),
    ('443,,8443', False), ('100-1', False), ('0', True), ('65535', True),
    ('0-65535', True), ('443,8000-8080', True), ('', False)])
@pytest.mark.parametrize('field', ['destination_port', 'source_port'])
def test_port_expressions_are_validated_before_direct_rendering(port, valid, field):
    fields = {'destination_port': '443', field: port}
    plan = PANMigrationPlan(services=(PlannedService(source_object_type='service', source_name='web',
        target_vsys='vsys1', status=PANMigrationStatus.SUPPORTED, protocol='tcp', **fields),))
    assert bool(PANSetRenderer().render(plan).commands) == valid


def test_extremely_long_port_number_fails_closed_without_crashing():
    plan = PANMigrationPlan(services=(PlannedService(source_object_type='service', source_name='web',
        target_vsys='vsys1', status=PANMigrationStatus.SUPPORTED, protocol='tcp', destination_port='9' * 5000),))
    assert not PANSetRenderer().render(plan).commands
