from fwmigrate.conversion.fortigate_to_palo_alto.models import (
    PANMigrationPlan, PANMigrationStatus, PlannedService,
)
from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import PANSetRenderer


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
