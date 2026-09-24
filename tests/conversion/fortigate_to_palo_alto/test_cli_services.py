from fwmigrate.conversion.fortigate_to_palo_alto.models import (
    PANMigrationPlan, PANMigrationStatus, PlannedService,
)
from fwmigrate.conversion.fortigate_to_palo_alto.renderer import PANSetRenderer


def test_tcp_destination_tcp_source_and_udp_service_commands():
    plan = PANMigrationPlan(services=(
        PlannedService(source_object_type="service", source_name="https", target_vsys="vsys1",
                       status=PANMigrationStatus.SUPPORTED, protocol="tcp", destination_port="443"),
        PlannedService(source_object_type="service", source_name="tcp-source", target_vsys="vsys1",
                       status=PANMigrationStatus.SUPPORTED, protocol="tcp", source_port="1024-65535"),
        PlannedService(source_object_type="service", source_name="dns", target_vsys="vsys1",
                       status=PANMigrationStatus.SUPPORTED, protocol="udp", destination_port="53"),
    ))

    assert PANSetRenderer().render(plan).commands == (
        "set system setting target-vsys vsys1",
        "set service https protocol tcp",
        "set service https protocol tcp port 443",
        "set service tcp-source protocol tcp",
        "set service tcp-source protocol tcp source-port 1024-65535",
        "set service dns protocol udp",
        "set service dns protocol udp port 53",
    )
