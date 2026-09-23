from fwmigrate.conversion.fortigate_to_palo_alto.models import (
    PANMigrationPlan, PANMigrationStatus, PlannedZone,
)
from fwmigrate.conversion.fortigate_to_palo_alto.renderer import PANSetRenderer


def test_zone_interface_membership_commands():
    plan = PANMigrationPlan(zones=(
        PlannedZone(source_object_type="zone", source_name="trust", target_vsys="vsys1",
                    status=PANMigrationStatus.SUPPORTED, interfaces=("ethernet1/1", "ethernet1/3")),
    ))

    assert PANSetRenderer().render(plan).commands == (
        "set system setting target-vsys vsys1",
        "set zone trust network layer3 [ ethernet1/1 ethernet1/3 ]",
    )
