from fwmigrate.conversion.fortigate_to_palo_alto.models import (
    PANMigrationPlan, PANMigrationStatus, PlannedAddress, PlannedAddressGroup,
)
from fwmigrate.conversion.fortigate_to_palo_alto.renderer import PANSetRenderer


def test_address_and_static_address_group_commands():
    plan = PANMigrationPlan(
        addresses=(PlannedAddress(source_object_type="address", source_name="web", target_vsys="vsys1",
                                  status=PANMigrationStatus.SUPPORTED, address_type="ip-netmask", value="10.0.0.10/32"),),
        address_groups=(PlannedAddressGroup(source_object_type="address_group", source_name="servers", target_vsys="vsys1",
                                            status=PANMigrationStatus.SUPPORTED, members=("web",)),),
    )

    assert PANSetRenderer().render(plan).commands == (
        "set system setting target-vsys vsys1",
        "set address web ip-netmask 10.0.0.10/32",
        "set address-group servers static [ web ]",
    )
