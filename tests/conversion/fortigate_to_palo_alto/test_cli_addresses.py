from fwmigrate.conversion.fortigate_to_palo_alto.models import (
    PANMigrationPlan, PANMigrationStatus, PlannedAddress, PlannedAddressGroup,
)
from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import PANSetRenderer
import pytest


def test_address_and_static_address_group_commands():
    plan = PANMigrationPlan(
        addresses=(PlannedAddress(source_object_type="address", source_name="web", target_vsys="vsys1",
                                  status=PANMigrationStatus.SUPPORTED, address_type="ip-netmask", value="10.0.0.10/32"),),
        address_groups=(PlannedAddressGroup(source_object_type="address_group", source_name="servers", target_vsys="vsys1",
                                            status=PANMigrationStatus.SUPPORTED, members=("web",)),),
    )

    assert PANSetRenderer().render(plan).commands == (
        "set vsys vsys1 address web ip-netmask 10.0.0.10/32",
        "set vsys vsys1 address-group servers static [ web ]",
    )


@pytest.mark.parametrize('kind,value,valid', [
    ('ip-range', '192.0.2.50-192.0.2.1', False), ('ip-range', '192.0.2.1-192.0.2.1', True),
    ('ip-range', 'bad-192.0.2.1', False), ('ip-netmask', '192.0.2.1/99', False),
    ('ip-netmask', '::/0', False), ('ip-wildcard', '192.0.2.0/999.0.0.0', False),
    ('fqdn', 'bad name.example', False), ('fqdn', 'example.org', True), ('future', '192.0.2.1', False),
])
def test_address_values_are_validated_before_direct_rendering(kind, value, valid):
    plan = PANMigrationPlan(addresses=(PlannedAddress(source_object_type='address', source_name='host',
        target_vsys='vsys1', status=PANMigrationStatus.SUPPORTED, address_type=kind, value=value),),
        address_groups=(PlannedAddressGroup(source_object_type='address_group', source_name='group',
            target_vsys='vsys1', status=PANMigrationStatus.SUPPORTED, members=('host',)),))
    assert bool(PANSetRenderer().render(plan).commands) == valid
