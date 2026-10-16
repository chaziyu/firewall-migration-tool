from fwmigrate.conversion.fortigate_to_palo_alto.models import (
    PANMigrationPlan, PANMigrationStatus, PlannedAddress, PlannedSecurityRule, PlannedStaticRoute,
)
from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import PANSetRenderer


def test_vsys_switching_keeps_duplicate_names_scoped_and_routes_at_device_scope():
    plan = PANMigrationPlan(
        addresses=(
            PlannedAddress(source_vdom="root", source_object_type="address", source_name="shared",
                           target_vsys="vsys1", status=PANMigrationStatus.SUPPORTED,
                           address_type="ip-netmask", value="10.0.0.1/32"),
            PlannedAddress(source_vdom="vdom-a", source_object_type="address", source_name="shared",
                           target_vsys="vsys2", status=PANMigrationStatus.SUPPORTED,
                           address_type="ip-netmask", value="10.0.0.2/32"),
        ),
        security_rules=(
            PlannedSecurityRule(applications=("any",), source_vdom="root", source_object_type="security_rule", source_name="root-rule",
                                target_vsys="vsys1", status=PANMigrationStatus.SUPPORTED,
                                from_zones=("any",), to_zones=("any",), sources=("shared",),
                                destinations=("any",), services=("any",), action="allow"),
            PlannedSecurityRule(applications=("any",), source_vdom="vdom-a", source_object_type="security_rule", source_name="vdom-rule",
                                target_vsys="vsys2", status=PANMigrationStatus.SUPPORTED,
                                from_zones=("any",), to_zones=("any",), sources=("shared",),
                                destinations=("any",), services=("any",), action="deny"),
        ),
        static_routes=(PlannedStaticRoute(source_vdom="vdom-a", source_object_type="static_route",
                                          source_name="default", target_vsys="vsys2",
                                          status=PANMigrationStatus.SUPPORTED, virtual_router="default",
                                          destination="0.0.0.0/0", nexthop="192.0.2.1"),),
    )

    assert PANSetRenderer().render(plan).commands == (
        "set vsys vsys1 address shared ip-netmask 10.0.0.1/32",
        "set vsys vsys1 rulebase security rules root-rule from [ any ]",
        "set vsys vsys1 rulebase security rules root-rule to [ any ]",
        "set vsys vsys1 rulebase security rules root-rule source [ shared ]",
        "set vsys vsys1 rulebase security rules root-rule destination [ any ]",
        "set vsys vsys1 rulebase security rules root-rule service [ any ]",
        "set vsys vsys1 rulebase security rules root-rule application [ any ]",
        "set vsys vsys1 rulebase security rules root-rule action allow",
        "set vsys vsys2 address shared ip-netmask 10.0.0.2/32",
        "set vsys vsys2 rulebase security rules vdom-rule from [ any ]",
        "set vsys vsys2 rulebase security rules vdom-rule to [ any ]",
        "set vsys vsys2 rulebase security rules vdom-rule source [ shared ]",
        "set vsys vsys2 rulebase security rules vdom-rule destination [ any ]",
        "set vsys vsys2 rulebase security rules vdom-rule service [ any ]",
        "set vsys vsys2 rulebase security rules vdom-rule application [ any ]",
        "set vsys vsys2 rulebase security rules vdom-rule action deny",
        "set network virtual-router default routing-table ip static-route default destination 0.0.0.0/0",
        "set network virtual-router default routing-table ip static-route default nexthop ip-address 192.0.2.1",
    )
