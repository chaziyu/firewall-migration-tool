from fwmigrate.conversion.fortigate_to_palo_alto.models import (
    PANMigrationPlan,
    PANMigrationStatus,
    PlannedDHCPServer,
    PlannedInterface,
)
from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import PANSetRenderer


def test_dhcp_commands_render_after_interface_ownership_in_device_scope():
    interface = PlannedInterface(
        source_vdom="root",
        source_kind="interface",
        source_object_type="interface",
        source_name="lan",
        target_vsys="vsys1",
        target_name="ethernet1/3",
        status=PANMigrationStatus.SUPPORTED,
        interface_family="ethernet",
        virtual_router="vr-main",
    )
    dhcp = PlannedDHCPServer(
        source_vdom="root",
        source_kind="dhcp_server",
        source_object_type="dhcp_server",
        source_name="1",
        target_vsys="vsys1",
        target_name="ethernet1/3",
        status=PANMigrationStatus.SUPPORTED,
        interface="ethernet1/3",
        mode="enabled",
        lease_type="timeout",
        lease_timeout=3600,
        gateway="10.0.0.1",
        subnet_mask="255.255.255.0",
        dns_primary="10.0.0.2",
        dns_secondary="10.0.0.3",
        ip_pools=("10.0.0.10-10.0.0.50",),
    )

    rendered = PANSetRenderer().render(PANMigrationPlan(
        interfaces=(interface,),
        dhcp_servers=(dhcp,),
    ))

    dhcp_commands = (
        "set network dhcp interface ethernet1/3 server mode enabled",
        "set network dhcp interface ethernet1/3 server option lease timeout 3600",
        "set network dhcp interface ethernet1/3 server option gateway 10.0.0.1",
        "set network dhcp interface ethernet1/3 server option subnet-mask 255.255.255.0",
        "set network dhcp interface ethernet1/3 server option dns primary 10.0.0.2",
        "set network dhcp interface ethernet1/3 server option dns secondary 10.0.0.3",
        "set network dhcp interface ethernet1/3 server ip-pool [ 10.0.0.10-10.0.0.50 ]",
    )
    assert rendered.commands[-len(dhcp_commands):] == dhcp_commands
    assert rendered.commands.index("set network virtual-router vr-main interface [ ethernet1/3 ]") < (
        rendered.commands.index(dhcp_commands[0])
    )
    item = next(item for item in rendered.report["items"] if item["source_object_type"] == "dhcp_server")
    assert item["rendered"] is True
    assert item["commands"] == list(dhcp_commands)


def test_unlimited_dhcp_lease_renders_without_timeout():
    interface = PlannedInterface(
        source_vdom="root", source_object_type="interface", source_name="lan",
        target_vsys="vsys1", target_name="ethernet1/3",
        status=PANMigrationStatus.SUPPORTED, interface_family="ethernet",
        virtual_router="vr-main",
    )
    dhcp = PlannedDHCPServer(
        source_vdom="root", source_object_type="dhcp_server", source_name="1",
        target_vsys="vsys1", target_name="ethernet1/3",
        status=PANMigrationStatus.SUPPORTED, interface="ethernet1/3",
        mode="disabled", lease_type="unlimited",
        ip_pools=("10.0.0.10-10.0.0.50",),
    )
    commands = PANSetRenderer().render(
        PANMigrationPlan(interfaces=(interface,), dhcp_servers=(dhcp,))
    ).commands
    assert "set network dhcp interface ethernet1/3 server option lease unlimited" in commands
    assert not any("lease timeout" in command for command in commands)
