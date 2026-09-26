import pytest

from fwmigrate.conversion.fortigate_to_palo_alto.models import (
    PANMigrationPlan, PANMigrationStatus, PlannedAddress, PlannedAddressGroup, PlannedNATRule,
    PlannedSchedule, PlannedSecurityRule, PlannedService, PlannedServiceGroup, PlannedStaticRoute, PlannedZone,
)
from fwmigrate.conversion.fortigate_to_palo_alto.renderer import PANSetRenderer
from fwmigrate.conversion.fortigate_to_palo_alto.validation import validate_plan


def test_structured_plan_renders_scoped_policy_and_nat_commands_in_order():
    plan = PANMigrationPlan(
        addresses=(PlannedAddress(source_object_type="address", source_name="web", target_vsys="vsys1",
                                   target_name="web", status=PANMigrationStatus.SUPPORTED,
                                   address_type="ip-netmask", value="10.0.0.5/32"),
                   PlannedAddress(source_object_type="address", source_name="db", target_vsys="vsys2",
                                   target_name="db", status=PANMigrationStatus.SUPPORTED,
                                   address_type="ip-netmask", value="10.0.0.6/32")),
        services=(PlannedService(source_object_type="service", source_name="web-svc", target_vsys="vsys1",
                                  target_name="web-svc", status=PANMigrationStatus.SUPPORTED,
                                  protocol="tcp", destination_port="443", source_port="1024-65535"),
                   PlannedService(source_object_type="service", source_name="dns", target_vsys="vsys1",
                                  target_name="dns", status=PANMigrationStatus.SUPPORTED,
                                  protocol="udp", destination_port="53")),
        address_groups=(PlannedAddressGroup(source_object_type="address_group", source_name="web-group",
            target_vsys="vsys1", target_name="web-group", status=PANMigrationStatus.SUPPORTED,
            members=("web",)),),
        service_groups=(PlannedServiceGroup(source_object_type="service_group", source_name="web-services",
            target_vsys="vsys1", target_name="web-services", status=PANMigrationStatus.SUPPORTED,
            members=("web-svc",)),),
        schedules=(PlannedSchedule(source_object_type="schedule", source_name="business-hours",
            target_vsys="vsys1", target_name="business-hours", status=PANMigrationStatus.SUPPORTED,
            schedule_type="recurring", weekly=(("monday", "08:00", "17:00"),)),
                    PlannedSchedule(source_object_type="schedule", source_name="holiday",
            target_vsys="vsys1", target_name="holiday", status=PANMigrationStatus.SUPPORTED,
            schedule_type="one-time", non_recurring=(("2026/12/25@00:00", "2026/12/26@00:00"),))),
        zones=(PlannedZone(source_object_type="zone", source_name="trust", target_vsys="vsys1", target_name="trust",
                           status=PANMigrationStatus.SUPPORTED, interfaces=("ethernet1/1",)),
               PlannedZone(source_object_type="zone", source_name="untrust", target_vsys="vsys1", target_name="untrust",
                           status=PANMigrationStatus.SUPPORTED)),
        security_rules=(PlannedSecurityRule(source_object_type="security_rule", source_name="allow-web",
            target_vsys="vsys1", target_name="allow-web", status=PANMigrationStatus.SUPPORTED,
            from_zones=("trust",), to_zones=("untrust",), sources=("web",), destinations=("any",),
            services=("web-svc",), schedule="business-hours", action="allow", negate_source=True,
            negate_destination=True, disabled=True, description="web access"),),
        nat_rules=(PlannedNATRule(source_object_type="nat_rule", source_name="snat", target_vsys="vsys1",
            target_name="snat", status=PANMigrationStatus.SUPPORTED, from_zones=("trust",),
            to_zones=("untrust",), source_addresses=("web",), destination_addresses=("any",),
            service="web-svc", to_interface="ethernet1/2",
            source_translation_type="dynamic-ip-and-port", translated_addresses=("203.0.113.5",)),
                   PlannedNATRule(source_object_type="nat_rule", source_name="dnat", target_vsys="vsys1",
            target_name="dnat", status=PANMigrationStatus.SUPPORTED, from_zones=("untrust",),
            to_zones=("trust",), source_addresses=("any",), destination_addresses=("203.0.113.20",),
            service="web-svc", to_interface="ethernet1/1", destination_translated_address="10.0.0.20",
            destination_translated_port="8443"),
                   PlannedNATRule(source_object_type="nat_rule", source_name="if-snat", target_vsys="vsys1",
            target_name="if-snat", status=PANMigrationStatus.SUPPORTED, from_zones=("trust",),
            to_zones=("untrust",), source_interface_address=True,
            source_translation_type="dynamic-ip-and-port")),
        static_routes=(PlannedStaticRoute(source_object_type="static_route", source_name="default",
            target_vsys="vsys1", target_name="default", status=PANMigrationStatus.SUPPORTED,
            virtual_router="default", destination="0.0.0.0/0", interface="ethernet1/1",
            nexthop="192.0.2.1", admin_distance=10),
                       PlannedStaticRoute(source_object_type="static_route", source_name="blackhole",
            target_vsys="vsys1", target_name="blackhole", status=PANMigrationStatus.SUPPORTED,
            virtual_router="default", destination="198.51.100.0/24", nexthop_type="discard")),
    )
    validation = validate_plan(plan)
    commands = PANSetRenderer().render(plan, validation).commands
    assert commands[0] == "set system setting target-vsys vsys1"
    assert "set address web ip-netmask 10.0.0.5/32" in commands
    assert "set address-group web-group static [ web ]" in commands
    assert "set service web-svc protocol tcp port 443" in commands
    assert "set service web-svc protocol tcp source-port 1024-65535" in commands
    assert "set service dns protocol udp port 53" in commands
    assert "set service-group web-services members [ web-svc ]" in commands
    assert "set schedule business-hours schedule-type recurring" in commands
    assert "set schedule business-hours schedule-type recurring weekly monday [ 08:00-17:00 ]" in commands
    assert "set schedule holiday schedule-type non-recurring [ 2026/12/25@00:00-2026/12/26@00:00 ]" in commands
    assert "set zone trust network layer3 [ ethernet1/1 ]" in commands
    snat_match = ["set rulebase nat rules snat from [ trust ]", "set rulebase nat rules snat to [ untrust ]",
                  "set rulebase nat rules snat source [ web ]", "set rulebase nat rules snat destination [ any ]",
                  "set rulebase nat rules snat service web-svc", "set rulebase nat rules snat to-interface ethernet1/2",
                  "set rulebase nat rules snat source-translation dynamic-ip-and-port translated-address [ 203.0.113.5 ]"]
    assert [commands.index(command) for command in snat_match] == sorted(commands.index(command) for command in snat_match)
    assert "set rulebase nat rules dnat destination-translation translated-address 10.0.0.20" in commands
    assert "set rulebase nat rules dnat destination-translation translated-port 8443" in commands
    assert "set rulebase nat rules if-snat source-translation dynamic-ip-and-port interface-address" in commands
    assert all("pool" not in command for command in commands)
    security_commands = ["set rulebase security rules allow-web from [ trust ]",
                         "set rulebase security rules allow-web to [ untrust ]",
                         "set rulebase security rules allow-web source [ web ]",
                         "set rulebase security rules allow-web destination [ any ]",
                         "set rulebase security rules allow-web service [ web-svc ]",
                         "set rulebase security rules allow-web schedule business-hours",
                         "set rulebase security rules allow-web negate-source yes",
                         "set rulebase security rules allow-web negate-destination yes",
                         "set rulebase security rules allow-web disabled yes",
                         "set rulebase security rules allow-web description \"web access\"",
                         "set rulebase security rules allow-web action allow"]
    assert [commands.index(command) for command in security_commands] == sorted(commands.index(command) for command in security_commands)
    nat_end = max(i for i, command in enumerate(commands) if "rulebase nat rules" in command)
    security_start = min(i for i, command in enumerate(commands) if "rulebase security rules" in command)
    assert nat_end < security_start
    assert commands[commands.index("set system setting target-vsys vsys2") + 1] == "set address db ip-netmask 10.0.0.6/32"
    reset = commands.index("set system target-vsys none")
    assert commands[reset + 1] == "set network virtual-router default routing-table ip static-route default destination 0.0.0.0/0"
    assert commands[reset + 2] == "set network virtual-router default routing-table ip static-route default interface ethernet1/1"
    assert commands[reset + 3] == "set network virtual-router default routing-table ip static-route default nexthop ip-address 192.0.2.1"
    assert commands[reset + 4] == "set network virtual-router default routing-table ip static-route default admin-dist 10"
    assert commands[reset + 5] == "set network virtual-router default routing-table ip static-route blackhole destination 198.51.100.0/24"
    assert commands[reset + 6] == "set network virtual-router default routing-table ip static-route blackhole nexthop discard"


def test_validation_blocks_manual_review_from_rendered_artifact(tmp_path):
    plan = PANMigrationPlan(addresses=(PlannedAddress(source_name="review", status=PANMigrationStatus.MANUAL_REVIEW),))
    renderer = PANSetRenderer()
    rendered = renderer.render(plan, validate_plan(plan))
    renderer.write_files(rendered, tmp_path)
    assert rendered.commands == ()
    assert (tmp_path / "migration_report.json").exists()
    assert not (tmp_path / "conversion_report.json").exists()
    assert rendered.report["items"][0]["renderable"] is False
    assert rendered.report["items"][0]["render_blockers"]


def test_renderer_rejects_validation_for_another_plan():
    first = PANMigrationPlan()
    second = PANMigrationPlan(addresses=(PlannedAddress(source_name="different"),))
    with pytest.raises(ValueError, match="does not match"):
        PANSetRenderer().render(first, validate_plan(second))


def test_renderer_rejects_forged_validation_result():
    from fwmigrate.conversion.fortigate_to_palo_alto.validation import MigrationValidationResult

    plan = PANMigrationPlan()
    with pytest.raises(ValueError, match="does not match"):
        PANSetRenderer().render(plan, MigrationValidationResult())
