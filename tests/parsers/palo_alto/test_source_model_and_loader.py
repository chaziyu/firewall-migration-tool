import pytest
from pathlib import Path

from fwmigrate.vendors.palo_alto.native import load_pan_source as native_load_pan_source
from fwmigrate.vendors.palo_alto.native import build_panos_config
from fwmigrate.vendors.palo_alto.source_model import PANScope, pan_scope_identity
from fwmigrate.vendors.palo_alto.xml_loader import load_pan_source


PANORAMA_FIXTURE = Path(__file__).parents[2] / "fixtures" / "palo_alto" / "integrated_panorama.xml"


def test_scope_identity_qualifies_vsys_by_device_and_serial():
    first = PANScope(kind="vsys", name="vsys1", device_name="fw-a", vsys="vsys1")
    second = PANScope(kind="vsys", name="vsys1", device_name="fw-b", vsys="vsys1")
    managed = PANScope(
        kind="vsys", name="vsys1", device_name="panorama", device_serial="SERIAL-1", vsys="vsys1"
    )

    assert pan_scope_identity(first) != pan_scope_identity(second)
    assert pan_scope_identity(managed) == "vsys:vsys1:device:SERIAL-1"
    assert pan_scope_identity(PANScope(kind="shared", name="shared")) == "shared:shared"


def test_rulebase_position_belongs_to_each_record():
    config = build_panos_config(
        """<config><devices>
          <entry name="fw-a"><vsys><entry name="vsys1">
            <pre-rulebase><security><rules><entry name="pre"/></rules></security></pre-rulebase>
            <rulebase><security><rules><entry name="local"/></rules></security></rulebase>
            <post-rulebase><security><rules><entry name="post"/></rules></security></post-rulebase>
          </entry></vsys></entry>
          <entry name="fw-b"><vsys><entry name="vsys1"><address><entry name="same"/></address></entry></vsys></entry>
        </devices></config>"""
    )

    positions = {record.name: record.rulebase_position for record in config.source_inventory}
    assert positions["pre"] == "pre"
    assert positions["local"] == "local"
    assert positions["post"] == "post"
    assert all(not hasattr(scope, "rulebase_position") for scope in config.scopes)
    assert len({pan_scope_identity(scope) for scope in config.scopes if scope.kind == "vsys"}) == 2


def test_xml_loader_preserves_supported_input_forms_and_compatibility_export():
    wrapped = "<response><result><config version='11.1'><devices><entry name='fw'/></devices></config></result></response>"
    document = load_pan_source(wrapped)

    assert document.root.tag == "config"
    assert document.source_version == "11.1"
    assert native_load_pan_source is load_pan_source

    with pytest.raises(ValueError, match="Empty configuration input"):
        load_pan_source("  ")
    with pytest.raises(ValueError, match="Malformed XML input"):
        load_pan_source("<config>")
    with pytest.raises(ValueError, match="CLI 'set'"):
        load_pan_source("set deviceconfig system hostname fw")


def test_walker_keeps_panorama_device_group_and_managed_serial_contexts_separate():
    from fwmigrate.vendors.palo_alto.source_builder import build_panos_config

    config = build_panos_config(PANORAMA_FIXTURE.read_text())
    by_name = {record.name: record for record in config.source_inventory}

    assert by_name["shared-pre"].scope.kind == "shared"
    assert by_name["parent-pre"].scope.device_group == "parent"
    assert by_name["child-pre"].scope.device_group == "child"
    assert by_name["child-pre"].scope.parent_device_group == "parent"
    assert by_name["vsys1"].scope.device_serial == "serial-child"
    assert by_name["vsys1"].scope.device_group == "child"
    assert by_name["child-pre"].rulebase_position == "pre"
    assert by_name["child-post"].rulebase_position == "post"


def test_typed_source_models_preserve_absent_and_explicit_empty_values():
    from fwmigrate.vendors.palo_alto.source_builder import build_panos_config

    config = build_panos_config(
        """<config><shared><address>
          <entry name='absent'/><entry name='empty'><tag/></entry>
        </address><rulebase><security><rules>
          <entry name='explicit'><disabled>no</disabled></entry>
        </rules></security></rulebase></shared></config>"""
    )

    absent, empty = config.addresses
    assert absent.ip_netmask is None
    assert "ip_netmask" not in absent.explicit_fields
    assert empty.tags == []
    assert "tags" in empty.explicit_fields
    assert config.security_rules[0].disabled == "no"
    assert "disabled" in config.security_rules[0].explicit_fields
    assert config.source_inventory


def test_typed_collections_are_authoritative_and_inventory_is_evidence():
    from fwmigrate.vendors.palo_alto.source_builder import build_panos_config

    config = build_panos_config(
        """<config><shared><address><entry name='a'><ip-netmask>10.0.0.1/32</ip-netmask></entry></address></shared></config>"""
    )

    assert config.addresses[0].name == "a"
    assert config.source_inventory[0].values["ip-netmask"] == "10.0.0.1/32"
    assert config.addresses[0].source_order == config.source_inventory[0].source_order


def test_typed_source_keeps_malformed_names_and_nested_unmodeled_xml():
    from fwmigrate.vendors.palo_alto.source_builder import build_panos_config

    config = build_panos_config(
        """<config><shared><address>
          <entry><ip-netmask>10.0.0.1/32</ip-netmask><future><nested>keep</nested></future></entry>
        </address></shared></config>"""
    )

    address = config.addresses[0]
    assert address.name is None
    assert address.raw_extra["future"] == {"nested": "keep"}
    assert "ip-netmask" not in address.raw_extra


def test_address_models_preserve_object_variants_and_scope():
    from fwmigrate.vendors.palo_alto.source_builder import build_panos_config

    fixture = Path(__file__).parents[2] / "fixtures" / "palo_alto" / "objects.xml"
    config = build_panos_config(fixture.read_text())
    addresses = {item.name: item for item in config.addresses if item.name}

    assert addresses["IPv4-Host"].ip_netmask == "10.10.10.50/32"
    assert addresses["IPv6-Net"].ip_netmask == "2001:db8:10::/64"
    assert addresses["IPv4-Range"].ip_range == "192.0.2.10-192.0.2.20"
    assert addresses["IPv6-Range"].ip_range == "2001:db8::10-2001:db8::20"
    assert addresses["Wildcard"].ip_wildcard == "10.5.1.1/0.127.248.2"
    assert addresses["External-FQDN"].fqdn == "Api.Example.test"
    assert addresses["Described"].description == "Preserved description"
    assert addresses["Tagged"].tags == ["production", "internet-facing"]
    assert addresses["Multiple-Types"].ip_netmask == "192.0.2.30/32"
    assert addresses["Multiple-Types"].fqdn == "duplicate.example.test"
    assert addresses["Missing-Type"].ip_netmask is None
    assert addresses["Missing-Type"].ip_range is None
    assert addresses["Missing-Type"].ip_wildcard is None
    assert addresses["Missing-Type"].fqdn is None
    assert addresses["Has-Unknown"].raw_extra == {"future-field": "retain-me"}
    assert addresses["IPv4-Host"].scope.kind == "vsys"
    assert addresses["IPv4-Host"].scope.name == "vsys1"
    assert addresses["IPv4-Host"].source_order is not None
    assert "ip_netmask" in addresses["IPv4-Host"].explicit_fields


def test_address_groups_preserve_static_dynamic_and_both_forms():
    from fwmigrate.vendors.palo_alto.source_builder import build_panos_config

    fixture = Path(__file__).parents[2] / "fixtures" / "palo_alto" / "objects.xml"
    config = build_panos_config(fixture.read_text())
    groups = {item.name: item for item in config.address_groups if item.name}

    assert groups["Static-Group"].static_members == ["IPv4-Host"]
    assert groups["Dynamic-Group"].dynamic_filter == "'production' and 'internet-facing'"
    assert groups["Both-Group"].static_members == ["IPv4-Net"]
    assert groups["Both-Group"].dynamic_filter == "'production'"
    assert groups["Nested-Group"].static_members == ["Static-Group", "Scoped-Web"]
    assert groups["Unknown-Group"].raw_extra == {"future-setting": "retain-me"}
    assert "static_members" in groups["Static-Group"].explicit_fields
    assert "dynamic_filter" in groups["Dynamic-Group"].explicit_fields
    assert groups["Static-Group"].scope.name == "vsys1"
    assert groups["Scoped-Group"].scope.name == "vsys2"


def test_services_preserve_independent_protocol_branches_and_source_strings():
    from fwmigrate.vendors.palo_alto.source_builder import build_panos_config

    fixture = Path(__file__).parents[2] / "fixtures" / "palo_alto" / "services.xml"
    config = build_panos_config(fixture.read_text())
    services = {
        item.name: item
        for item in config.services
        if item.name and item.scope and item.scope.name == "vsys1"
    }

    assert services["TCP-443"].tcp.port == "443"
    assert services["UDP-53"].udp.port == "53"
    assert services["TCP-Source"].tcp.source_port == "1024-65535"
    assert services["UDP-Source"].udp.source_port == "500,4500"
    assert services["Port-Range"].tcp.port == "80-90"
    assert services["Multi-Range"].tcp.port == "80,443,8000-8100,9000-9010"
    assert services["Missing-Port"].tcp is not None
    assert services["Missing-Port"].tcp.port is None
    assert services["Both-Protocols"].tcp is not None
    assert services["Both-Protocols"].udp is not None
    assert services["Timeout-Service"].tcp.override.timeout == "3600"
    assert services["Timeout-Service"].tcp.override.halfclose_timeout == "120"
    assert services["Timeout-Service"].tcp.override.timewait_timeout == "15"
    assert services["Unknown-Service"].udp.raw_extra == {"future-protocol": "value"}
    assert services["Unknown-Service"].raw_extra == {"future-setting": "retain-me"}
    assert services["TCP-443"].description == "HTTPS service"
    assert services["Tagged-Service"].tags == ["production"]
    assert "port" in services["TCP-443"].tcp.explicit_fields


def test_service_groups_and_names_remain_scoped_source_references():
    from fwmigrate.vendors.palo_alto.source_builder import build_panos_config

    fixture = Path(__file__).parents[2] / "fixtures" / "palo_alto" / "services.xml"
    config = build_panos_config(fixture.read_text())
    scoped_services = [item for item in config.services if item.name == "Scoped-Service"]
    scoped_groups = [item for item in config.service_groups if item.name == "Scoped-Group"]

    assert {item.scope.name for item in scoped_services} == {"shared", "vsys1", "vsys2"}
    assert {item.scope.name for item in scoped_groups} == {"vsys1", "vsys2"}
    assert any(item.name == "Collision" for item in config.services)
    assert any(item.name == "Collision" for item in config.service_groups)
    assert config.service_groups[0].members
    assert config.service_groups[0].members[0] in {"TCP-443", "UDP-53"}


def test_schedules_preserve_recurring_and_non_recurring_structure():
    from fwmigrate.vendors.palo_alto.source_builder import build_panos_config

    fixture = Path(__file__).parents[2] / "fixtures" / "palo_alto" / "schedules.xml"
    config = build_panos_config(fixture.read_text())
    schedules = {
        item.name: item
        for item in config.schedules
        if item.name and item.scope and item.scope.name == "vsys1"
    }

    assert schedules["Daily-One"].recurring.daily == ["08:00-17:00"]
    assert schedules["Daily-Multiple"].recurring.daily == ["08:00-12:00", "13:00-17:00"]
    assert schedules["Weekly-One"].recurring.weekly == {"monday": ["08:00-17:00"]}
    assert schedules["Weekly-Same"].recurring.weekly == {
        "monday": ["08:00-17:00"],
        "tuesday": ["08:00-17:00"],
    }
    assert schedules["Weekly-Multiple"].recurring.weekly["monday"] == [
        "08:00-12:00", "13:00-17:00"
    ]
    assert schedules["Once-One"].recurring is None
    assert schedules["Once-One"].non_recurring == ["2026/09/01@08:00-2026/09/01@17:00"]
    assert schedules["Once-Multiple"].non_recurring == [
        "2026/09/01@08:00-2026/09/01@17:00",
        "2026/09/02@08:00-2026/09/02@17:00",
    ]
    assert schedules["Bad-Time"].recurring.daily == ["25:00-26:00"]
    assert schedules["Bad-Date"].non_recurring == ["2026/99/01@08:00-2026/99/01@17:00"]
    assert schedules["Unknown-Schedule"].raw_extra == {"future-setting": "retain-me"}
    assert "recurring" in schedules["Daily-One"].explicit_fields
    assert schedules["Daily-One"].source_order is not None


def test_schedules_remain_scoped_by_source_context():
    from fwmigrate.vendors.palo_alto.source_builder import build_panos_config

    fixture = Path(__file__).parents[2] / "fixtures" / "palo_alto" / "schedules.xml"
    config = build_panos_config(fixture.read_text())
    scoped = [item for item in config.schedules if item.name == "Scoped-Schedule"]

    assert {item.scope.name for item in scoped} == {"shared", "vsys1", "vsys2"}
    assert {item.recurring.daily[0] for item in scoped} == {
        "01:00-02:00", "03:00-04:00", "05:00-06:00"
    }


def test_security_rules_preserve_absent_flags_selectors_and_profiles():
    from fwmigrate.vendors.palo_alto.source_builder import build_panos_config

    fixture = Path(__file__).parents[2] / "fixtures" / "palo_alto" / "policies.xml"
    config = build_panos_config(fixture.read_text())
    rules = {item.name: item for item in config.security_rules if item.name}

    absent = rules["Absent-Flags"]
    explicit = rules["Explicit-No"]
    assert absent.disabled is None
    assert absent.log_start is None
    assert absent.log_end is None
    assert explicit.disabled == "no"
    assert explicit.log_start == "no"
    assert explicit.log_end == "no"
    assert absent.source == ["any"]
    assert absent.from_zones == ["trust"]
    assert rules["Missing-Source"].source is None
    assert rules["Missing-Destination"].destination is None
    assert rules["Profile-Group"].profile_setting.groups == ["Corporate-Profiles"]
    assert rules["Direct-Profiles"].profile_setting.profiles["virus"] == ["av-profile"]
    assert rules["Mixed-Profiles"].profile_setting.groups == ["Corporate-Profiles"]
    assert rules["Mixed-Profiles"].profile_setting.profiles["virus"] == ["av-profile"]
    assert rules["Tags-Logging"].tags == ["production", "audited"]
    assert rules["Tags-Logging"].group_tag == "policy-group"
    assert "disabled" in explicit.explicit_fields
    assert explicit.rulebase_position == "local"


def test_default_security_rules_remain_separate_and_incomplete_entries_stay_empty():
    from fwmigrate.vendors.palo_alto.source_builder import build_panos_config

    fixture = Path(__file__).parents[2] / "fixtures" / "palo_alto" / "default_security_rules.xml"
    config = build_panos_config(fixture.read_text())
    rules = {
        (item.scope.kind if item.scope else "", item.scope.name if item.scope else "", item.name): item
        for item in config.default_security_rules
    }

    shared = rules[("shared", "shared", "intrazone-default")]
    parent = rules[("device-group", "dg-parent", "interzone-default")]
    assert shared.action is None
    assert shared.disabled is None
    assert shared.log_start == "yes"
    assert shared.raw_extra == {"future-default": "shared-evidence"}
    assert parent.action == "drop"
    assert parent.profile_setting.groups == ["strict-group"]
    assert parent.rulebase_position == "post"


def test_security_rules_preserve_panorama_scope_and_rulebase_position():
    from fwmigrate.vendors.palo_alto.source_builder import build_panos_config

    fixture = Path(__file__).parents[2] / "fixtures" / "palo_alto" / "integrated_panorama.xml"
    config = build_panos_config(fixture.read_text())
    rules = {item.name: item for item in config.security_rules if item.name}

    assert rules["shared-pre"].scope.kind == "shared"
    assert rules["shared-pre"].rulebase_position == "pre"
    assert rules["parent-pre"].scope.device_group == "parent"
    assert rules["child-pre"].scope.device_group == "child"
    assert rules["child-pre"].rulebase_position == "pre"


def test_interfaces_preserve_device_structure_units_and_import_evidence():
    from fwmigrate.vendors.palo_alto.source_builder import build_panos_config

    fixture = Path(__file__).parents[2] / "fixtures" / "palo_alto" / "interfaces_extended.xml"
    config = build_panos_config(fixture.read_text())
    interfaces = {item.name: item for item in config.interfaces if item.name}
    units = {item.name: item for item in config.interface_units if item.name}

    assert interfaces["ethernet1/1"].interface_family == "ethernet"
    assert interfaces["ethernet1/1"].mode == "layer3"
    assert interfaces["ethernet1/1"].ipv4_addresses == ["192.0.2.1/24", "192.0.2.10/24"]
    assert interfaces["ethernet1/1"].ipv6_addresses[0].address == "2001:db8::1/64"
    assert interfaces["ethernet1/1"].management_profile == "allow-ping"
    assert interfaces["ethernet1/1"].raw_extra["layer3"] == {"future-l3": "keep-l3"}
    assert interfaces["ethernet1/2"].mode == "layer2"
    assert interfaces["ethernet1/3"].mode == "virtual-wire"
    assert interfaces["ethernet1/4"].mode == "tap"
    assert interfaces["ae1"].interface_family == "aggregate-ethernet"
    assert units["ethernet1/1.10"].parent == "ethernet1/1"
    assert units["ethernet1/1.10"].tag == "10"
    assert units["ethernet1/1.10"].ipv4_addresses == ["10.10.10.1/24"]
    assert units["ethernet1/2.20"].raw_extra == {"future-l2": "keep-l2"}
    assert config.interface_imports[0].scope.name == "vsys1"
    assert config.interface_imports[0].interfaces == ["ethernet1/1", "ethernet1/2.20"]


def test_interfaces_preserve_integrated_firewall_scope_and_families():
    from fwmigrate.vendors.palo_alto.source_builder import build_panos_config

    fixture = Path(__file__).parents[2] / "fixtures" / "palo_alto" / "integrated_firewall.xml"
    config = build_panos_config(fixture.read_text())
    by_name = {item.name: item for item in config.interfaces if item.name}

    assert by_name["ae1"].interface_family == "aggregate-ethernet"
    assert by_name["ethernet1/1"].scope.kind == "device"
    assert config.interface_imports[0].interfaces == ["ethernet1/1", "ae1"]


def test_nat_models_preserve_nested_translation_variants():
    from fwmigrate.vendors.palo_alto.source_builder import build_panos_config

    fixture = Path(__file__).parents[2] / "fixtures" / "palo_alto" / "nat_pipeline_conformance.xml"
    config = build_panos_config(fixture.read_text())
    rules = {item.name: item for item in config.nat_rules if item.name}

    assert rules["dipp-pool-rule"].source_translation.translated_addresses == ["dipp-pool"]
    assert rules["dipp-interface-rule"].source_translation.interface == "ethernet1/1"
    assert rules["dipp-interface-rule"].source_translation.ip == "203.0.113.1/24"
    assert rules["static-twice-rule"].source_translation.translated_address == "198.51.100.10"
    assert rules["static-twice-rule"].source_translation.bi_directional == "yes"
    assert rules["static-twice-rule"].destination_translation.translated_address == "web-server"
    assert rules["dynamic-dnat-rule"].dynamic_destination_translation.translated_addresses == ["web-servers"]
    assert rules["dynamic-dnat-rule"].dynamic_destination_translation.distribution == "round-robin"
    assert rules["dynamic-dnat-rule"].dynamic_destination_translation.dns_rewrite.direction == "reverse"
    assert rules["translated-port-rule"].destination_translation.translated_port == "8443"
    assert rules["disabled-no-translation"].disabled == "yes"
    assert rules["disabled-no-translation"].source_translation is None
    assert rules["disabled-no-translation"].destination_translation is None
    assert rules["disabled-no-translation"].dynamic_destination_translation is None


def test_routing_models_preserve_virtual_router_hierarchy():
    from fwmigrate.vendors.palo_alto.source_builder import build_panos_config

    fixture = Path(__file__).parents[2] / "fixtures" / "palo_alto" / "dynamic_routing.xml"
    config = build_panos_config(fixture.read_text())
    routers = {item.name: item for item in config.virtual_routers if item.name}

    assert routers["vr-a"].bgp.router_id == "10.0.0.1"
    assert routers["vr-a"].bgp.local_as == "65001"
    assert routers["vr-a"].bgp.peer_groups[0].name == "transit"
    assert routers["vr-a"].bgp.peer_groups[0].peers[0].peer_as == "65002"
    assert routers["vr-a"].bgp.peer_groups[0].peers[0].peer_address == "192.0.2.2"
    assert routers["vr-a"].ospf.areas[0].interfaces[0].metric == "10"
    assert routers["vr-a"].ospf.areas[0].interfaces[0].bfd_profile == "rapid-bfd"
    assert routers["vr-a"].ospfv3.areas[0].interfaces[0].cost == "20"
    assert routers["vr-a"].rip.interfaces[0].name == "ethernet1/4"
    assert routers["vr-a"].raw_extra == {}


def test_routing_models_preserve_static_routes_and_logical_router_vrfs():
    from fwmigrate.vendors.palo_alto.source_builder import build_panos_config

    fixture = Path(__file__).parents[2] / "fixtures" / "palo_alto" / "integrated_firewall.xml"
    config = build_panos_config(fixture.read_text())
    router = config.virtual_routers[0]
    route = router.static_routes[0]

    assert route.destination == "0.0.0.0/0"
    assert route.nexthop_ip_address == "192.0.2.2"
    assert route.metric == "10"
    assert config.virtual_routers[0].interfaces == ["ethernet1/1", "ae1"]

    dynamic = build_panos_config((Path(__file__).parents[2] / "fixtures" / "palo_alto" / "dynamic_routing.xml").read_text())
    assert dynamic.logical_routers[0].vrfs[0].name == "vrf-a"
    assert dynamic.logical_routers[0].vrfs[0].routing_protocol["bgp"]["router-id"] == "10.255.0.1"
