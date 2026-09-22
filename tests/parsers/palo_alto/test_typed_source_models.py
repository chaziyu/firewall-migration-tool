from pathlib import Path

from fwmigrate.vendors.palo_alto.source_builder import build_panos_config


FIXTURES = Path(__file__).parents[2] / "fixtures" / "palo_alto"


def test_explicit_fields_distinguish_missing_empty_and_explicit_no():
    config = build_panos_config((FIXTURES / "policies.xml").read_text())
    rules = {item.name: item for item in config.security_rules if item.name}

    assert rules["Absent-Flags"].disabled is None
    assert "disabled" not in rules["Absent-Flags"].explicit_fields
    assert rules["Explicit-No"].disabled == "no"
    assert "disabled" in rules["Explicit-No"].explicit_fields

    addresses = build_panos_config((FIXTURES / "objects.xml").read_text()).addresses
    missing = next(item for item in addresses if item.name == "Missing-Type")
    assert missing.ip_netmask is None
    assert "ip-netmask" not in missing.explicit_fields


def test_address_variants_preserve_explicit_forms_and_unknown_content():
    config = build_panos_config((FIXTURES / "objects.xml").read_text())
    addresses = {item.name: item for item in config.addresses}
    groups = {item.name: item for item in config.address_groups}

    assert addresses["Missing-Type"].ip_netmask is None
    assert addresses["Missing-Type"].fqdn is None
    assert not {"ip-netmask", "fqdn"} & addresses["Missing-Type"].explicit_fields
    assert addresses["Multiple-Types"].ip_netmask == "192.0.2.30/32"
    assert addresses["Multiple-Types"].fqdn == "duplicate.example.test"
    assert {"ip-netmask", "fqdn"} <= addresses["Multiple-Types"].explicit_fields
    assert addresses["Has-Unknown"].raw_extra["future-field"] == "retain-me"
    assert groups["Unknown-Group"].raw_extra["future-setting"] == "retain-me"
    assert groups["Both-Group"].static_members == ["IPv4-Net"]
    assert groups["Both-Group"].dynamic_filter == "'production'"
    assert {"static", "dynamic"} <= groups["Both-Group"].explicit_fields


def test_service_variants_preserve_missing_ports_both_protocols_and_unknowns():
    config = build_panos_config((FIXTURES / "services.xml").read_text())
    services = {item.name: item for item in config.services}

    assert services["Missing-Port"].tcp.port is None
    assert "port" not in services["Missing-Port"].tcp.explicit_fields
    assert services["Both-Protocols"].tcp.port == "80"
    assert services["Both-Protocols"].udp.port == "80"
    assert services["Unknown-Service"].udp.raw_extra["future-protocol"] == "value"
    assert services["Unknown-Service"].raw_extra["future-setting"] == "retain-me"


def test_policy_unknown_and_missing_values_remain_source_explicit():
    config = build_panos_config((FIXTURES / "policies.xml").read_text())
    rules = {item.name: item for item in config.security_rules}

    assert rules["Explicit-No"].disabled == "no"
    assert "disabled" in rules["Explicit-No"].explicit_fields
    assert rules["Absent-Flags"].disabled is None
    assert "disabled" not in rules["Absent-Flags"].explicit_fields
    assert rules["Missing-Action"].action is None
    assert rules["Missing-Source"].source is None
    assert rules["Explicit-Any"].source == ["any"]
    assert rules["Unknown-Field"].raw_extra["future-setting"] == {"nested": "retain-me"}


def test_nat_without_translation_does_not_fabricate_translation():
    config = build_panos_config((FIXTURES / "nat_pipeline_conformance.xml").read_text())
    rule = next(item for item in config.nat_rules if item.name == "disabled-no-translation")

    assert rule.disabled == "yes"
    assert rule.source_translation is None
    assert rule.destination_translation is None
    assert rule.dynamic_destination_translation is None


def test_routing_missing_values_remain_missing():
    config = build_panos_config((FIXTURES / "dynamic_routing.xml").read_text())
    router = next(item for item in config.virtual_routers if item.name == "vr-a")
    peer = router.bgp.peer_groups[0].peers[1]
    ospfv3_interface = router.ospfv3.areas[0].interfaces[0]

    assert peer.enable is None
    assert peer.bfd_profile is None
    assert peer.hold_time is None
    assert ospfv3_interface.metric is None
    assert ospfv3_interface.bfd_profile is None


def test_unsupported_policy_family_remains_inventory_evidence():
    config = build_panos_config((FIXTURES / "policy_families.xml").read_text())

    assert any("future-policy" in item.source_path for item in config.source_inventory)
    assert all(item.source_path.find("future-policy") < 0 for item in config.security_rules)


def test_panorama_typed_objects_do_not_inherit_parent_or_shared_objects():
    config = build_panos_config((FIXTURES / "integrated_panorama.xml").read_text())
    addresses = {(item.scope.kind, item.scope.device_group, item.name) for item in config.addresses if item.scope}

    assert ("shared", None, "shared-net") in addresses
    assert ("device-group", "parent", "shadowed") in addresses
    assert ("device-group", "child", "shadowed") in addresses
    assert len([item for item in config.addresses if item.name == "shared-net"]) == 1

    scoped_objects = {(item.scope.kind, item.scope.device_group, item.name) for item in config.services if item.scope}
    assert ("shared", None, "shared-https") in scoped_objects
    assert all(not (kind == "device-group" and group == "child" and name == "shared-https") for kind, group, name in scoped_objects)
    assert len(config.addresses) == len([record for record in config.source_inventory if "/address/entry" in record.source_path])


def test_typed_unknown_values_are_redacted():
    config = build_panos_config(
        "<config><shared><address><entry name='x'><future-password>secret-value</future-password></entry></address></shared></config>"
    )

    dumped = str(config.model_dump())
    assert "secret-value" not in dumped
    assert "[REDACTED]" in dumped
