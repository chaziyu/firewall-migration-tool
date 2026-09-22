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


def test_typed_unknown_values_are_redacted():
    config = build_panos_config(
        "<config><shared><address><entry name='x'><future-password>secret-value</future-password></entry></address></shared></config>"
    )

    dumped = str(config.model_dump())
    assert "secret-value" not in dumped
    assert "[REDACTED]" in dumped
