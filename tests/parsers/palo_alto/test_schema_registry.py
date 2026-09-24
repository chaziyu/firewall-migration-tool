import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
from pydantic import BaseModel

from fwmigrate.vendors.palo_alto.extraction.common import source_fields
from fwmigrate.vendors.palo_alto.extraction.extractor import extract_typed
from fwmigrate.vendors.palo_alto.schema_registry import (
    PANPathSpec,
    get_path_spec,
    match_path_spec,
    register_path,
    registered_paths,
)
from fwmigrate.vendors.palo_alto.source_context import PANWalkContext


EXPECTED_PATHS = {
    "address",
    "address_group",
    "default_security_rule",
    "interface_aggregate-ethernet",
    "interface_ethernet",
    "interface_import",
    "interface_loopback",
    "interface_tunnel",
    "interface_unit",
    "ipsec_tunnel",
    "virtual_router_import",
    "interface_vlan",
    "logical_router",
    "nat_rule",
    "schedule",
    "security_profile_group",
    "security_rule",
    "service",
    "service_group",
    "tag",
    "virtual_router",
    "zone",
    "vulnerability_profile", "administrator", "admin_role", "ike_gateway", "ike_crypto_profile",
    "ipsec_crypto_profile", "dhcp_server", "dhcp_interface", "sdwan_interface_profile",
    "sdwan_path_quality_profile", "sdwan_traffic_distribution_profile", "sdwan_saas_quality_profile",
    "sdwan_error_correction_profile", "sdwan_rule", "local_user", "local_user_database",
    "sdwan_interface_profile_cli", "sdwan_path_quality_profile_cli",
    "sdwan_traffic_distribution_profile_cli", "sdwan_saas_quality_profile_cli",
    "sdwan_error_correction_profile_cli",
    "local_user_group", "local_user_group_compat", "local_user_database_compat", "group_mapping",
    "globalprotect_portal", "globalprotect_gateway", "globalprotect_portal_selected",
    "globalprotect_gateway_selected", "administrator_mgt_config",
}


def test_expected_paths_are_registered():
    assert set(registered_paths()) == EXPECTED_PATHS


def test_duplicate_registration_is_rejected_without_mutating_the_registry():
    before = registered_paths()

    with pytest.raises(ValueError, match="already registered"):
        register_path(PANPathSpec("address", ("new-address", "entry")))
    with pytest.raises(ValueError, match="suffix already registered"):
        register_path(PANPathSpec("new-address", ("address", "entry")))

    assert registered_paths() == before


@pytest.mark.parametrize(
    ("left", "right"),
    [
        ("scalar_fields", "member_list_fields"),
        ("scalar_fields", "entry_list_fields"),
        ("scalar_fields", "nested_fields"),
        ("member_list_fields", "entry_list_fields"),
        ("member_list_fields", "nested_fields"),
        ("entry_list_fields", "nested_fields"),
    ],
)
def test_field_category_overlap_is_rejected(left, right):
    fields = {left: frozenset({"duplicate"}), right: frozenset({"duplicate"})}

    with pytest.raises(ValueError, match="incompatible categories"):
        PANPathSpec("invalid", ("invalid", "entry"), **fields)


def test_field_mapping_is_deterministic_and_immutable():
    spec = get_path_spec("address")

    assert spec is not None
    assert tuple(spec.field_map.items()) == (
        ("ip-netmask", "ip_netmask"),
        ("ip-range", "ip_range"),
        ("ip-wildcard", "ip_wildcard"),
        ("tag", "tags"),
    )
    with pytest.raises(TypeError):
        spec.field_map["fqdn"] = "fqdn"


@pytest.mark.parametrize(
    "path",
    [
        ("config", "shared", "address", "entry"),
        ("config", "devices", "entry", "vsys", "entry", "address", "entry"),
        ("config", "devices", "entry", "device-group", "entry", "address", "entry"),
    ],
)
def test_suffix_matching_works_in_supported_scopes(path):
    assert match_path_spec(path).name == "address"


@pytest.mark.parametrize(
    "path",
    [
        ("config", "shared", "address", "entry", "future", "entry"),
        ("config", "shared", "address", "entry", "future", "address", "entry"),
    ],
)
def test_nested_entries_do_not_match_top_level_specs(path):
    assert match_path_spec(path) is None


def test_interface_import_matches_without_an_entry_element():
    spec = match_path_spec(("config", "devices", "entry", "vsys", "entry", "import", "network", "interface"))

    assert spec is not None
    assert spec.name == "interface_import"


def test_registry_contains_only_source_shape_metadata():
    assert set(PANPathSpec.__dataclass_fields__) == {
        "name",
        "path_suffix",
        "scalar_fields",
        "member_list_fields",
        "entry_list_fields",
        "nested_fields",
        "field_map",
        "allowed_scope_kinds",
    }


def test_registry_matches_structural_suffixes_and_preserves_model_field_names():
    spec = match_path_spec(("config", "shared", "address", "entry"))
    assert spec is not None
    assert spec.name == "address"
    assert "address" in registered_paths()

    extra, explicit = source_fields(
        ET.fromstring("<entry name='web'><ip-netmask>192.0.2.1/32</ip-netmask><future>keep</future></entry>"),
        spec,
    )
    assert "ip_netmask" in explicit
    assert extra["future"] == "keep"


def test_orchestrator_dispatches_only_the_registered_domain():
    element = ET.fromstring("<entry name='web'><fqdn>web.example.test</fqdn></entry>")
    result = extract_typed(element, ("config", "shared", "address", "entry"), PANWalkContext(), 1)
    assert result is not None
    assert result[0] == "addresses"
    assert result[1].name == "web"


def test_fixture_explicit_fields_use_model_names_only():
    from fwmigrate.vendors.palo_alto.source_builder import build_panos_config

    def check(value):
        if isinstance(value, BaseModel):
            explicit = getattr(value, "explicit_fields", set())
            assert not explicit & {"name", "scope", "source_path", "source_order", "rulebase_position"}
            assert not any("-" in field for field in explicit)
            assert explicit <= set(type(value).model_fields)
            for child in value.__dict__.values():
                check(child)
        elif isinstance(value, dict):
            for child in value.values():
                check(child)
        elif isinstance(value, (list, tuple)):
            for child in value:
                check(child)

    fixture_dir = Path(__file__).parents[2] / "fixtures" / "palo_alto"
    for fixture in fixture_dir.glob("*.xml"):
        check(build_panos_config(fixture.read_text()))


def test_registry_declares_nested_source_shapes_for_phase_schemas():
    service = match_path_spec(("config", "shared", "service", "entry"))
    schedule = match_path_spec(("config", "shared", "schedule", "entry"))
    group = match_path_spec(("config", "shared", "address-group", "entry"))

    assert {"protocol/tcp", "protocol/udp", "protocol/*/port"} <= service.nested_fields
    assert {"schedule-type/recurring", "schedule-type/non-recurring"} <= schedule.nested_fields
    assert {"static", "dynamic"} <= group.nested_fields
    assert not group.entry_list_fields


def test_default_policy_conflicts_preserve_both_source_locations():
    from fwmigrate.vendors.palo_alto.source_builder import build_panos_config

    config = build_panos_config(
        "<config><shared><default-security-rules><rules><entry name='conflict'><disable-server-response-inspection>yes</disable-server-response-inspection><option><disable-server-response-inspection>no</disable-server-response-inspection></option></entry></rules></default-security-rules></shared></config>"
    )
    rule = config.default_security_rules[0]
    assert rule.disable_server_response_inspection is None
    assert rule.raw_extra["conflicting-source-fields"]["disable-server-response-inspection"]["option"]["disable-server-response-inspection"] == "no"


def test_phase_ten_and_eleven_registry_shapes_are_structural():
    interface = match_path_spec(("config", "devices", "entry", "network", "interface", "ethernet", "entry"))
    nat = match_path_spec(("config", "vsys", "entry", "rulebase", "nat", "rules", "entry"))

    assert interface.name == "interface_ethernet"
    assert {"layer3", "layer2", "virtual-wire", "tap", "ha", "decrypt-mirror"} <= interface.nested_fields
    assert {"from", "to", "source", "destination"} <= nat.member_list_fields
    assert "source-translation/dynamic-ip-and-port" in nat.nested_fields


def test_routing_registry_owns_router_roots_only():
    paths = registered_paths()
    assert "virtual_router" in paths
    assert "logical_router" in paths
    assert not any(name.startswith("static_route") for name in paths)


def test_routing_extracts_nested_order_and_source_shapes():
    from pathlib import Path
    from fwmigrate.vendors.palo_alto.source_builder import build_panos_config

    fixture_dir = Path(__file__).parents[2] / "fixtures" / "palo_alto"
    dynamic = build_panos_config((fixture_dir / "dynamic_routing.xml").read_text())
    router = dynamic.virtual_routers[0]
    peer = router.bgp.peer_groups[0].peers[0]
    area = router.ospf.areas[0]
    rip_interface = router.rip.interfaces[0]

    assert peer.hold_time == "90"
    assert area.area_type == "normal"
    assert router.rip.raw_extra["timers"]["update-interval"] == "30"
    assert rip_interface.raw_extra["auth-profile"] == "rip-auth"

    integrated = build_panos_config((fixture_dir / "integrated_firewall.xml").read_text())
    assert [route.name for route in integrated.virtual_routers[0].static_routes] == ["default"]
    assert [route.name for route in integrated.static_routes] == ["default"]


def test_nested_unknowns_stay_with_the_nearest_typed_owner():
    from pathlib import Path
    from fwmigrate.vendors.palo_alto.source_builder import build_panos_config

    fixture_dir = Path(__file__).parents[2] / "fixtures" / "palo_alto"
    services = build_panos_config((fixture_dir / "services.xml").read_text())
    unknown_service = next(item for item in services.services if item.name == "Unknown-Service")
    assert unknown_service.udp.raw_extra["future-protocol"] == "value"
    assert "future-protocol" not in unknown_service.raw_extra

    routing = build_panos_config((fixture_dir / "dynamic_routing.xml").read_text())
    peer = routing.virtual_routers[0].bgp.peer_groups[0].peers[0]
    assert peer.raw_extra["future-peer-field"] == {"keep": "peer-evidence"}
    assert "future-peer-field" not in routing.virtual_routers[0].bgp.raw_extra


def test_inventory_survives_typed_extractor_failure(monkeypatch):
    import fwmigrate.vendors.palo_alto.source_builder as source_builder

    def fail(*args, **kwargs):
        raise RuntimeError("typed extraction failure")

    monkeypatch.setattr(source_builder, "extract_typed", fail)
    config = source_builder.build_panos_config(
        "<config><shared><future-policy><rules><entry name='future'><material>retain-me</material></entry></rules></future-policy></shared></config>"
    )

    assert config.source_inventory[0].name == "future"
    assert "retain-me" in config.source_inventory[0].raw_xml
    assert config.unknown_paths == ["config/shared/future-policy/rules/entry"]
