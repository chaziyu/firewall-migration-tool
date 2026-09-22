from pathlib import Path

from fwmigrate.vendors.palo_alto.native import build_derived_views
from fwmigrate.vendors.palo_alto.source_builder import build_panos_config


FIXTURES = Path(__file__).parents[2] / "fixtures" / "palo_alto"


def test_relationship_views_preserve_source_and_extract_firewall_topology():
    config = build_panos_config((FIXTURES / "integrated_firewall.xml").read_text())
    before = config.model_dump(mode="json")
    derived = build_derived_views(config)

    assert config.model_dump(mode="json") == before
    assert {zone.name for zone in config.zones} == {"trust", "untrust"}
    assert any(item.status == "RESOLVED" and item.reference_name == "strict-profiles" for item in derived.reference_resolutions)
    ethernet = next(item for item in derived.interface_topology if item.interface == "ethernet1/1")
    assert ethernet.imported_vsys == ("vsys1",)
    assert ethernet.zones == ("trust",)
    assert ethernet.virtual_routers == ("vr-main",)
    assert derived.nat[0].source_translation_mode == "PANDynamicIPAndPortTranslation"


def test_panorama_shadowing_and_effective_order_are_explicitly_ambiguous():
    config = build_panos_config((FIXTURES / "integrated_panorama.xml").read_text())
    derived = build_derived_views(config)

    assert any(item.family == "address" and item.name == "shadowed" for item in derived.shadowing)
    assert any(item.status == "AMBIGUOUS" and item.reference_name == "shadowed" for item in derived.reference_resolutions)
    child_order = [item for item in derived.policy_order if item.target_scope.endswith(":child:device:panorama")]
    assert [item.rule_name for item in child_order[:3]] == ["shared-pre", "parent-pre", "child-pre"]


def test_derived_views_are_non_mutating_for_required_fixtures():
    for name in ("integrated_panorama.xml", "integrated_firewall.xml", "phase94_production.xml"):
        config = build_panos_config((FIXTURES / name).read_text())
        before = config.model_dump(mode="json")
        build_derived_views(config)
        assert config.model_dump(mode="json") == before
