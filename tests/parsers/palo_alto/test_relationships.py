from pathlib import Path

from fwmigrate.vendors.palo_alto.native import build_derived_views
from fwmigrate.vendors.palo_alto.source_builder import build_panos_config
from fwmigrate.vendors.palo_alto.validation import validate_panos_config


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
    assert derived.nat[0].source_translation_mode == "dynamic-ip-and-port"


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


def test_literals_predefined_services_tags_and_interface_units_are_classified_from_source():
    config = build_panos_config("""<config><devices><entry name='fw'><network><interface><tunnel><units><entry name='tunnel.1'/></units></tunnel></interface></network>
      <vsys><entry name='vsys1'><tag><entry name='production'><color>color1</color><comments>keep</comments></entry></tag>
      <import><network><interface><member>tunnel.1</member></interface></network></import>
      <rulebase><security><rules><entry name='allow'><from><member>any</member></from><to><member>any</member></to>
      <source><member>72.5.65.111/32</member><member>::1</member><member>panw-highrisk-ip-list</member><member>panw-known-ip-list</member><member>MY</member><member>unknown-address</member></source><destination><member>any</member></destination>
      <service><member>service-http</member><member>service-https</member><member>unknown-service</member></service>
      <application><member>any</member></application><tag><member>production</member></tag><action>allow</action></entry></rules></security></rulebase>
      </entry></vsys></entry></devices></config>""")

    derived = build_derived_views(config)
    status = {(item.owner_field, item.reference_name): item.status for item in derived.reference_resolutions}

    assert config.tags[0].name == "production"
    assert config.tags[0].comments == "keep"
    assert status[("tags", "production")] == "RESOLVED"
    assert status[("source", "72.5.65.111/32")] == "SOURCE_ONLY"
    assert status[("source", "::1")] == "SOURCE_ONLY"
    assert status[("source", "panw-highrisk-ip-list")] == "SOURCE_ONLY"
    assert status[("source", "panw-known-ip-list")] == "SOURCE_ONLY"
    assert status[("source", "MY")] == "SOURCE_ONLY"
    assert status[("source", "unknown-address")] == "UNRESOLVED"
    assert status[("service", "service-http")] == "SOURCE_ONLY"
    assert status[("service", "service-https")] == "SOURCE_ONLY"
    assert status[("service", "unknown-service")] == "UNRESOLVED"
    tunnel = next(item for item in derived.interface_topology if item.interface == "tunnel.1")
    assert tunnel.imported_vsys == ("vsys1",)
    assert "import of missing interface" not in tunnel.issues


def test_vsys_interface_imports_use_device_ownership_and_report_real_missing_imports():
    config = build_panos_config("""<config><devices><entry name='fw'><network><interface><ethernet>
      <entry name='ethernet1/1'/><entry name='ethernet1/2'/></ethernet><tunnel><units><entry name='tunnel.1'/></units></tunnel>
      </interface></network><vsys><entry name='vsys1'><import><network><interface>
      <member>ethernet1/1</member><member>tunnel.1</member><member>ethernet1/99</member>
      </interface></network></import></entry></vsys></entry></devices></config>""")
    before = config.model_dump(mode="json")
    derived = build_derived_views(config)

    assert config.model_dump(mode="json") == before
    assert not any(item.message == "imported interface was not found in device network configuration" and item.source_name != "ethernet1/99" for item in derived.relationship_issues)
    missing = [item for item in derived.relationship_issues if item.source_name == "ethernet1/99"]
    assert len(missing) == 1
    assert missing[0].field == "interfaces"
    validation = validate_panos_config(config, derived)
    warnings = [item for item in validation.warnings if item.source_name == "ethernet1/99"]
    assert len(warnings) == 1
    assert warnings[0].scope_identity.endswith(":device:fw")
