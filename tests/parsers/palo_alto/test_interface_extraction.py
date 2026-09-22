from pathlib import Path

from fwmigrate.vendors.palo_alto.model import PANInterface, PANInterfaceImport
from fwmigrate.vendors.palo_alto.native import build_derived_views
from fwmigrate.vendors.palo_alto.source_builder import build_panos_config


FIXTURES = Path(__file__).parents[2] / "fixtures" / "palo_alto"


def test_interface_families_units_and_imports_are_extracted_from_source():
    config = build_panos_config((FIXTURES / "interfaces_extended.xml").read_text())
    interfaces = {item.name: item for item in config.interfaces}
    units = {item.name: item for item in config.interface_units}

    assert interfaces["ethernet1/1"].mode == "layer3"
    assert interfaces["ethernet1/1"].ipv4_addresses == ["192.0.2.1/24", "192.0.2.10/24"]
    assert interfaces["ae1"].interface_family == "aggregate-ethernet"
    assert units["ethernet1/1.10"].parent == "ethernet1/1"
    assert units["ethernet1/2.20"].raw_extra["future-l2"] == "keep-l2"
    assert units["tunnel.1"].parent is None
    assert units["tunnel.1"].source_path.endswith("tunnel/units/entry")
    assert units["tunnel.1"].scope.kind == "device"
    assert config.interface_imports[0].interfaces == ["ethernet1/1", "ethernet1/2.20"]


def test_interface_contract_preserves_explicit_state_scope_inventory_and_redaction(assert_source_contract):
    secret = "interface-secret-value"
    config = build_panos_config(
        f"""<config><devices><entry name='fw'>
          <network><interface><ethernet>
            <entry name='ethernet1/1'><link-state>no</link-state><layer3><ip><entry name='192.0.2.1/24'/></ip><future-nested>keep-nested</future-nested><future-password>{secret}</future-password></layer3><future-field>keep</future-field></entry>
            <entry name='ethernet1/2'/>
          </ethernet></interface></network>
          <vsys><entry name='vsys1'><import><network><interface><member>ethernet1/1</member></interface></network></import></entry></vsys>
        </entry></devices></config>"""
    )
    explicit, missing = config.interfaces
    imported = config.interface_imports[0]

    assert isinstance(explicit, PANInterface)
    assert isinstance(imported, PANInterfaceImport)
    assert explicit.link_state == "no"
    assert explicit.ipv4_addresses == ["192.0.2.1/24"]
    assert missing.link_state is None
    assert explicit.raw_extra["future-field"] == "keep"
    assert explicit.raw_extra["layer3"]["future-nested"] == "keep-nested"
    assert imported.interfaces == ["ethernet1/1"]
    assert explicit.scope.kind == "device"
    assert imported.scope.kind == "vsys"
    assert_source_contract(explicit, config)
    assert secret not in str(config.model_dump())


def test_interface_topology_preserves_aggregate_units_and_ipsec_tunnel_attachment():
    config = build_panos_config("""<config><devices><entry name='fw'><network><interface>
      <ethernet><entry name='ethernet1/1'><layer3><aggregate-group>ae1</aggregate-group><units><entry name='ethernet1/1.10'/></units></layer3></entry></ethernet>
      <aggregate-ethernet><entry name='ae1'><layer3/></entry></aggregate-ethernet>
      <tunnel><units><entry name='tunnel.1'/></units></tunnel>
      <ipsec><entry name='vpn1'><tunnel-interface>tunnel.1</tunnel-interface></entry></ipsec>
    </interface></network><vsys><entry name='vsys1'><import><network><interface><member>ethernet1/1</member><member>ethernet1/1.10</member><member>tunnel.1</member></interface></network></import></entry></vsys></entry></devices></config>""")

    derived = build_derived_views(config)
    by_name = {
        (item.scope, item.interface): item
        for item in derived.interface_topology
        if item.scope.startswith("device:")
    }

    assert config.interfaces[0].aggregate_group == "ae1"
    assert config.interface_units[-1].interface_family == "tunnel"
    assert config.ipsec_tunnels[0].tunnel_interface == "tunnel.1"
    assert by_name[("device:fw:device:fw", "ethernet1/1")].aggregate == "ae1"
    assert by_name[("device:fw:device:fw", "ethernet1/1.10")].parent == "ethernet1/1"
    assert by_name[("device:fw:device:fw", "ethernet1/1.10")].path == ("ethernet1/1.10", "ethernet1/1", "ae1")
    assert by_name[("device:fw:device:fw", "tunnel.1")].attached_tunnels == ("vpn1",)
