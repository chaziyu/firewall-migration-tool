from pathlib import Path

from fwmigrate.vendors.palo_alto.model import PANInterface, PANInterfaceImport
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
