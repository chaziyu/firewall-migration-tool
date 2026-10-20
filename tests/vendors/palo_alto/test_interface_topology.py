from fwmigrate.vendors.palo_alto.native import build_derived_views
from fwmigrate.vendors.palo_alto.source_builder import build_panos_config
from fwmigrate.vendors.palo_alto.source_model import pan_scope_identity

import pytest


def test_interfaces_preserve_parent_aggregate_and_tunnel_relationships():
    source = """<config><devices><entry name='fw'><network><interface>
      <ethernet><entry name='ethernet1/1'><layer3><aggregate-group>ae1</aggregate-group><units><entry name='ethernet1/1.10'/></units></layer3></entry></ethernet>
      <aggregate-ethernet><entry name='ae1'><layer3/></entry></aggregate-ethernet><tunnel><units><entry name='tunnel.1'/></units></tunnel>
      <ipsec><entry name='vpn'><tunnel-interface>tunnel.1</tunnel-interface></entry></ipsec>
    </interface></network></entry></devices></config>"""
    config = build_panos_config(source)
    topology = build_derived_views(config).interface_topology
    by_interface = {item.interface: item for item in topology}
    scope = config.interfaces[0].scope
    assert by_interface["ethernet1/1.10"].parent == "ethernet1/1"
    assert by_interface["ethernet1/1.10"].scope == by_interface["ethernet1/1"].scope
    assert by_interface["ethernet1/1"].aggregate == "ae1"
    assert by_interface["tunnel.1"].attached_tunnels == ("vpn",)
    assert scope is not None and by_interface["ethernet1/1"].scope == pan_scope_identity(scope)


@pytest.mark.parametrize("router_import, warning", [("", False), ("<virtual-router/>", True),
    ("<virtual-router><member>other</member></virtual-router>", True),
    ("<virtual-router><member>vr</member></virtual-router>", False)])
def test_absent_router_import_is_unknown_but_explicit_exclusion_is_reported(router_import, warning):
    source = f"""<config><devices><entry name="fw"><network>
      <interface><ethernet><entry name="ethernet1/1"><layer3/></entry></ethernet></interface>
      <virtual-router><entry name="vr"><interface><member>ethernet1/1</member></interface></entry></virtual-router>
      </network><vsys><entry name="vsys1"><import><network><interface><member>ethernet1/1</member></interface>
      {router_import}</network></import></entry></vsys></entry></devices></config>"""
    config = build_panos_config(source)
    before = config.model_dump()
    topology = build_derived_views(config).interface_topology[0]
    assert ("virtual-router member is not imported into this VSYS" in topology.issues) is warning
    assert topology.virtual_routers == ("vr",)
    assert config.model_dump() == before
