from fwmigrate.core.registry import PluginRegistry
from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.palo_alto.source_model import PANScope


def _extract(network_xml: str, vsys_xml: str = ""):
    parser = PluginRegistry.get_parser("palo_alto")
    xml = f"""
    <config version="11.1.0">
      <devices><entry name="localhost.localdomain">
        <network>{network_xml}</network>
      </entry></devices>
      {vsys_xml}
    </config>
    """
    return parser, parser.extract(xml)


def _interface(result, name: str):
    return next(item for item in result.canonical_ir.interfaces if item.name == name)


def _inventory(result, name: str):
    return next(
        item for item in result.inventory_items
        if item.domain == "interfaces" and item.name == name
    )


def test_unconfigured_physical_interface_is_canonical_and_resolvable():
    parser, result = _extract("""
      <interface><ethernet>
        <entry name="ethernet1/7">
          <comment>spare uplink</comment>
          <link-state>down</link-state>
          <mtu>1400</mtu>
          <lldp><enable>yes</enable></lldp>
        </entry>
      </ethernet></interface>
    """)

    interface = _interface(result, "ethernet1/7")
    assert interface.interface_type == "ethernet"
    assert interface.description == "spare uplink"
    assert interface.source_mtu == 1400
    assert interface.source_link_state == "down"
    assert interface.source_lldp_enabled == "yes"
    assert interface.status is False
    assert interface.source_attributes["pan_interface_mode"] == "unconfigured"
    assert interface.source_attributes["pan_interface_family"] == "ethernet"

    resolved = parser.resolver.resolve(
        "ethernet1/7",
        "interface",
        PANScope(kind="device", name="localhost.localdomain"),
    )
    assert resolved is not None
    assert resolved.ir_object is interface

    record = _inventory(result, "ethernet1/7")
    assert record.status == ExtractionStatus.PARTIALLY_NORMALIZED
    assert record.requires_manual_review is True


def test_layer2_physical_and_subinterface_are_canonical():
    _, result = _extract("""
      <interface><ethernet>
        <entry name="ethernet1/3">
          <comment>switch-facing</comment>
          <layer2>
            <interface-management-profile>mgmt-prof</interface-management-profile>
            <mtu>1500</mtu>
            <units>
              <entry name="ethernet1/3.20">
                <tag>20</tag>
                <comment>users vlan</comment>
              </entry>
            </units>
          </layer2>
        </entry>
      </ethernet></interface>
    """)

    parent = _interface(result, "ethernet1/3")
    unit = _interface(result, "ethernet1/3.20")

    assert parent.interface_type == "ethernet"
    assert parent.description == "switch-facing"
    assert parent.management_profile == "mgmt-prof"
    assert parent.source_mtu == 1500
    assert parent.source_attributes["pan_interface_mode"] == "layer2"

    assert unit.interface_type == "ethernet-subinterface"
    assert unit.parent == "ethernet1/3"
    assert unit.vlanid == 20
    assert unit.description == "users vlan"
    assert unit.source_attributes["pan_interface_mode"] == "layer2-subinterface"
    assert unit.source_attributes["pan_interface_unit_name"] == "ethernet1/3.20"

    assert _inventory(result, "ethernet1/3").status == ExtractionStatus.PARTIALLY_NORMALIZED
    assert _inventory(result, "ethernet1/3.20").status == ExtractionStatus.PARTIALLY_NORMALIZED


def test_non_layer3_physical_modes_are_not_lost_from_canonical_ir():
    _, result = _extract("""
      <interface><ethernet>
        <entry name="ethernet1/1"><virtual-wire><comment>vwire leg</comment></virtual-wire></entry>
        <entry name="ethernet1/2"><tap><comment>tap leg</comment></tap></entry>
        <entry name="ethernet1/4"><ha><comment>ha leg</comment></ha></entry>
      </ethernet></interface>
    """)

    interfaces = {item.name: item for item in result.canonical_ir.interfaces}
    assert set(interfaces) == {"ethernet1/1", "ethernet1/2", "ethernet1/4"}
    assert interfaces["ethernet1/1"].source_attributes["pan_interface_mode"] == "virtual-wire"
    assert interfaces["ethernet1/2"].source_attributes["pan_interface_mode"] == "tap"
    assert interfaces["ethernet1/4"].source_attributes["pan_interface_mode"] == "ha"
    assert interfaces["ethernet1/1"].description == "vwire leg"
    assert interfaces["ethernet1/2"].description == "tap leg"
    assert interfaces["ethernet1/4"].description == "ha leg"
    assert all(item.requires_manual_review for item in interfaces.values())


def test_sdwan_unit_is_canonical_with_ordered_members_and_metadata():
    parser, result = _extract("""
      <interface>
        <sdwan><units>
          <entry name="sdwan.10">
            <comment>branch fabric</comment>
            <cluster-name>cluster-a</cluster-name>
            <link-tag><member>primary</member><member>backup</member></link-tag>
            <interface><member>ethernet1/1</member><member>ethernet1/2</member></interface>
            <protocol>ipv4</protocol>
          </entry>
        </units></sdwan>
      </interface>
    """)

    interface = _interface(result, "sdwan.10")
    assert interface.interface_type == "sdwan"
    assert interface.description == "branch fabric"
    assert interface.members == ["ethernet1/1", "ethernet1/2"]
    assert interface.source_attributes["pan_interface_family"] == "sdwan"
    assert interface.source_attributes["pan_interface_mode"] == "sdwan-unit"
    assert interface.source_attributes["pan_interface_unit_name"] == "sdwan.10"
    assert interface.source_attributes["pan_sdwan_cluster_name"] == "cluster-a"
    assert interface.source_attributes["pan_sdwan_link_tags"] == ["primary", "backup"]
    assert interface.source_attributes["pan_sdwan_protocol"] == "ipv4"

    resolved = parser.resolver.resolve(
        "sdwan.10",
        "interface",
        PANScope(kind="device", name="localhost.localdomain"),
    )
    assert resolved is not None
    assert resolved.ir_object is interface
    assert _inventory(result, "sdwan.10").status == ExtractionStatus.PARTIALLY_NORMALIZED


def test_loopback_tunnel_and_vlan_unit_identity_is_preserved():
    _, result = _extract("""
      <interface>
        <loopback><units><entry name="loopback.1"><ip><entry name="192.0.2.1/32"/></ip></entry></units></loopback>
        <tunnel><units><entry name="tunnel.5"><ip><entry name="198.51.100.1/32"/></ip></entry></units></tunnel>
        <vlan><units><entry name="vlan.30"><ip><entry name="203.0.113.1/24"/></ip></entry></units></vlan>
      </interface>
    """)

    loopback = _interface(result, "loopback.1")
    tunnel = _interface(result, "tunnel.5")
    vlan = _interface(result, "vlan.30")

    assert loopback.interface_type == "loopback"
    assert loopback.source_attributes["pan_interface_family"] == "loopback"
    assert loopback.source_attributes["pan_interface_unit_name"] == "loopback.1"
    assert tunnel.interface_type == "tunnel"
    assert tunnel.source_attributes["pan_interface_family"] == "tunnel"
    assert tunnel.source_attributes["pan_interface_unit_name"] == "tunnel.5"
    assert vlan.interface_type == "vlan"
    assert vlan.source_attributes["pan_interface_family"] == "vlan"
    assert vlan.source_attributes["pan_interface_unit_name"] == "vlan.30"
