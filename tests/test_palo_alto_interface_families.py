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
            <netflow-profile>nf-l2</netflow-profile>
            <lldp><enable>yes</enable><profile>edge-lldp</profile></lldp>
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
    assert parent.source_netflow_profile == "nf-l2"
    assert parent.source_lldp_enabled == "yes"
    assert parent.source_attributes["pan_interface_mode"] == "layer2"
    assert parent.source_attributes["pan_layer2_lldp"]["profile"] == "edge-lldp"

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
        <entry name="ethernet1/2"><tap><comment>tap leg</comment><netflow-profile>tap-nf</netflow-profile></tap></entry>
        <entry name="ethernet1/4"><ha><comment>ha leg</comment><lacp><enable>yes</enable></lacp></ha></entry>
      </ethernet></interface>
    """)

    interfaces = {item.name: item for item in result.canonical_ir.interfaces}
    assert set(interfaces) == {"ethernet1/1", "ethernet1/2", "ethernet1/4"}
    assert interfaces["ethernet1/1"].source_attributes["pan_interface_mode"] == "virtual-wire"
    assert interfaces["ethernet1/2"].source_attributes["pan_interface_mode"] == "tap"
    assert interfaces["ethernet1/4"].source_attributes["pan_interface_mode"] == "ha"
    assert interfaces["ethernet1/1"].description == "vwire leg"
    assert interfaces["ethernet1/2"].description == "tap leg"
    assert interfaces["ethernet1/2"].source_netflow_profile == "tap-nf"
    assert interfaces["ethernet1/4"].source_attributes["pan_ha_lacp_fields"]["enable"] == "yes"
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
    assert interface.source_attributes["pan_sdwan_unknown_fields"]["protocol"] == "ipv4"

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


def test_layer3_ipv6_nd_ra_and_dhcpv6_are_extracted_without_ipv4_flattening():
    _, result = _extract("""
      <interface><ethernet><entry name="ethernet1/8"><layer3>
        <ipv6>
          <enabled>yes</enabled>
          <interface-id>EUI-64</interface-id>
          <address>
            <entry name="2001:db8:8::1/64"><enable-on-interface>yes</enable-on-interface></entry>
            <entry name="2001:db8:8::2/64"><enable>no</enable></entry>
          </address>
          <neighbor-discovery>
            <enable-dad>yes</enable-dad>
            <dad-attempts>3</dad-attempts>
            <router-advertisement>
              <enable>yes</enable>
              <managed-flag>yes</managed-flag>
              <other-flag>no</other-flag>
              <hop-limit>64</hop-limit>
            </router-advertisement>
          </neighbor-discovery>
          <dhcp-client>
            <enable>yes</enable>
            <accept-ra-route>yes</accept-ra-route>
            <default-route-metric>10</default-route-metric>
            <v6-options><rapid-commit>yes</rapid-commit><duid-type>duid-type-llt</duid-type></v6-options>
          </dhcp-client>
        </ipv6>
      </layer3></entry></ethernet></interface>
    """)

    interface = _interface(result, "ethernet1/8")
    attrs = interface.source_attributes

    assert interface.ip is None
    assert interface.ipv6_address == "2001:db8:8::1/64"
    assert interface.source_ipv6_address == "2001:db8:8::1/64"
    assert interface.source_ipv6_interface_identifier == "EUI-64"
    assert interface.source_ipv6_send_adv == "yes"
    assert interface.source_ipv6_manage_flag == "yes"
    assert interface.source_ipv6_other_flag == "no"
    assert [item.address for item in interface.additional_ipv6_addresses] == ["2001:db8:8::2/64"]
    assert attrs["pan_ipv6_addresses"][0]["enable"] == "yes"
    assert attrs["pan_ipv6_addresses"][0]["enable_on_interface"] == "yes"
    assert attrs["pan_ipv6_neighbor_discovery_local"]["enable_dad"] == "yes"
    assert attrs["pan_ipv6_neighbor_discovery_local"]["router_advertisement"]["hop_limit"] == "64"
    assert attrs["pan_ipv6_dhcp_client"]["enable"] == "yes"
    assert attrs["pan_ipv6_dhcp_client"]["v6_options"]["rapid_commit"] == "yes"
    assert _inventory(result, "ethernet1/8").status == ExtractionStatus.PARTIALLY_NORMALIZED


def test_layer2_vlan_and_vlan_virtual_interface_relationships_are_correlated():
    _, result = _extract("""
      <interface>
        <ethernet><entry name="ethernet1/3"><layer2><units>
          <entry name="ethernet1/3.20"><tag>20</tag></entry>
        </units></layer2></entry></ethernet>
        <vlan><units><entry name="vlan.20"><ip><entry name="10.20.0.1/24"/></ip></entry></units></vlan>
      </interface>
      <vlan><entry name="users-vlan">
        <interface><member>ethernet1/3.20</member></interface>
        <virtual-interface><interface>vlan.20</interface></virtual-interface>
      </entry></vlan>
    """)

    l2 = _interface(result, "ethernet1/3.20")
    svi = _interface(result, "vlan.20")
    assert l2.source_attributes["pan_layer2_vlans"] == ["users-vlan"]
    assert svi.source_attributes["pan_vlan_virtual_interface_for"] == ["users-vlan"]
    assert _inventory(result, "ethernet1/3.20").source_attributes["pan_layer2_vlans"] == ["users-vlan"]


def test_virtual_wire_subinterface_and_external_virtual_wire_relationship_are_preserved():
    _, result = _extract("""
      <interface><ethernet>
        <entry name="ethernet1/1"><virtual-wire><units>
          <entry name="ethernet1/1.100">
            <tag>100</tag>
            <netflow-profile>vwire-nf</netflow-profile>
            <ip-classifier><member>192.0.2.0/24</member><member>198.51.100.0/24</member></ip-classifier>
          </entry>
        </units></virtual-wire></entry>
        <entry name="ethernet1/2"><virtual-wire/></entry>
      </ethernet></interface>
      <virtual-wire><entry name="inline-vwire">
        <interface1>ethernet1/1.100</interface1>
        <interface2>ethernet1/2</interface2>
      </entry></virtual-wire>
    """)

    unit = _interface(result, "ethernet1/1.100")
    peer = _interface(result, "ethernet1/2")
    assert unit.parent == "ethernet1/1"
    assert unit.vlanid == 100
    assert unit.source_netflow_profile == "vwire-nf"
    assert unit.source_attributes["pan_virtual_wire_ip_classifiers"] == ["192.0.2.0/24", "198.51.100.0/24"]
    assert unit.source_attributes["pan_virtual_wires"] == [{"name": "inline-vwire", "role": "interface1"}]
    assert peer.source_attributes["pan_virtual_wires"] == [{"name": "inline-vwire", "role": "interface2"}]


def test_aggregate_ethernet_lacp_and_physical_link_fields_are_preserved():
    _, result = _extract("""
      <interface><aggregate-ethernet>
        <entry name="ae1">
          <link-state>auto</link-state>
          <link-speed>10000</link-speed>
          <link-duplex>full</link-duplex>
          <lacp><enable>yes</enable><mode>active</mode><transmission-rate>fast</transmission-rate></lacp>
          <layer3><ip><entry name="10.1.0.1/24"/></ip></layer3>
        </entry>
      </aggregate-ethernet></interface>
    """)

    interface = _interface(result, "ae1")
    attrs = interface.source_attributes
    assert interface.interface_type == "aggregate-ethernet"
    assert interface.source_link_state == "auto"
    assert interface.source_speed == "10000"
    assert interface.source_duplex == "full"
    assert attrs["pan_lacp_fields"]["enable"] == "yes"
    assert attrs["pan_lacp_fields"]["mode"] == "active"
    assert attrs["pan_lacp_fields"]["transmission_rate"] == "fast"


def test_pppoe_password_source_evidence_is_redacted():
    _, result = _extract("""
      <interface><ethernet><entry name="ethernet1/9"><layer3>
        <pppoe>
          <enable>yes</enable>
          <username>branch-user</username>
          <password>super-secret</password>
        </pppoe>
      </layer3></entry></ethernet></interface>
    """)

    interface = _interface(result, "ethernet1/9")
    attrs = interface.source_attributes
    assert interface.addressing_mode == "pppoe"
    assert attrs["pan_pppoe_fields"]["username"] == "branch-user"
    assert attrs["pan_pppoe"]["pppoe"]["password"] == "[REDACTED]"
    assert "super-secret" not in str(attrs)
