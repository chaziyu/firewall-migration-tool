from fwmigrate.parsers.palo_alto.parser import PANOSSourceParser


def test_template_stack_materializes_one_effective_interface_with_field_provenance():
    xml = """
    <config version="12.1.0">
      <template>
        <entry name="base">
          <config><devices><entry name="localhost.localdomain">
            <network>
              <interface><ethernet><entry name="ethernet1/1"><layer3>
                <ip><entry name="192.0.2.1/24"/></ip><comment>base</comment>
              </layer3></entry></ethernet></interface>
              <virtual-router><entry name="default"><interface><member>ethernet1/1</member></interface></entry></virtual-router>
            </network>
            <vsys><entry name="vsys1">
              <import><network><interface><member>ethernet1/1</member></interface></network></import>
              <zone><entry name="trust"><network><layer3><member>ethernet1/1</member></layer3></network></entry></zone>
            </entry></vsys>
          </entry></devices></config>
        </entry>
        <entry name="override">
          <config><devices><entry name="localhost.localdomain">
            <network><interface><ethernet><entry name="ethernet1/1"><layer3>
              <ip><entry name="198.51.100.1/24"/><entry name="198.51.100.2/24"/></ip>
              <comment>override</comment><mtu>1400</mtu>
            </layer3></entry></ethernet></interface></network>
          </entry></devices></config>
        </entry>
        <entry name="last">
          <config><devices><entry name="localhost.localdomain">
            <network><interface><ethernet><entry name="ethernet1/1"><layer3><mtu>1500</mtu></layer3></entry></ethernet></interface></network>
          </entry></devices></config>
        </entry>
      </template>
      <template-stack><entry name="branch-stack">
        <templates><member>base</member><member>override</member><member>last</member></templates>
        <devices><entry name="001122334455"><vsys><entry name="vsys1"/></vsys></entry></devices>
      </entry></template-stack>
    </config>
    """

    result = PANOSSourceParser().extract(xml)
    effective = next(
        item for item in result.canonical_ir.interfaces
        if item.source_context == "template-stack:branch-stack:device:001122334455"
    )

    assert effective.ip == "198.51.100.1/24"
    assert [item.source_address for item in effective.ipv4_addresses] == [
        "198.51.100.1/24", "198.51.100.2/24"
    ]
    assert effective.source_mtu == 1500
    assert effective.source_routing_instance == "default"
    assert effective.source_attributes["pan_vsys_associations"] == ["vsys1"]
    assert effective.source_attributes["pan_template_zones"] == [{
        "vsys": "vsys1", "zone": "trust", "zone_types": ["layer3"]
    }]
    provenance = effective.source_attributes["pan_interface_provenance"]
    ip_history = next(values for path, values in provenance.items() if path.endswith("/ip"))
    assert [entry["source"] for entry in ip_history] == ["base", "override"]
    assert ip_history[-1]["overrides"] == ["base"]


def test_missing_template_stack_reference_is_parse_error_and_not_materialized():
    xml = """
    <config>
      <template><entry name="base"><network><interface><ethernet>
        <entry name="ethernet1/1"><layer3><ip><entry name="192.0.2.1/24"/></ip></layer3></entry>
      </ethernet></interface></network></entry></template>
      <template-stack><entry name="broken"><templates><member>missing</member></templates>
        <devices><entry name="FW1"/></devices>
      </entry></template-stack>
    </config>
    """

    result = PANOSSourceParser().extract(xml)

    assert not any(
        item.source_context == "template-stack:broken:device:FW1"
        for item in result.canonical_ir.interfaces
    )
    assert any(
        item.status.value == "PARSE_ERROR"
        and "missing templates" in " ".join(item.notes)
        for item in result.inventory_items
        if item.domain == "panorama_template_stacks"
    )


def test_pan_os_interface_modes_relationships_and_ordered_ipv4_are_typed():
    xml = """
    <config><devices><entry name="localhost.localdomain"><network>
      <interface><ethernet>
        <entry name="ethernet1/1"><layer2><units><entry name="ethernet1/1.20"><tag>20</tag></entry></units></layer2></entry>
        <entry name="ethernet1/2"><virtual-wire><units><entry name="ethernet1/2.30"><tag>30</tag></entry></units></virtual-wire></entry>
        <entry name="ethernet1/3"><layer3><ip><entry name="203.0.113.1/24"/><entry name="203.0.113.2/24"/></ip></layer3></entry>
      </ethernet></interface>
      <vlan><entry name="users"><interface><member>ethernet1/1.20</member></interface></entry></vlan>
      <virtual-wire><entry name="edge"><interface1>ethernet1/2</interface1><interface2>ethernet1/3</interface2></entry></virtual-wire>
    </network></entry></devices></config>
    """

    result = PANOSSourceParser().extract(xml)
    interfaces = {item.name: item for item in result.canonical_ir.interfaces}

    assert interfaces["ethernet1/1"].interface_mode.value == "layer2"
    assert interfaces["ethernet1/1.20"].interface_mode.value == "layer2-subinterface"
    assert interfaces["ethernet1/1.20"].parent == "ethernet1/1"
    assert interfaces["ethernet1/1.20"].source_vlan_relationships[0].vlan_name == "users"
    assert interfaces["ethernet1/2"].interface_mode.value == "virtual-wire"
    assert interfaces["ethernet1/2"].source_virtual_wire_relationships[0].role == "interface1"
    assert interfaces["ethernet1/3"].ip == "203.0.113.1/24"
    assert [item.source_address for item in interfaces["ethernet1/3"].ipv4_addresses] == [
        "203.0.113.1/24", "203.0.113.2/24"
    ]
