from fwmigrate.vendors.palo_alto.source_report import PaloAltoSourceReporter


def test_interfaces_preserve_parent_aggregate_and_tunnel_relationships():
    source = """<config><devices><entry name='fw'><network><interface>
      <ethernet><entry name='ethernet1/1'><layer3><aggregate-group>ae1</aggregate-group><units><entry name='ethernet1/1.10'/></units></layer3></entry></ethernet>
      <aggregate-ethernet><entry name='ae1'><layer3/></entry></aggregate-ethernet><tunnel><units><entry name='tunnel.1'/></units></tunnel>
      <ipsec><entry name='vpn'><tunnel-interface>tunnel.1</tunnel-interface></entry></ipsec>
    </interface></network></entry></devices></config>"""
    rows = PaloAltoSourceReporter().build_preview(PaloAltoSourceReporter().analyze_source(source))["sections"]["interface_topology"]
    assert any(row["parent"] == "ethernet1/1" for row in rows)
    assert any(row["aggregate"] == "ae1" for row in rows)
