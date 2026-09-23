from fwmigrate.vendors.palo_alto.source_report import PaloAltoSourceReporter


def test_ipsec_preview_keeps_tunnel_interface_and_ike_gateway():
    source = """<config><devices><entry name='fw'><network><interface><tunnel><units><entry name='tunnel.1'/></units></tunnel><ipsec><entry name='vpn'><tunnel-interface>tunnel.1</tunnel-interface><auto-key><ike-gateway><member>gw1</member></ike-gateway></auto-key></entry></ipsec></interface></network></entry></devices></config>"""
    vpn = PaloAltoSourceReporter().build_preview(PaloAltoSourceReporter().analyze_source(source))["sections"]["vpn_tunnels"][0]
    assert vpn["interface"] == "tunnel.1"
    assert vpn["ike_gateways"] == ["gw1"]
