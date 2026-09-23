from fwmigrate.vendors.palo_alto.source_builder import build_panos_config


def test_dhcp_xml_reaches_typed_server_and_preserves_unknown_source():
    config = build_panos_config("""<config><shared><network><dhcp>
      <entry name='dhcp-main'><interface>ethernet1/1</interface><mode>auto</mode>
        <wins><member>192.0.2.2</member></wins><ntp><member>192.0.2.3</member></ntp>
        <ip-pool><entry name='pool-1'><start-ip>192.0.2.10</start-ip><end-ip>192.0.2.20</end-ip><future-field>retain-pool</future-field></entry></ip-pool>
        <reservations><entry name='printer'><ip-address>192.0.2.30</ip-address><mac-address>00:11:22:33:44:55</mac-address></entry></reservations>
        <options><entry name='dns'><code>6</code><ip-values><member>192.0.2.2</member></ip-values></entry></options>
        <future-setting>retain-me</future-setting>
      </entry>
    </dhcp></network></shared></config>""")

    server = config.dhcp_servers[0]
    assert server.name == "dhcp-main"
    assert server.interface == "ethernet1/1"
    assert server.mode == "auto"
    assert server.wins == ["192.0.2.2"]
    assert server.ntp == ["192.0.2.3"]
    assert server.ip_pools[0].start_ip == "192.0.2.10"
    assert server.ip_pools[0].end_ip == "192.0.2.20"
    assert server.ip_pools[0].raw_extra["future-field"] == "retain-pool"
    assert server.reservations[0].mac_address == "00:11:22:33:44:55"
    assert server.options[0].code == "6"
    assert server.options[0].ip_values == ["192.0.2.2"]
    assert server.raw_extra["future-setting"] == "retain-me"
