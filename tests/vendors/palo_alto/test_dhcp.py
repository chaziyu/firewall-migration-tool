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


def test_selected_interface_server_options_pools_reservations_and_unknowns():
    config = build_panos_config("""<config><shared><network><dhcp><interface><entry name='ethernet1/1'><server>
      <mode>enabled</mode><probe-ip>yes</probe-ip><ip-pool><member>192.0.2.10-192.0.2.20</member></ip-pool>
      <reserved><entry name='printer'><mac>00:11:22:33:44:55</mac><description>printer</description><future-reservation>keep-reservation</future-reservation></entry></reserved>
      <option><lease><timeout>720</timeout></lease><inheritance><source>ethernet1/2</source></inheritance>
        <gateway>192.0.2.1</gateway><subnet-mask>255.255.255.0</subnet-mask><dns><primary>192.0.2.2</primary><secondary>192.0.2.3</secondary><future-dns>keep-dns</future-dns></dns>
        <wins><member>192.0.2.4</member></wins><ntp><member>192.0.2.5</member></ntp><dns-suffix>example.test</dns-suffix>
        <user-defined><entry name='custom'><code>200</code><ascii><member>hello</member></ascii><future-option>keep-option</future-option></entry></user-defined><future-option-root>keep-root</future-option-root>
      </option><future-server>keep-server</future-server>
    </server></entry></interface></dhcp></network></shared></config>""")
    server, = config.dhcp_servers
    assert server.interface == "ethernet1/1" and server.mode == "enabled" and server.probe_ip == "yes"
    assert server.lease_type == "timeout" and server.lease_timeout == "720"
    assert server.inheritance_source == "ethernet1/2" and server.gateway == "192.0.2.1"
    assert server.dns_primary == "192.0.2.2" and server.dns_secondary == "192.0.2.3"
    assert server.wins == ["192.0.2.4"] and server.ntp == ["192.0.2.5"]
    assert server.ip_pools[0].value == "192.0.2.10-192.0.2.20"
    assert server.reservations[0].mac_address == "00:11:22:33:44:55" and server.reservations[0].ip_address is None
    assert server.options[0].value_type == "ascii" and server.options[0].ascii_values == ["hello"]
    assert server.raw_extra["server"]["future-server"] == "keep-server"
    assert server.raw_extra["server"]["option"]["future-option-root"] == "keep-root"
    assert server.raw_extra["server"]["option"]["dns"]["future-dns"] == "keep-dns"
    assert server.options[0].raw_extra["future-option"] == "keep-option"
    assert server.reservations[0].raw_extra["future-reservation"] == "keep-reservation"


def test_selected_dhcp_missing_options_stay_unknown_and_unlimited_is_explicit():
    config = build_panos_config("""<config><shared><network><dhcp><interface><entry name='ethernet1/1'><server>
      <option><lease><unlimited/></lease></option>
    </server></entry></interface></dhcp></network></shared></config>""")
    server, = config.dhcp_servers
    assert server.lease_type == "unlimited" and server.lease_timeout is None
    assert server.gateway is None and server.subnet_mask is None and server.dns_primary is None
