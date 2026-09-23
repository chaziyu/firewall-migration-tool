from fwmigrate.vendors.palo_alto.source_builder import build_panos_config


def test_vpn_xml_reaches_typed_gateways_profiles_and_tunnels():
    config = build_panos_config("""<config><shared><network>
      <ike><gateway><entry name='gw1'><local-interface>ethernet1/1</local-interface><peer-address>198.51.100.1</peer-address><ike-version>ikev2</ike-version></entry></gateway>
        <crypto-profiles><ike-crypto-profile><entry name='ike-strong'><encryption><member>aes-256-cbc</member></encryption></entry></ike-crypto-profile></crypto-profiles>
      </ike>
      <ipsec><crypto-profiles><ipsec-crypto-profile><entry name='ipsec-strong'><protocol>esp</protocol></entry></ipsec-crypto-profile></crypto-profiles>
        <entry name='vpn-main'><tunnel-interface>tunnel.1</tunnel-interface><ipsec-crypto-profile>ipsec-strong</ipsec-crypto-profile><auto-key><ike-gateway><member>gw1</member></ike-gateway></auto-key></entry>
      </ipsec>
    </network></shared></config>""")

    gateway = config.ike_gateways[0]
    ike_profile = config.ike_crypto_profiles[0]
    ipsec_profile = config.ipsec_crypto_profiles[0]
    tunnel = config.ipsec_tunnels[0]
    assert gateway.name == "gw1"
    assert gateway.peer_address == "198.51.100.1"
    assert ike_profile.name == "ike-strong"
    assert "encryption" in ike_profile.explicit_fields
    assert ipsec_profile.name == "ipsec-strong"
    assert ipsec_profile.protocol == "esp"
    assert tunnel.name == "vpn-main"
    assert tunnel.tunnel_interface == "tunnel.1"
    assert tunnel.ike_gateways == ["gw1"]


def test_ipsec_proxy_ids_extract_both_auto_key_families_without_manual_secrets():
    secret = "manual-key-secret"
    source = f"""<config><shared><network><ipsec><entry name='vpn-main'>
      <auto-key>
        <proxy-id><entry name='proxy-v4'><local>10.0.0.0/24</local><remote>10.1.0.0/24</remote><protocol>tcp</protocol><protocol-number>6</protocol-number><local-port>443</local-port><remote-port>8443</remote-port></entry></proxy-id>
        <proxy-id-v6><entry name='proxy-v6'><local>2001:db8:1::/64</local><remote>2001:db8:2::/64</remote><protocol>any</protocol></entry></proxy-id-v6>
      </auto-key>
      <manual-key><key>{secret}</key></manual-key>
    </entry></ipsec></network></shared></config>"""
    config = build_panos_config(source)

    tunnel = config.ipsec_tunnels[0]
    v4, v6 = tunnel.proxy_ids
    assert tunnel.manual_key_configured is True
    assert (v4.address_family, v4.local, v4.remote, v4.protocol, v4.protocol_number, v4.local_port, v4.remote_port) == ("ipv4", "10.0.0.0/24", "10.1.0.0/24", "tcp", "6", "443", "8443")
    assert (v6.address_family, v6.local, v6.remote, v6.protocol) == ("ipv6", "2001:db8:1::/64", "2001:db8:2::/64", "any")
    assert secret not in config.model_dump_json()


def test_vpn_unknown_source_is_retained_separately():
    config = build_panos_config("<config><shared><network><ipsec><entry name='vpn'><future-setting>retain-me</future-setting></entry></ipsec></network></shared></config>")
    assert config.source_inventory
    assert config.ipsec_tunnels[0].raw_extra["future-setting"] == "retain-me"
