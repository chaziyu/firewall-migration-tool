from fwmigrate.vendors.palo_alto.source_builder import build_panos_config


def test_vpn_xml_reaches_typed_gateways_profiles_and_tunnels():
    config = build_panos_config("""<config><shared><network>
      <ike><gateway><entry name='gw1'><local-interface>ethernet1/1</local-interface><peer-address>198.51.100.1</peer-address><ike-version>ikev2</ike-version></entry></gateway>
        <crypto-profiles><ike-crypto-profiles><entry name='ike-strong'><encryption><member>aes-256-cbc</member></encryption></entry></ike-crypto-profiles><ipsec-crypto-profiles><entry name='ipsec-strong'><protocol>esp</protocol></entry></ipsec-crypto-profiles></crypto-profiles>
      </ike>
      <ipsec>
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
    assert ike_profile.encryption_algorithms == ["aes-256-cbc"]
    assert "encryption_algorithms" in ike_profile.explicit_fields
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
    assert "manual_key_configured" in tunnel.explicit_fields


def test_vpn_unknown_source_is_retained_separately():
    config = build_panos_config("<config><shared><network><ipsec><entry name='vpn'><future-setting>retain-me</future-setting></entry></ipsec></network></shared></config>")
    assert config.source_inventory
    assert config.ipsec_tunnels[0].raw_extra["future-setting"] == "retain-me"


def test_missing_manual_key_stays_unconfigured_and_proxy_family_is_structural():
    config = build_panos_config("""<config><shared><network><ipsec><entry name='vpn'>
      <auto-key><proxy-id><entry name='v4'/></proxy-id><proxy-id-v6><entry name='v6'/></proxy-id-v6></auto-key>
    </entry></ipsec></network></shared></config>""")
    tunnel = config.ipsec_tunnels[0]
    assert tunnel.manual_key_configured is None
    assert "manual_key_configured" not in tunnel.explicit_fields
    assert [(item.address_family, "address_family" in item.explicit_fields) for item in tunnel.proxy_ids] == [("ipv4", False), ("ipv6", False)]


def test_reference_shaped_nested_proxy_protocol_and_auto_key_profile():
    config = build_panos_config("""<config><shared><network><ipsec><entry name='vpn'>
      <auto-key><ipsec-crypto-profile>ipsec-strong</ipsec-crypto-profile>
        <proxy-id><entry name='tcp'><protocol><tcp><local-port>443</local-port><remote-port>8443</remote-port><future-setting>retain-me</future-setting></tcp></protocol></entry>
          <entry name='udp'><protocol><udp><local-port>53</local-port></udp></protocol></entry>
          <entry name='any'><protocol><any/></protocol></entry>
          <entry name='number'><protocol><number>47</number></protocol></entry></proxy-id>
      </auto-key></entry></ipsec></network></shared></config>""")
    tunnel = config.ipsec_tunnels[0]
    assert tunnel.ipsec_crypto_profile == "ipsec-strong"
    assert "ipsec_crypto_profile" in tunnel.explicit_fields
    assert [(item.protocol, item.protocol_number, item.local_port, item.remote_port) for item in tunnel.proxy_ids] == [
        ("tcp", None, "443", "8443"), ("udp", None, "53", None), ("any", None, None, None), (None, "47", None, None)
    ]
    assert tunnel.proxy_ids[0].raw_extra["protocol"]["tcp"]["future-setting"] == "retain-me"
    assert {"protocol", "local_port", "remote_port"} <= tunnel.proxy_ids[0].explicit_fields
    assert "protocol_number" in tunnel.proxy_ids[3].explicit_fields
    assert not config.extraction_issues


def test_malformed_proxy_extraction_is_visible_and_does_not_hide_failure():
    config = build_panos_config("""<config><shared><network><ipsec><entry name='vpn'>
      <auto-key><proxy-id><entry name='proxy'><protocol><tcp><local-port><member>443</member></local-port></tcp></protocol></entry></proxy-id></auto-key>
    </entry></ipsec></network></shared></config>""")
    assert config.ipsec_tunnels == []
    assert any(issue.source_name == "vpn" and issue.domain == "ipsec_tunnel" for issue in config.extraction_issues)


def test_ike_id_scalar_compatibility_and_unverified_subtree_preservation():
    config = build_panos_config("""<config><shared><network><ike><gateway>
      <entry name='scalar'><local-id>vpn-id</local-id><peer-id>peer-id</peer-id></entry>
      <entry name='structured'><local-id><future-identifier-leaf>retain-id</future-identifier-leaf></local-id></entry>
    </gateway></ike></network></shared></config>""")
    scalar, structured = config.ike_gateways
    assert scalar.local_id == "vpn-id" and scalar.peer_id == "peer-id"
    assert structured.local_id is None
    assert structured.raw_extra["local-id"]["future-identifier-leaf"] == "retain-id"
