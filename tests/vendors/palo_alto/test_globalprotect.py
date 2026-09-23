from fwmigrate.vendors.palo_alto.source_builder import build_panos_config


def test_globalprotect_xml_reaches_typed_portal_and_gateway():
    config = build_panos_config("""<config><shared><network><global-protect>
      <portal><entry name='portal-main'><ssl-tls-service-profile>ssl-profile</ssl-tls-service-profile><certificate-profile>portal-cert</certificate-profile>
        <client-config><entry name='managed'><internal-host-detection><ip-address>10.0.0.10</ip-address><hostname>inside.example</hostname></internal-host-detection><gateways><entry><gateway-type>external</gateway-type><gateway>gateway-main</gateway><priority>1</priority></entry></gateways><authentication-override><cookie-encrypt-decrypt><password>portal-password</password></cookie-encrypt-decrypt></authentication-override><agent-ui-settings><show-logout>yes</show-logout></agent-ui-settings><hip-collection-settings><enabled>yes</enabled></hip-collection-settings><agent-configuration><passcode>agent-passcode</passcode></agent-configuration><app-configuration><setting>keep</setting></app-configuration></entry></client-config>
        <clientless-vpn><hostname>vpn.example</hostname><security-zone>vpn</security-zone><login-lifetime>8</login-lifetime></clientless-vpn>
      </entry></portal>
      <gateway><entry name='gateway-main'><tunnel-mode>yes</tunnel-mode><local-interface>ethernet1/1</local-interface><local-address>192.0.2.1</local-address><client-authentication><entry name='users'><operating-system>Windows</operating-system><authentication-profile>ldap</authentication-profile><auto-retrieve-passcode>yes</auto-retrieve-passcode><password>gateway-password</password></entry></client-authentication><remote-user-tunnel><entry name='tunnel'><ip-pools><member>pool-a</member></ip-pools><authentication-server-ip-pools><member>auth-pool</member></authentication-server-ip-pools><split-tunneling><include-domains><member>example.com</member></include-domains></split-tunneling><no-direct-access-to-local-network>yes</no-direct-access-to-local-network><retrieve-framed-ip>no</retrieve-framed-ip></entry></remote-user-tunnel></entry></gateway>
    </global-protect></network></shared></config>""")

    portal = config.globalprotect_portals[0]
    gateway = config.globalprotect_gateways[0]
    assert portal.name == "portal-main"
    assert portal.ssl_tls_service_profile == "ssl-profile"
    assert portal.certificate_profile == "portal-cert"
    assert portal.client_configs[0].internal_host_detection_ip == "10.0.0.10"
    assert portal.client_configs[0].internal_host_detection_hostname == "inside.example"
    assert portal.client_configs[0].gateways[0].gateway == "gateway-main"
    assert portal.client_configs[0].authentication_override["cookie-encrypt-decrypt"]["password"] == "[REDACTED]"
    assert portal.clientless_vpn.hostname == "vpn.example"
    assert gateway.name == "gateway-main"
    assert gateway.tunnel_mode == "yes"
    assert gateway.local_interface == "ethernet1/1"
    assert gateway.local_address == "192.0.2.1"
    assert gateway.client_authentication[0].authentication_profile == "ldap"
    assert gateway.client_authentication[0].raw_extra["password"] == "[REDACTED]"
    assert gateway.remote_user_tunnels[0].ip_pools == ["pool-a"]
    assert gateway.remote_user_tunnels[0].split_tunneling["include-domains"]["member"] == "example.com"
    assert "portal-password" not in config.model_dump_json()
    assert "agent-passcode" not in config.model_dump_json()
    assert "gateway-password" not in config.model_dump_json()
