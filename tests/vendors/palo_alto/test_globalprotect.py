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


def test_selected_globalprotect_roots_and_nested_shapes_are_typed():
    config = build_panos_config("""<config><shared><global-protect>
      <global-protect-portal><entry name='portal-selected'><client-config><configs><entry name='managed'>
        <internal-host-detection><ip-address>10.0.0.20</ip-address><hostname>inside.example</hostname></internal-host-detection>
        <agent-ui><show-logout>yes</show-logout></agent-ui><hip-collection><enabled>yes</enabled></hip-collection>
        <agent-config><portal-setting>yes</portal-setting></agent-config><gp-app-config><setting>keep</setting></gp-app-config>
        <authentication-override><cookie-encrypt-decrypt><password>SECRET</password></cookie-encrypt-decrypt></authentication-override>
        <gateways><entry><gateway-type>external</gateway-type><gateway>gateway-selected</gateway></entry></gateways><future-client>keep-client</future-client>
      </entry></configs></client-config><clientless-vpn><max-user>500</max-user><login-lifetime><hours>8</hours></login-lifetime><inactivity-logout><minutes>20</minutes></inactivity-logout></clientless-vpn><future-portal>keep-portal</future-portal></entry></global-protect-portal>
      <global-protect-gateway><entry name='gateway-selected'><tunnel-mode>yes</tunnel-mode><local-address><interface>ethernet1/2</interface><ip-address-family>ipv4_ipv6</ip-address-family><future-address>keep-address</future-address></local-address>
        <client-auth><entry name='users'><os>Windows</os><authentication-profile>ldap</authentication-profile><auto-retrieve-passcode>yes</auto-retrieve-passcode></entry></client-auth>
        <remote-user-tunnel-configs><entry name='remote'><authentication-server-ip-pool><member>auth-pool</member></authentication-server-ip-pool><retrieve-framed-ip-address>yes</retrieve-framed-ip-address><no-direct-access-to-local-network>no</no-direct-access-to-local-network><split-tunneling><include-domains><member>example.com</member></include-domains></split-tunneling></entry></remote-user-tunnel-configs>
      </entry></global-protect-gateway>
    </global-protect></shared></config>""")
    portal, = config.globalprotect_portals
    gateway, = config.globalprotect_gateways
    client = portal.client_configs[0]
    assert client.name == "managed" and client.internal_host_detection_ip == "10.0.0.20"
    assert client.agent_ui_settings["show-logout"] == "yes"
    assert client.hip_collection_settings["enabled"] == "yes"
    assert client.agent_configuration["portal-setting"] == "yes"
    assert client.app_configuration["setting"] == "keep"
    assert portal.clientless_vpn.maximum_users == "500"
    assert (portal.clientless_vpn.login_lifetime, portal.clientless_vpn.login_lifetime_unit) == ("8", "hours")
    assert (portal.clientless_vpn.inactivity_logout, portal.clientless_vpn.inactivity_logout_unit) == ("20", "minutes")
    assert portal.raw_extra["future-portal"] == "keep-portal" and client.raw_extra["future-client"] == "keep-client"
    assert gateway.local_interface == "ethernet1/2" and gateway.local_address is None
    assert gateway.ip_address_family == "ipv4_ipv6"
    assert gateway.client_authentication[0].operating_system == "Windows"
    tunnel = gateway.remote_user_tunnels[0]
    assert tunnel.authentication_server_ip_pools == ["auth-pool"]
    assert tunnel.retrieve_framed_ip == "yes" and tunnel.no_direct_access_to_local_network == "no"
    assert tunnel.split_tunneling["include-domains"]["member"] == "example.com"
    assert gateway.raw_extra["local-address"]["future-address"] == "keep-address"
