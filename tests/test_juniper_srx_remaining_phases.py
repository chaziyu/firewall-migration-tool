from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser


def test_remaining_juniper_domains_are_structured_and_secret_safe():
    content = """
    set system login user alice class super-user
    set system radius-server 192.0.2.10 port 1812 secret "radius-secret"
    set system tacplus-server 192.0.2.11 timeout 5 secret "tacacs-secret"
    set system authentication-order [ radius password ]
    set access profile corp authentication-order radius
    set security dynamic-vpn remote access-profile corp
    set security user-identification device-identity profile corp
    set security utm custom-utm antivirus signature-set default
    set security policies global policy vpn-policy then permit tunnel ipsec-vpn site-to-site
    """
    result = JuniperSRXParser(content).extract()
    config = result.canonical_ir
    raw = JuniperSRXParser(content).parse_raw()

    assert raw.local_users["alice"].name == "alice"
    assert raw.radius_servers["192.0.2.10"].settings
    assert raw.tacplus_servers["192.0.2.11"].settings
    assert raw.authentication_order == ["radius", "password"]
    root = raw.contexts["root"]
    assert root.access_profiles["corp"].settings
    assert root.dynamic_vpns["remote"].settings
    assert root.user_identification["device-identity"].settings
    assert root.utm_policies["custom-utm"].settings
    assert "radius-secret" not in result.model_dump_json()
    assert "tacacs-secret" not in result.model_dump_json()
    assert raw.contexts["root"].global_policies[0].vpn_reference == "site-to-site"
    assert raw.contexts["root"].global_policies[0].vpn_action == "tunnel"
