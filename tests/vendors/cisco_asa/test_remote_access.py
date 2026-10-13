from fwmigrate.vendors.cisco_asa.parser import CiscoASAParser

from fwmigrate.vendors.cisco_asa.relationships.references import build_asa_reference_index

from fwmigrate.vendors.cisco_asa.relationships.vpn import build_vpn_relationships

from io import BytesIO

from openpyxl import load_workbook

from fwmigrate.vendors.cisco_asa import extract_cisco_asa_source

from fwmigrate.vendors.cisco_asa.export.excel import export_asa_excel

from fwmigrate.vendors.cisco_asa.web_report import build_asa_preview

def test_remote_access_relationships_resolve_group_policy_and_interface():
    config = CiscoASAParser("""interface GigabitEthernet0/1
 nameif outside
webvpn
 enable outside
group-policy GP attributes
 vpn-filter value FILTER
tunnel-group RA type remote-access
tunnel-group RA general-attributes
 default-group-policy GP
""").parse_raw()
    before = config.model_dump()
    result = build_vpn_relationships(config, build_asa_reference_index(config))
    webvpn = next(row for row in result.relationships if row.source is config.webvpn)
    tunnel = next(row for row in result.relationships if row.source is config.tunnel_groups[0])
    policy = next(row for row in result.relationships if row.source is config.group_policies[0])
    assert webvpn.targets[0][1] is config.interfaces[0]
    assert tunnel.targets[0][1] is config.group_policies[0]
    assert policy.issues[0].reference_name == "FILTER"
    assert config.model_dump() == before

def test_remote_access_view_keeps_context_and_source_layers_separate():
    result = extract_cisco_asa_source(
        "changeto context blue\n"
        "interface GigabitEthernet0/1\n nameif outside\n"
        "webvpn\n enable outside\n"
        "vpn-addr-assign local reuse-delay 10\n"
        "ip local pool POOL 10.0.0.1-10.0.0.20 mask 255.255.255.0\n"
        "aaa-server AUTH protocol radius\n"
        "group-policy PARENT internal\n"
        "group-policy PARENT attributes\n dns-server value 8.8.8.8\n"
        "group-policy GP internal from PARENT\n"
        "group-policy GP attributes\n vpn-tunnel-protocol ssl-client\n vpn-filter value FILTER\n"
        "tunnel-group RA type remote-access\n"
        "tunnel-group RA general-attributes\n default-group-policy GP\n address-pool POOL\n authentication-server-group AUTH\n"
        "tunnel-group RA webvpn-attributes\n authentication saml\n"
        "changeto context green\n"
        "webvpn\n enable vpn-out\n"
        "vpn-addr-assign dhcp\n"
        "tunnel-group RA type remote-access\n"
    )

    blue, green = result.derived.vpn.remote_access
    assert blue.source_context == "blue"
    assert blue.group_policy.name == "GP"
    assert blue.inherited_group_policy.name == "PARENT"
    assert blue.dns_servers == ()
    assert blue.authentication_server_group.name == "AUTH"
    assert blue.address_assignment_methods == ("local",)
    assert [getattr(pool, "name", pool) for pool in blue.address_pools] == ["POOL"]
    assert blue.vpn_protocols == ("ssl-client",)
    assert blue.vpn_filter_acl == "FILTER"
    assert "Unresolved acl reference" in blue.issues
    assert blue.resolution_status == "PARTIAL"

    assert green.source_context == "green"
    assert green.group_policy is None
    assert green.address_assignment_methods == ("dhcp",)
    assert green.dhcp_servers == ()
    assert "DHCP address-assignment source is unresolved" in green.issues
    assert green.enabled_interfaces == ("vpn-out",)
    assert result.derived.vpn.ipsec_topologies == ()


def test_remote_access_source_is_explicit_and_context_scoped():
    config = CiscoASAParser("""changeto context blue
interface GigabitEthernet0/1
 nameif outside
webvpn
 enable outside
 tunnel-group-list enable
vpn-addr-assign aaa
vpn-addr-assign local reuse-delay 10
tunnel-group RA type remote-access
tunnel-group RA general-attributes
 default-group-policy GP
 authentication-server-group AUTH
tunnel-group RA webvpn-attributes
 authentication saml
changeto context green
webvpn
 enable outside
vpn-addr-assign dhcp
""").parse_raw()
    assert config.webvpn.enabled_interfaces == ["outside"]
    assert config.webvpn.source_context == "blue"
    assert config.vpn_address_assignment.aaa_enabled is True
    assert config.vpn_address_assignment.local_enabled is True
    assert config.vpn_address_assignment.reuse_delay == 10
    group = config.tunnel_groups[0]
    assert group.default_group_policy == "GP"
    assert group.general_attributes["authentication_server_group"] == "AUTH"
    assert group.webvpn_attributes["authentication"] == "saml"
    assert [item.source_context for item in config.webvpn_configs] == ["blue", "green"]
    assert [item.source_context for item in config.vpn_address_assignments] == ["blue", "green"]
    assert config.vpn_address_assignments[1].dhcp_enabled is True

def test_local_pool_uses_single_hyphenated_range_and_only_explicit_mask():
    config = CiscoASAParser(
        "ip local pool POOL 10.0.0.1-10.0.0.20\n"
        "ip local pool POOL2 10.1.0.10-10.1.0.30 mask 255.255.255.0\n"
    ).parse_raw()
    first, second = config.vpn_address_pools
    assert (first.start, first.end, first.mask) == ("10.0.0.1", "10.0.0.20", None)
    assert (second.start, second.end, second.mask) == ("10.1.0.10", "10.1.0.30", "255.255.255.0")

def test_local_pool_rejects_separate_addresses_instead_of_reinterpreting_them():
    config = CiscoASAParser("ip local pool POOL 10.0.0.1 10.0.0.20 mask 255.255.255.0\n").parse_raw()
    assert config.vpn_address_pools[0].extraction_status == "PARSE_ERROR"

def test_local_pool_accepts_only_ipv4_ranges_and_valid_masks():
    config = CiscoASAParser(
        "ip local pool IPV6 2001:db8::1-2001:db8::5\n"
        "ip local pool HOSTS 10.0.0.1-10.0.0.5 mask 255.255.255.255\n"
        "ip local pool CIDR 10.0.0.1-10.0.0.5 mask /24\n"
        "ip local pool VALID 10.0.0.1-10.0.0.5 mask 255.255.255.0\n"
    ).parse_raw()
    assert [pool.extraction_status for pool in config.vpn_address_pools] == [
        "PARSE_ERROR", "PARSE_ERROR", "PARSE_ERROR", "SOURCE_ONLY",
    ]
