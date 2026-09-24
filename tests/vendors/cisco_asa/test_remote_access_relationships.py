from fwmigrate.vendors.cisco_asa.parser import CiscoASAParser
from fwmigrate.vendors.cisco_asa.relationships.references import build_asa_reference_index
from fwmigrate.vendors.cisco_asa.relationships.vpn import build_vpn_relationships


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
