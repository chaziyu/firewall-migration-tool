from fwmigrate.vendors.checkpoint.gaia.command_evaluator import evaluate_gaia_commands
from fwmigrate.vendors.checkpoint.gaia.parser import parse_gaia


def evaluate(text):
    return evaluate_gaia_commands(parse_gaia(text))


def test_route_families_and_interface_state_are_separate():
    values = evaluate(
        "set interface eth0 ipv4-address 192.0.2.1\n"
        "set interface eth0 mask-length 24\n"
        "set static-route 10.0.0.0/8 nexthop gateway address 192.0.2.1 on\n"
        "set ipv6 route static 2001:db8::/32 nexthop gateway address 2001:db8::1 on\n"
    )
    assert [item.kind for item in values] == ["interface", "static-route-ipv4", "static-route-ipv6"]
    assert values[0].values["mask_length"] == "24"
    assert values[1].values["ipv4_destination"] == "10.0.0.0/8"
    assert values[2].values["ipv6_destination"] == "2001:db8::/32"


def test_dhcp_subnets_and_rba_assignments_remain_structured_and_separate():
    values = evaluate(
        "set dhcp server state on\n"
        "set dhcp server subnet 192.0.2.0 netmask 24 enabled on\n"
        "set rba role network-admin all-features on\n"
        "set rba user admin role network-admin\n"
    )
    assert values[0].kind == "dhcp-server"
    assert values[0].values["process_state"] == "on"
    assert values[0].values["subnets"][0]["subnet"] == "192.0.2.0"
    assert [item.kind for item in values[1:]] == ["gaia-rba-role", "gaia-rba-user-assignment"]


def test_show_output_is_preserved_as_unsupported_until_grammar_is_known():
    values = evaluate("show route static all\n")
    assert values[0].kind == "unsupported"
    assert values[0].values["command"] == "show route static all"


def test_multiple_static_route_next_hops_and_gaia_route_forms_are_preserved():
    values = evaluate(
        "set static-route 10.0.0.0/8 nexthop gateway address 192.0.2.1 on priority 1\n"
        "set static-route 10.0.0.0/8 nexthop logical eth0 on priority 2\n"
        "set static-route default nexthop blackhole\n"
        "set static-route 203.0.113.0/24 nexthop reject\n"
        "set ipv6 static-route 2001:db8::/32 nexthop gateway address 2001:db8::1 on\n"
        "add vpn tunnel 7 type numbered local 192.0.2.2 remote 192.0.2.3 peer branch\n"
        "add vpn tunnel 8 type unnumbered peer branch dev eth1\n"
    )
    route = values[0]
    assert len(route.values["next_hops"]) == 2
    assert route.values["next_hops"][0] == {"next_hop_type": "gateway", "gateway": "192.0.2.1", "priority": "1"}
    assert route.values["next_hops"][1]["interface"] == "eth0"
    assert values[1].values["default"] is True and values[1].values["next_hops"][0]["next_hop_type"] == "blackhole"
    assert values[2].values["next_hops"][0]["next_hop_type"] == "reject"
    assert values[3].values["next_hops"][0]["gateway"] == "2001:db8::1"
    assert (values[4].values["tunnel_type"], values[4].values["local_address"], values[4].values["remote_address"]) == ("numbered", "192.0.2.2", "192.0.2.3")
    assert (values[5].values["tunnel_type"], values[5].values["local_device"]) == ("unnumbered", "eth1")


def test_dhcp_subnet_pools_and_dns_merge_without_losing_explicit_values():
    values = evaluate(
        "set dhcp server state on\n"
        "add dhcp server subnet 192.0.2.0 netmask 255.255.255.0 include-ip-pool start 192.0.2.10 end 192.0.2.20\n"
        "add dhcp server subnet 192.0.2.0 include-ip-pool start 192.0.2.30 end 192.0.2.40\n"
        "add dhcp server subnet 192.0.2.0 exclude-ip-pool start 192.0.2.15 end 192.0.2.16\n"
        "set dhcp server subnet 192.0.2.0 include-ip-pool 192.0.2.10-192.0.2.20 disable default-lease 3600 max-lease 7200 default-gateway 192.0.2.1 domain example.test dns 192.0.2.53,192.0.2.54\n"
    )
    subnet = values[0].values["subnets"][0]
    assert values[0].values["process_state"] == "on"
    assert subnet["netmask"] == "255.255.255.0"
    assert len(subnet["included_pools"]) == 2 and subnet["included_pools"][0]["enabled"] is False
    assert subnet["excluded_pools"] == [{"start": "192.0.2.15", "end": "192.0.2.16"}]
    assert subnet["default_lease"] == "3600" and subnet["maximum_lease"] == "7200"
    assert subnet["dns_servers"] == ["192.0.2.53", "192.0.2.54"]
