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
