from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser


def parse(text):
    return JuniperSRXParser(text).parse_raw().contexts["root"]


def test_source_inventory_domains_and_repeated_values():
    ctx = parse("\n".join([
        "set security screen ids-option flood tcp syn-flood alarm-threshold 10",
        "set firewall family inet filter F term T from source-address 10.0.0.0/8",
        "set firewall family inet filter F term T then accept",
        "set firewall policer P bandwidth-limit 1m",
        "set class-of-service schedulers scheduler S transmit-rate percent 10",
        "set policy-options prefix-list PL 10.0.0.0/8",
        "set policy-options prefix-list PL 2001:db8::/32",
        "set security policies from-zone trust to-zone untrust policy P then log session-init",
        "set security policies from-zone trust to-zone untrust policy P then log session-close",
        "set security ike gateway G local-identity hostname edge",
        "set security ike gateway G nat-traversal",
    ]))
    assert ctx.screens["ids-option"].options[0].path[-1] == "10"
    assert ctx.firewall_filters["F"].terms[0].actions[0]["action"] == ["accept"]
    assert ctx.firewall_filters["F"].terms[0].from_conditions
    assert ctx.policers["P"].bandwidth_limit == "1m"
    assert ctx.cos_schedulers["S"].transmit_rate == "percent 10"
    assert ctx.prefix_lists["PL"].entries == ["10.0.0.0/8", "2001:db8::/32"]
    assert ctx.policies[0].log_session_init and ctx.policies[0].log_session_close
    assert ctx.vpn.ike_gateways["G"].nat_traversal is True


def test_inactive_application_term_and_address_set_member_are_not_resolved():
    ctx = parse("\n".join([
        "set applications application APP term web protocol tcp",
        "deactivate applications application APP term web",
        "set security address-book global address A 10.0.0.1/32",
        "set security address-book global address-set G address A",
        "deactivate security address-book global address-set G address A",
    ]))
    assert ctx.applications["APP"].terms[0].disabled is True
    assert ctx.address_books["global"].address_sets["G"].members[0].disabled is True
