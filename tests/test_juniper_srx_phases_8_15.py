from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser


def test_zone_host_inbound_keeps_zone_and_interface_scope():
    cfg = JuniperSRXParser("""
    set security zones security-zone trust interfaces ge-0/0/0.0
    set security zones security-zone trust host-inbound-traffic system-services ssh
    set security zones security-zone trust host-inbound-traffic interfaces ge-0/0/0.0 protocols bgp
    """).parse_raw()
    zone = cfg.contexts["root"].zones["trust"]
    assert zone.interfaces == ["ge-0/0/0.0"]
    assert zone.host_inbound_system_services == ["ssh"]
    assert zone.interface_host_inbound["ge-0/0/0.0"]["protocols"] == ["bgp"]


def test_routes_retain_actions_and_ribs():
    cfg = JuniperSRXParser("""
    set routing-options rib inet6.0 static route 2001:db8::/32 next-table inet.0
    set routing-options static route 10.0.0.0/8 retain
    """).parse_raw()
    routes = cfg.contexts["root"].routes
    assert routes[0].rib == "inet6.0" and routes[0].action == "next-table"
    assert routes[1].retain is True and routes[1].action == "retain"


def test_filter_order_attachment_and_dns_children():
    cfg = JuniperSRXParser("""
    set firewall family inet filter F term first from source-address 10.0.0.0/8
    set firewall family inet filter F term first then accept
    set interfaces ge-0/0/0 unit 0 family inet filter input F
    set system name-server 192.0.2.1 routing-instance mgmt
    set system domain-name example.test
    set system domain-search example.test example.org
    """).parse_raw()
    filt = cfg.contexts["root"].firewall_filters["F"]
    assert [term.name for term in filt.terms] == ["first"]
    assert cfg.contexts["root"].interfaces["ge-0/0/0"].units["0"].filters[0]["name"] == "F"
    assert cfg.name_servers[0].server == "192.0.2.1"
    assert cfg.name_servers[0].routing_instance == "mgmt"
    assert cfg.domain_search == ["example.test", "example.org"]


def test_routing_instances_dhcp_and_link_monitor_are_source_inventory():
    cfg = JuniperSRXParser("""
    set routing-instances blue instance-type vrf
    set routing-instances blue interface ge-0/0/0.0
    set access address-assignment pool USERS family inet low 10.0.0.10
    set access address-assignment pool USERS family inet high 10.0.0.20
    set access address-assignment pool USERS family inet router 10.0.0.1
    set system services dhcp-local-server group LOCAL interface ge-0/0/0.0
    set link-monitor foo threshold 3
    """).parse_raw()
    ctx = cfg.contexts["root"]
    assert ctx.routing_instances["blue"].instance_type == "vrf"
    assert ctx.routing_instances["blue"].interfaces == ["ge-0/0/0.0"]
    assert ctx.dhcp_pools["USERS"].router == ["10.0.0.1"]
    assert cfg.contexts["root"].source_attributes["link_monitor"]
