from fwmigrate.parsers.juniper_srx import JuniperSRXParser


def test_tenant_interfaces_routes_zones_and_screens_stay_local():
    parser = JuniperSRXParser("""
    set tenants TSYS1 interfaces ge-0/0/1 unit 0 family inet address 192.0.2.1/24
    set tenants TSYS1 interfaces ge-0/0/1 unit 0 family inet6 address 2001:db8::1/64
    set tenants TSYS1 routing-instances VR1 instance-type virtual-router
    set tenants TSYS1 routing-instances VR1 interface ge-0/0/1.0
    set tenants TSYS1 routing-instances VR1 routing-options static route 0.0.0.0/0 next-hop 192.0.2.254
    set tenants TSYS1 routing-instances VR1 routing-options static route 0.0.0.0/0 metric 10
    set tenants TSYS1 routing-instances VR1 routing-options static route 0.0.0.0/0 preference 5
    set tenants TSYS1 routing-instances VR1 routing-options static route 0.0.0.0/0 tag 7
    set tenants TSYS1 security zones security-zone trust interfaces ge-0/0/1.0
    set tenants TSYS1 security zones security-zone trust host-inbound-traffic system-services ping
    set tenants TSYS1 security screen ids-option SCREEN tcp-rst
    set tenants TSYS1 security zones security-zone trust screen SCREEN
    """)
    parser.extract()
    context = parser.config.contexts["TSYS1"]

    assert context.interfaces["ge-0/0/1"].units["0"].addresses[0].address == "192.0.2.1/24"
    assert {a.family for a in context.interfaces["ge-0/0/1"].units["0"].addresses} == {"inet", "inet6"}
    assert context.routing_instances["VR1"].interfaces == ["ge-0/0/1.0"]
    assert context.routes[0].routing_instance == "VR1"
    assert context.routes[0].metric == 10
    assert context.zones["trust"].interfaces == ["ge-0/0/1.0"]
    assert context.zones["trust"].screen == "SCREEN"
