from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser


def test_zones_are_context_local_and_bind_host_inbound_correctly():
    cfg = JuniperSRXParser("\n".join([
        "set security zones security-zone trust interfaces ge-0/0/0.0",
        "set logical-systems LS1 security zones security-zone trust interfaces ge-0/0/1.0",
        "set logical-systems LS1 security zones security-zone trust interfaces ge-0/0/1.0 host-inbound-traffic system-services ssh",
        "set logical-systems LS1 security zones security-zone trust host-inbound-traffic protocols ospf",
        "set logical-systems LS2 security zones security-zone trust tcp-rst",
        "set logical-systems LS1 security zones security-zone blocked interfaces all",
        "deactivate logical-systems LS1 security zones security-zone trust",
    ])).parse_raw()
    assert cfg.contexts["root"].zones["trust"].interfaces == ["ge-0/0/0.0"]
    ls1 = cfg.contexts["LS1"].zones["trust"]
    assert ls1.interfaces == ["ge-0/0/1.0"]
    assert ls1.interface_host_inbound["ge-0/0/1.0"]["system_services"] == ["ssh"]
    assert ls1.host_inbound_protocols == ["ospf"]
    assert cfg.contexts["LS2"].zones["trust"].tcp_rst
    assert cfg.contexts["LS1"].zones["blocked"].source_attributes["invalid_children"]


def test_zone_activation_isolated():
    parser = JuniperSRXParser("\n".join([
        "set security zones security-zone trust",
        "set logical-systems LS1 security zones security-zone trust",
        "set logical-systems LS2 security zones security-zone trust",
        "deactivate logical-systems LS1 security zones security-zone trust",
    ]))
    parser.extract()
    assert "disabled" not in parser.config.contexts["root"].zones["trust"].source_attributes
    assert parser.config.contexts["LS1"].zones["trust"].source_attributes["disabled"]
    assert "disabled" not in parser.config.contexts["LS2"].zones["trust"].source_attributes
