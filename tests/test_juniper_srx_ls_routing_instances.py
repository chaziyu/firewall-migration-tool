from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser


def test_routing_instances_are_context_local_and_preserve_children():
    cfg = JuniperSRXParser("\n".join([
        "set routing-instances VR1 instance-type vrf",
        "set routing-instances VR1 interface ge-0/0/0.0",
        "set logical-systems LS1 routing-instances VR1 instance-type virtual-router",
        "set logical-systems LS1 routing-instances VR1 interface ge-0/0/1.0",
        "set logical-systems LS1 routing-instances VR1 interface ge-0/0/1.0",
        "set logical-systems LS1 routing-instances VR1 routing-options static route 10.20.0.0/16 next-hop 10.1.1.2",
        "set logical-systems LS1 routing-instances VR1 protocols ospf area 0.0.0.0",
        "set logical-systems LS2 routing-instances VR1 routing-options static route 10.20.0.0/16 next-hop 10.2.1.2",
    ])).parse_raw()

    root = cfg.contexts["root"].routing_instances["VR1"]
    ls1 = cfg.contexts["LS1"].routing_instances["VR1"]
    ls2 = cfg.contexts["LS2"].routing_instances["VR1"]
    assert root is not ls1 is not ls2
    assert root.instance_type == "vrf"
    assert ls1.instance_type == "virtual-router"
    assert ls1.interfaces == ["ge-0/0/1.0"]
    assert ls1.source_attributes["unsupported_children"][0]["path"][:1] == ["protocols"]
    assert cfg.contexts["LS1"].routes[0].routing_instance == "VR1"
    assert cfg.contexts["LS2"].routes[0].routing_instance == "VR1"


def test_routing_instance_activation_isolated():
    parser = JuniperSRXParser("\n".join([
        "set routing-instances VR1 instance-type vrf",
        "set logical-systems LS1 routing-instances VR1 instance-type vrf",
        "set logical-systems LS2 routing-instances VR1 instance-type vrf",
        "set logical-systems LS1 routing-instances VR1 routing-options static route 10.20.0.0/16 next-hop 10.1.1.2",
        "deactivate logical-systems LS1 routing-instances VR1",
    ]))
    parser.extract()
    assert parser.config.contexts["LS1"].routing_instances["VR1"].source_attributes["disabled"]
    assert "disabled" not in parser.config.contexts["root"].routing_instances["VR1"].source_attributes
    assert "disabled" not in parser.config.contexts["LS2"].routing_instances["VR1"].source_attributes
    assert parser.config.contexts["LS1"].routes[0].disabled


def test_malformed_routing_instance_command_is_reported():
    result = JuniperSRXParser("set routing-instances").extract()
    assert result.unsupported_items
