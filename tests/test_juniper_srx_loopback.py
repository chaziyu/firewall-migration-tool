from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser


def test_loopback_reuses_unit_family_address_filter_parser():
    content = """
    set interfaces lo0 unit 0 family inet address 10.0.0.1/32
    set interfaces lo0 unit 0 family inet6 address 2001:db8::1/128
    set interfaces lo0 unit 0 family inet filter input LOOP4
    set interfaces lo0 unit 1 family inet address 10.0.0.2/32
    set interfaces lo0 unit 1 family inet6 filter output LOOP6
    """
    cfg = JuniperSRXParser(content).parse_raw().contexts["root"]
    assert cfg.interfaces["lo0"].interface_type == "loopback"
    out = JuniperSRXParser(content).transform_to_ir()
    lo0 = next(i for i in out.interfaces if i.name == "lo0.0")
    lo1 = next(i for i in out.interfaces if i.name == "lo0.1")
    assert (lo0.ip, lo1.ip) == ("10.0.0.1/32", "10.0.0.2/32")
    assert {f["name"] for f in lo0.source_attributes["junos_filters"]} == {"LOOP4"}
    assert {f["name"] for f in lo1.source_attributes["junos_filters"]} == {"LOOP6"}

