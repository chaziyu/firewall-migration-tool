from fwmigrate.vendors.juniper_srx.derived import build_juniper_derived_views
from fwmigrate.vendors.juniper_srx.parser import JuniperSRXParser


def test_nat_rule_ownership_pool_usage_and_static_prefix_are_derived():
    config = JuniperSRXParser("\n".join([
        "set security address-book global address PUBLIC 203.0.113.8/32",
        "set security nat source pool SP address 192.0.2.8",
        "set security nat source rule-set SRC from zone trust",
        "set security nat source rule-set SRC to zone untrust",
        "set security nat source rule-set SRC rule R1 match source-address 10.0.0.0/24",
        "set security nat source rule-set SRC rule R1 then source-nat pool SP",
        "set security nat source rule-set SRC rule R2 then source-nat interface",
        "set security nat destination pool DP address 192.0.2.9/32",
        "set security nat destination rule-set DST rule D1 then destination-nat pool DP",
        "set security nat static rule-set STATIC rule S1 then static-nat prefix-name PUBLIC",
    ])).extract_source()
    derived = build_juniper_derived_views(config)
    by_name = {row["rule_name"]: row for row in derived.nat_usage}
    assert by_name["R1"]["rule_set_name"] == "SRC"
    assert by_name["R1"]["rule_order"] == 0
    assert by_name["R1"]["pool_name"] == "SP" and by_name["R1"]["pool_resolved"] is True
    assert by_name["D1"]["pool_resolved"] is True
    assert by_name["S1"]["nat_type"] == "static"
    assert by_name["S1"]["address_references"] == ({"field": "prefix_name", "reference": "PUBLIC", "resolved": True},)
    assert {row["pool_name"] for row in derived.nat_pool_usage} == {"SP", "DP"}
    assert "rule_set_name" not in config.get_context().nat.source_rule_sets["SRC"].rules[0].model_dump()


def test_static_nat_does_not_resolve_destination_pool_as_its_pool():
    config = JuniperSRXParser("set security nat static rule-set S rule R then static-nat prefix 203.0.113.0/24").extract_source()
    derived = build_juniper_derived_views(config)
    row = next(item for item in derived.nat_usage if item["rule_name"] == "R")
    assert row["pool_name"] is None
    assert not [item for item in derived.dependencies if item.source_object == "R" and item.expected_type.endswith("nat-pool")]
