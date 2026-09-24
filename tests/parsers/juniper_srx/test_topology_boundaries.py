from copy import deepcopy

from fwmigrate.vendors.juniper_srx.derived import build_juniper_derived_views
from fwmigrate.vendors.juniper_srx.relationships import build_juniper_dependencies
from fwmigrate.vendors.juniper_srx.source_report import extract_juniper_source
from fwmigrate.vendors.juniper_srx.validation import validate_juniper_config


def test_interface_topology_is_derived_without_synthetic_source_objects():
    result = extract_juniper_source("""set interfaces ae0 description uplink
set interfaces ge-0/0/0 ether-options 802.3ad ae0
set interfaces ge-0/0/1 ether-options 802.3ad ae0
set interfaces ge-0/0/2 gigether-options redundant-parent reth0
set interfaces irb unit 10 family inet address 192.0.2.1/24
""")
    context = result.config.get_context()
    assert set(context.interfaces) == {"ae0", "ge-0/0/0", "ge-0/0/1", "ge-0/0/2", "irb"}
    assert context.interfaces["ae0"].description == "uplink"
    assert context.interfaces["ge-0/0/0"].aggregate_parent == "ae0"
    assert context.interfaces["ge-0/0/2"].redundant_parent == "reth0"
    assert not hasattr(context.interfaces["ae0"], "aggregate_members")

    rows = {row["interface"]: row for row in result.derived.interface_topology if row["unit"] is None}
    assert rows["ae0"]["aggregate_members"] == ("ge-0/0/0", "ge-0/0/1")
    assert rows["reth0"]["source_present"] is False
    assert rows["reth0"]["redundant_members"] == ("ge-0/0/2",)
    assert rows["reth0"]["redundant_parent_resolved"] is False
    assert rows["ae0"]["interface_type"] == "aggregate-ethernet"
    assert rows["irb"]["interface_type"] == "irb"


def test_topology_resolves_unit_zone_and_routing_instance_memberships():
    result = extract_juniper_source("""set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24
set security zones security-zone trust interfaces ge-0/0/0.0
set routing-instances VR instance-type virtual-router
set routing-instances VR interface ge-0/0/0.0
""")
    unit = next(row for row in result.derived.interface_topology if row["name"] == "ge-0/0/0.0")
    assert unit["parent"] == "ge-0/0/0"
    assert unit["zone_memberships"] == ("trust",)
    assert unit["routing_instance_memberships"] == ("VR",)


def test_same_interface_names_remain_context_scoped():
    result = extract_juniper_source("""set logical-systems L1 interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24
set logical-systems L1 security zones security-zone trust interfaces ge-0/0/0.0
set logical-systems L2 interfaces ge-0/0/0 unit 0 family inet address 198.51.100.1/24
""")
    rows = [row for row in result.derived.interface_topology if row["name"] == "ge-0/0/0.0"]
    assert {row["context"] for row in rows} == {"logical-system L1", "logical-system L2"}
    assert next(row for row in rows if row["context"].endswith("L1"))["zone_memberships"] == ("trust",)
    assert next(row for row in rows if row["context"].endswith("L2"))["zone_memberships"] == ()


def test_unresolved_parent_and_nat_rule_ownership_do_not_mutate_source():
    result = extract_juniper_source("""set interfaces ge-0/0/0 ether-options 802.3ad ae99
set security nat source rule-set RS1 rule R1 match source-address 10.0.0.0/24
set security nat source rule-set RS1 rule R1 then source-nat interface
set security nat source rule-set RS1 from zone trust
set security nat source rule-set RS1 to zone untrust
""")
    config = result.config
    before = deepcopy(config.model_dump(mode="python"))
    ruleset = config.get_context().nat.source_rule_sets["RS1"]
    assert ruleset.from_context.zones == ["trust"]
    assert ruleset.to_context.zones == ["untrust"]
    assert "junos_rule_set_context" not in ruleset.rules[0].source_attributes

    unresolved = [item for item in result.derived.dependencies
                  if item.source_field == "aggregate-parent" and item.reference == "ae99"]
    assert len(unresolved) == 1 and unresolved[0].result == "UNRESOLVED"
    assert "ae99" not in config.get_context().interfaces
    assert any(issue.category == "reference" for issue in result.validation.issues)
    derived = build_juniper_derived_views(config)
    dependencies = build_juniper_dependencies(config)
    validate_juniper_config(config, derived)
    assert any(item.source_field == "aggregate-parent" and item.reference == "ae99"
               for item in dependencies)
    assert config.model_dump(mode="python") == before
