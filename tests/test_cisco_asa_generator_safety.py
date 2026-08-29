from fwmigrate.generators.cisco_asa.cli_generator import CiscoASACLIGenerator
from fwmigrate.ir.core import IRConfig, IRMetadata, IRNATRule, IRPolicy, IRRoute
from fwmigrate.ir.enums import NATType, PolicyAction


def test_generator_does_not_choose_first_reference_or_invent_route_values():
    ir = IRConfig(
        metadata=IRMetadata(hostname="safe"),
        policies=[IRPolicy(
            name="multiple", from_zone=["inside"], to_zone=["outside"],
            source=["a", "b"], destination=["d"], service=["s"],
            action=PolicyAction.ALLOW,
        )],
        routes=[IRRoute(name="missing", destination="0.0.0.0/0")],
    )
    output = CiscoASACLIGenerator().generate(ir)
    assert "access-list inside_access_in" not in output
    assert "route outside" not in output
    assert "192.168.1.1" not in output


def test_generator_preserves_restrictive_nat_source_and_withholds_twice_nat():
    ir = IRConfig(
        metadata=IRMetadata(hostname="safe"),
        nat_rules=[
            IRNATRule(
                name="source", type=NATType.SOURCE,
                from_zone=["inside"], to_zone=["outside"],
                source=["REAL"], destination=["any"], services=["any"],
                translated_sources=["MAPPED"],
                source_attributes={"source_mode": "static"},
            ),
            IRNATRule(
                name="twice", type=NATType.TWICE,
                from_zone=["inside"], to_zone=["outside"],
                source=["REAL"], destination=["DST"], services=["any"],
                translated_sources=["MAPPED"], translated_destinations=["NEWDST"],
            ),
        ],
    )
    output = CiscoASACLIGenerator().generate(ir)
    assert "source static REAL MAPPED" in output
    assert "source static any MAPPED" not in output
    assert "NAT rule twice withheld" in output
