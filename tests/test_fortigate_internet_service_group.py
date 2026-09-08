from fwmigrate.parsers.fortigate.parser import parse_fortigate_config
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer


def test_group_direction_is_typed_and_retained():
    fg = parse_fortigate_config("""
config firewall internet-service-group
    edit "source-group"
        set direction source
        set member "Google-Other"
    next
end
""")
    group = fg.internet_service_groups[0]
    assert (group.direction, group.members) == ("source", ["Google-Other"])
    ir = FGToIRTransformer(fg).transform().internet_service_groups[0]
    assert ir.direction == "source"
    assert ir.requires_manual_review is True
