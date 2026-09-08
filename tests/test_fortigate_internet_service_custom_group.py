from fwmigrate.parsers.fortigate.parser import parse_fortigate_config
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer


def test_custom_group_members_are_preserved_as_extract_only_data():
    fg = parse_fortigate_config("""
config firewall internet-service-custom-group
    edit "web-group"
        set comment "Web services"
        set member "custom-web" "custom-api"
    next
end
""")
    group = fg.custom_internet_service_groups[0]
    assert group.members == ["custom-web", "custom-api"]
    ir = FGToIRTransformer(fg).transform()
    assert ir.custom_internet_service_groups[0].members == group.members
    assert ir.custom_internet_service_groups[0].migration_status == "EXTRACT_ONLY"
