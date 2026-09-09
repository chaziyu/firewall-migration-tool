from fwmigrate.parsers.fortigate.parser import parse_fortigate_config
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer


def test_sdwan_zone_fields_are_typed_and_invalid_int_is_preserved():
    fg = parse_fortigate_config('''
config system sdwan
    config zone
        edit "Overlay"
            set advpn-health-check "overlay-hc"
            set advpn-select enable
            set minimum-sla-meet-members 2
            set service-sla-tie-break fib-best-match
        next
        edit "Broken"
            set minimum-sla-meet-members invalid
            set future-zone-setting "retained"
        next
    end
end
''')
    overlay, broken = fg.sdwans[0].zones
    assert overlay.minimum_sla_meet_members == 2
    assert overlay.advpn_health_check == "overlay-hc"
    assert overlay.advpn_select == "enable"
    assert overlay.service_sla_tie_break == "fib-best-match"
    assert broken.minimum_sla_meet_members is None
    assert broken.extra_settings == {
        "unparsed_minimum_sla_meet_members": "invalid",
        "future_zone_setting": "retained",
    }

    ir_zone = FGToIRTransformer(fg).transform().sdwans[0].zones[0]
    assert ir_zone.source_minimum_sla_meet_members == 2
    assert ir_zone.source_service_sla_tie_break == "fib-best-match"


def test_sdwan_member_only_zone_has_no_explicit_zone_settings():
    fg = parse_fortigate_config('''
config system sdwan
    config members
        edit 1
            set interface "wan1"
            set zone "Referenced"
        next
    end
end
''')
    zone = FGToIRTransformer(fg).transform().zones[0]
    assert zone.name == "Referenced"
    assert zone.source_attributes == {}

