from fwmigrate.parsers.fortigate.parser import parse_fortigate_config
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer


def test_system_zone_fields_and_nested_tagging_are_preserved():
    fg = parse_fortigate_config('''
config system zone
    edit "Trust"
        set description "Main zone"
        set interface "port 1" "port2"
        set intrazone allow
        set future-setting "keep me"
        config tagging
            edit "location"
                set category "site name"
                set tags "HQ" "Primary"
                append tags "Critical"
                set future-entry "retained"
            next
        end
    next
end
''')
    zone = fg.system_zones[0]
    assert zone.interface == ["port 1", "port2"]
    assert zone.description == "Main zone"
    assert zone.intrazone == "allow"
    assert zone.extra_settings == {"future_setting": "keep me"}
    assert zone.tagging[0].name == "location"
    assert zone.tagging[0].category == "site name"
    assert zone.tagging[0].tags == ["HQ", "Primary", "Critical"]
    assert zone.tagging[0].extra_settings == {"future_entry": "retained"}
    assert zone.nested_configs[0].name == "tagging"
    assert zone.nested_configs[0].children[0].commands[-1].key == "future-entry"

    ir_zone = FGToIRTransformer(fg).transform().zones[0]
    assert ir_zone.source_intrazone == "allow"
    assert ir_zone.source_tagging_entries[0].tags == ["HQ", "Primary", "Critical"]
    assert ir_zone.requires_manual_review is True
    assert ir_zone.migration_status == "PARTIALLY_NORMALIZED"


def test_system_zone_unset_intrazone_and_namespaces_do_not_collide():
    fg = parse_fortigate_config('''
config system zone
    edit "WAN"
        set intrazone allow
        unset intrazone
    next
end
config system sdwan
    config zone
        edit "WAN"
        next
    end
end
config vdom
    edit "tenant-a"
        config system zone
            edit "WAN"
            next
        end
    next
end
''')
    assert fg.system_zones[0].intrazone is None
    zones = FGToIRTransformer(fg).transform().zones
    assert {(z.source_context, z.zone_type, z.name) for z in zones} >= {
        ("root", "system", "WAN"),
        ("root", "sdwan", "WAN"),
        ("tenant-a", "system", "WAN"),
    }

