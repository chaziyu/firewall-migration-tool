from fwmigrate.parsers.fortigate.parser import parse_fortigate_config
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer


def test_append_fields_are_typed_and_extract_only():
    fg = parse_fortigate_config("""
config firewall internet-service-append
    edit 100
        set addr-mode ipv4
        set append-port 8080
        set match-port 80
        set future-option retained
    next
end
""")
    item = fg.internet_service_appends[0]
    assert (item.id, item.addr_mode, item.append_port, item.match_port) == (100, "ipv4", 8080, 80)
    assert item.extra_settings == {"future_option": "retained"}
    ir = FGToIRTransformer(fg).transform()
    assert ir.internet_service_appends[0].requires_manual_review is True
