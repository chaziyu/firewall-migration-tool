from fwmigrate.parsers.fortigate.parser import parse_fortigate_config
from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer


def test_extension_keeps_disable_entries_separate_from_additional_entries():
    fg = parse_fortigate_config("""
config firewall internet-service-extension
    edit 100
        set comment "Extension"
        config disable-entry
            edit 1
                set addr-mode ipv4
                set ip-range 192.0.2.1 192.0.2.2
                set protocol 6
            next
        end
        config entry
            edit 2
                set addr-mode ipv6
                set dst6 2001:db8::/32
                set protocol 17
            next
        end
    next
end
""")
    item = fg.internet_service_extensions[0]
    assert len(item.disable_entries) == 1
    assert len(item.entries) == 1
    assert item.disable_entries[0].ip_range == ["192.0.2.1", "192.0.2.2"]
    ir = FGToIRTransformer(fg).transform().internet_service_extensions[0]
    assert ir.disable_entries[0].ipv4_ranges[0].value == "192.0.2.1"
    assert ir.entries[0].destination_ipv6 == ["2001:db8::/32"]


def test_invalid_ports_are_retained_and_block_unsafe_generation():
    result = extract_fortigate_config("""
config firewall internet-service-extension
    edit 100
        config entry
            edit 1
                config port-range
                    edit 1
                        set start-port 500
                        set end-port 400
                    next
                end
            next
        end
    next
end
""")
    port = result.canonical_ir.internet_service_extensions[0].entries[0].port_ranges[0]
    assert (port.start_port, port.end_port) == (500, 400)
    assert result.generation_safe is False
