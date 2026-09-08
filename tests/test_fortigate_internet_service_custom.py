from fwmigrate.parsers.fortigate.parser import parse_fortigate_config
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer


def test_custom_service_keeps_ipv4_ipv6_and_port_hierarchy():
    fg = parse_fortigate_config("""
config firewall internet-service-custom
    edit "custom-web"
        set comment "Custom web"
        config entry
            edit 1
                set addr-mode both
                set dst 192.0.2.0/24
                set dst6 2001:db8::/32
                set protocol 6
                set reputation 3
                set future-entry keep
                config port-range
                    edit 1
                        set start-port 80
                        set end-port 443
                    next
                end
            next
        end
    next
end
""")
    item = fg.custom_internet_services[0]
    entry = item.entries[0]
    assert (entry.addr_mode, entry.dst, entry.dst6, entry.protocol, entry.reputation) == (
        "both", ["192.0.2.0/24"], ["2001:db8::/32"], 6, 3
    )
    assert entry.extra_settings == {"future_entry": "keep"}
    ir_entry = FGToIRTransformer(fg).transform().custom_internet_services[0].entries[0]
    assert ir_entry.destination_ipv6 == ["2001:db8::/32"]
