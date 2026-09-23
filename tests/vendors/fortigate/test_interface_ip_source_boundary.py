from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter


def test_interface_ip_is_the_explicit_source_value():
    source = '''config system interface
    edit "wan1"
        set ip 192.0.2.10 255.255.255.0
    next
end
'''
    analysis = FortiGateSourceReporter().analyze_source(source)
    interface = next(item for item in analysis.extracted.config.interfaces if item.name == "wan1")
    assert interface.ip == "192.0.2.10 255.255.255.0"
