from fwmigrate.parsers.palo_alto import PANOSSourceParser

def test_pan_ha_preserves_configured_interface_values():
    xml = '<config><devices><entry name="fw"><deviceconfig><high-availability><enabled>yes</enabled><group><group-id>1</group-id><peer-ip>1.1.1.2</peer-ip></group><interface><ha1><ip-address>1.1.1.1</ip-address><netmask>255.255.255.0</netmask></ha1><ha3/></interface></high-availability></deviceconfig></entry></devices></config>'
    ir = PANOSSourceParser().parse(xml)
    assert ir.pan_high_availability.enabled is True
    assert ir.pan_high_availability.interfaces[0].ip_address == "1.1.1.1"
    assert ir.pan_high_availability.interfaces[1].ip_address is None
