from fwmigrate.parsers.palo_alto import PANOSSourceParser

def test_pan_advanced_settings_preserve_explicit_values():
    xml = '<config><devices><entry name="fw"><deviceconfig><setting><session><rematch>yes</rematch><timeout-default>30</timeout-default></session><tcp><urgent-data>clear</urgent-data></tcp></setting></deviceconfig></entry></devices></config>'
    ir = PANOSSourceParser().parse(xml)
    assert ir.pan_device_operational_settings.rematch_sessions is True
    assert ir.pan_device_operational_settings.session_timeout_default_seconds == 30
