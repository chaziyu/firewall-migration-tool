from fwmigrate.parsers.palo_alto import PANOSSourceParser


def test_direct_deviceconfig_unknown_child_is_unsupported():
    result = PANOSSourceParser().extract('<config><devices><entry name="fw"><deviceconfig><future-device-option><x>1</x></future-device-option></deviceconfig></entry></devices></config>')
    assert any(item.status.value == "UNSUPPORTED" and "future-device-option" in item.source_path for item in result.inventory_items)


def test_phase94_missing_required_log_profile_name_is_parse_error_without_placeholder():
    result = PANOSSourceParser().extract('<config><shared><log-settings><syslog><entry><server><entry name="s"><address>10.0.0.1</address></entry></server></entry></syslog></log-settings></shared></config>')
    assert not result.canonical_ir.pan_log_server_profiles
    assert any(item.status.value == "PARSE_ERROR" and item.name is None for item in result.inventory_items)
