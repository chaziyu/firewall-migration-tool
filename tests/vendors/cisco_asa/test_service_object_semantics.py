from fwmigrate.vendors.cisco_asa.parser import CiscoASAParser


def test_service_object_keeps_last_specification_and_flags_prior_conflict():
    config = CiscoASAParser(
        "object service APP\n"
        " service tcp destination eq 443\n"
        " service udp destination eq 53\n"
    ).parse_raw()
    service = config.service_objects[0]

    assert [(item.protocol, item.destination.values) for item in service.ports] == [("udp", ["53"])]
    assert service.extraction_status == "PARTIAL"
    assert "Multiple service specifications in one service object" in [item.reason for item in config.diagnostics]
    assert service.raw_extra["superseded_service_commands"] == ["service tcp destination eq 443"]
