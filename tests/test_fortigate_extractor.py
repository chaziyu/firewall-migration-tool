from fwmigrate.extraction.models import ExtractionResult, ExtractionStatus
from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.parsers.fortigate.parser import parse_fortigate_config
from fwmigrate.parsers.fortigate.section_scanner import scan_fortigate_sections


def test_extractor_classifies_every_discovered_section():
    config = """config firewall address
    edit "lan"
        set subnet 10.0.0.0 255.255.255.0
    next
end
config application list
    edit "monitor-only"
        set comment "source inventory"
    next
end
config switch-controller global
    set allow-multiple-interfaces enable
end
config system mystery
    edit "unknown-object"
        set enabled yes
    next
end
"""

    result = extract_fortigate_config(config)

    assert isinstance(result, ExtractionResult)
    assert result.canonical_ir.addresses[0].name == "lan"
    statuses = {section.path: section.status for section in result.source_sections}
    assert statuses == {
        "firewall address": ExtractionStatus.NORMALIZED,
        "application list": ExtractionStatus.EXTRACT_ONLY,
        "switch-controller global": ExtractionStatus.IGNORED_BY_POLICY,
        "system mystery": ExtractionStatus.UNSUPPORTED,
    }
    assert len(result.source_sections) == 4
    assert {item.source_path for item in result.inventory_items} == {
        "application list",
        "system mystery",
    }
    assert [item.source_path for item in result.unsupported_items] == ["system mystery"]
    assert result.unsupported_items[0].raw_capture is None


def test_legacy_parser_remains_independently_available():
    parsed = parse_fortigate_config(
        "config firewall address\nedit x\nset subnet 192.0.2.1 255.255.255.255\nnext\nend"
    )

    assert parsed.addresses[0].name == "x"


def test_source_command_evidence_redacts_secret_values():
    result = extract_fortigate_config(
        "config system mystery\n"
        "edit x\n"
        "set password do-not-retain\n"
        "next\n"
        "end"
    )

    command = result.inventory_items[0].commands[0]
    assert command.values == ["[REDACTED]"]
    assert "do-not-retain" not in result.model_dump_json()


def test_set_only_extract_only_section_preserves_commands():
    result = extract_fortigate_config(
        "config vpn ssl settings\n"
        "set tunnel-ip-pools pool-a\n"
        "append authentication-rule rule-a\n"
        "unset source-interface\n"
        "end"
    )

    item = result.inventory_items[0]
    assert item.source_path == "vpn ssl settings"
    assert [(command.operation, command.key, command.values) for command in item.commands] == [
        ("set", "tunnel-ip-pools", ["pool-a"]),
        ("append", "authentication-rule", ["rule-a"]),
        ("unset", "source-interface", []),
    ]


def test_appliance_sections_are_ignored_by_policy_but_unknown_remains_unsupported():
    result = extract_fortigate_config('''config system replacemsg admin
    edit "msg"
    next
end
config switch-controller managed-switch
end
config wireless-controller vap
end
config system truly-unknown
end
''')
    by_path = {section.path: section for section in result.source_sections}
    assert by_path["system replacemsg admin"].status == ExtractionStatus.IGNORED_BY_POLICY
    assert "replacement-message" in by_path["system replacemsg admin"].notes[0]
    assert by_path["switch-controller managed-switch"].status == ExtractionStatus.IGNORED_BY_POLICY
    assert by_path["wireless-controller vap"].status == ExtractionStatus.IGNORED_BY_POLICY
    assert by_path["system truly-unknown"].status == ExtractionStatus.UNSUPPORTED


def test_every_scanned_section_occurrence_receives_an_explicit_status():
    config = '''config router bgp
    set as 65001
end
config system mystery
end
config system mystery
end
config switch-controller global
end
'''
    scanned = scan_fortigate_sections(config)
    result = extract_fortigate_config(config)
    allowed = set(ExtractionStatus)

    assert len(result.source_sections) == len(scanned)
    for discovered, classified in zip(scanned, result.source_sections):
        assert (classified.path, classified.line_start, classified.line_end) == (
            discovered.path,
            discovered.line_start,
            discovered.line_end,
        )
        assert classified.status in allowed

    duplicates = [
        section for section in result.source_sections
        if section.path == "system mystery"
    ]
    assert len(duplicates) == 2


def test_ips_sensor_and_entries_have_typed_extract_only_coverage():
    result = extract_fortigate_config('''config ips sensor
    edit "high_security"
        config entries
            edit 1
                set severity medium high critical
                set action block
            next
            edit 2
                set rule 43814
                set action block
            next
        end
    next
end
''')
    sections = {section.path: section for section in result.source_sections}

    sensor = sections["ips sensor"]
    assert sensor.status == ExtractionStatus.EXTRACT_ONLY
    assert sensor.parser_handler == "FortiGateParser.build_model"
    assert sensor.object_count_source == 1
    assert sensor.object_count_parsed == 1
    assert sensor.object_count_normalized == 1

    entries = sections["ips sensor entries"]
    assert entries.status == ExtractionStatus.EXTRACT_ONLY
    assert entries.parser_handler == "FortiGateParser.build_model"
    assert entries.object_count_source == 2
    assert entries.object_count_parsed == 2
    assert entries.object_count_normalized == 2
