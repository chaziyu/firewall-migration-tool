from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.fortigate.section_scanner import scan_fortigate_sections


def test_scanner_discovers_nested_empty_and_unknown_sections():
    config = """config system interface
    edit "port1"
        config secondaryip
            edit 1
            next
        end
    next
end
config firewall empty-section
end
config system unknown-feature
    edit "x"
    next
end
"""

    sections = scan_fortigate_sections(config)
    by_path = {section.path: section for section in sections}

    assert list(by_path) == [
        "system interface",
        "system interface secondaryip",
        "firewall empty-section",
        "system unknown-feature",
    ]
    assert by_path["system interface"].line_start == 1
    assert by_path["system interface"].line_end == 8
    assert by_path["system interface"].object_count_source == 1
    assert by_path["system interface secondaryip"].line_start == 3
    assert by_path["system interface secondaryip"].line_end == 6
    assert by_path["system interface secondaryip"].object_count_source == 1
    assert by_path["firewall empty-section"].object_count_source == 0
    assert by_path["system unknown-feature"].object_count_source == 1
    assert all(section.status == ExtractionStatus.UNSUPPORTED for section in sections)


def test_scanner_closes_unterminated_section_at_eof():
    sections = scan_fortigate_sections("config firewall mystery\n    edit x\n")

    assert len(sections) == 1
    assert sections[0].line_end == 2
    assert "matching end" in sections[0].notes[0]

