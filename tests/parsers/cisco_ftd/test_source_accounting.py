from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.vendors.cisco_ftd.source_accounting import account_cli_sections, project_collection_completeness
from fwmigrate.vendors.cisco_ftd.source_analysis import _text_source


def test_cli_accounting_keeps_malformed_routes_as_parse_error():
    source = "route\n"
    sections = account_cli_sections(source, _text_source(source, None))
    assert len(sections) == 1
    assert sections[0].status is ExtractionStatus.PARSE_ERROR
    assert sections[0].object_count_extracted == 0


def test_collection_completeness_is_projected_without_mutating_source():
    config = _text_source("interface GigabitEthernet0/0", None)
    sections = []
    project_collection_completeness(config, sections)
    assert sections == []
