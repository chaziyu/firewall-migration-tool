from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.vendors.cisco_ftd.source_accounting import account_cli_sections, project_collection_completeness
from fwmigrate.vendors.cisco_ftd.source_analysis import _text_source
from fwmigrate.vendors.cisco_ftd.source_analysis import extract_cisco_ftd_source


def test_cli_accounting_keeps_malformed_routes_as_parse_error():
    source = "route\n"
    sections = account_cli_sections(source, _text_source(source))
    assert len(sections) == 1
    assert sections[0].status is ExtractionStatus.PARSE_ERROR
    assert sections[0].object_count_extracted == 0


def test_collection_completeness_is_projected_without_mutating_source():
    config = _text_source("interface GigabitEthernet0/0")
    sections = []
    project_collection_completeness(config, sections)
    assert sections == []


def test_unsupported_cli_block_is_retained_once_with_range_and_review_finding():
    source = "access-list UNIQUE_ACL extended permit ip any any\n password SECRET_VALUE\n!\ninterface inside\n description LAN\n"
    result = extract_cisco_ftd_source(source)
    evidence, = result.unsupported_items
    assert evidence["source_path"] == "ftd-cli/other"
    assert (evidence["line_start"], evidence["line_end"]) == (1, 2)
    assert "UNIQUE_ACL" in evidence["raw"] and "SECRET_VALUE" not in evidence["raw"]
    assert result.source_sections[0].status is ExtractionStatus.UNSUPPORTED
    assert result.source_sections[0].object_count_source == 1
    assert any(issue.category == "unsupported" for issue in result.validation.issues)
    before = result.config.model_dump(mode="json")
    account_cli_sections(source, result.config)
    assert result.config.model_dump(mode="json") == before
