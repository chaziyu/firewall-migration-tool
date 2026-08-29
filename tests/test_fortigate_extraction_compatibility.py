from fwmigrate.extraction.models import (
    ExtractionResult,
    ExtractionStatus,
    SourceCommand,
    SourceInventoryItem,
    SourceSectionResult,
    UnsupportedItem,
)
from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config


def test_source_command_backward_compatibility():
    """Verify SourceCommand default field values work with legacy 3-arg constructor."""
    cmd = SourceCommand(operation="set", key="subnet", values=["192.168.1.0", "255.255.255.0"])
    assert cmd.operation == "set"
    assert cmd.key == "subnet"
    assert cmd.values == ["192.168.1.0", "255.255.255.0"]
    assert cmd.line_number is None
    assert cmd.status is None
    assert cmd.parser_handler is None
    assert cmd.requires_manual_review is False


def test_source_command_extended_fields():
    """Verify SourceCommand supports new granular accounting fields."""
    cmd = SourceCommand(
        operation="set",
        key="address",
        values=["10.0.0.1/32"],
        line_number=42,
        status=ExtractionStatus.NORMALIZED,
        parser_handler="interfaces",
        requires_manual_review=False,
    )
    assert cmd.line_number == 42
    assert cmd.status == ExtractionStatus.NORMALIZED
    assert cmd.parser_handler == "interfaces"
    assert cmd.requires_manual_review is False


def test_fortigate_extraction_pipeline_compatibility():
    """Verify extract_fortigate_config runs cleanly and populates ExtractionResult."""
    fgt_config = """
    config firewall address
        edit "web_server"
            set subnet 10.1.1.100 255.255.255.255
        next
    end
    """
    result = extract_fortigate_config(fgt_config)
    assert isinstance(result, ExtractionResult)
    assert len(result.canonical_ir.addresses) >= 1
    assert any(addr.name == "web_server" for addr in result.canonical_ir.addresses)
