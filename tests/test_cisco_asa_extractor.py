from fwmigrate.extraction.models import ExtractionResult, ExtractionStatus
from fwmigrate.parsers.cisco_asa.extractor import extract_cisco_asa_config


def test_extractor_accounts_for_supported_unsupported_and_unknown_commands():
    result = extract_cisco_asa_config("""
hostname edge
access-list A extended permit ip any any
crypto ikev2 enable outside
made-up-command value
""")
    assert isinstance(result, ExtractionResult)
    assert len(result.inventory_items) == 4
    statuses = {section.path: section.status for section in result.source_sections}
    assert statuses["system hostname"] == ExtractionStatus.NORMALIZED
    assert statuses["access-list"] == ExtractionStatus.PARTIALLY_NORMALIZED
    assert statuses["crypto ikev2"] == ExtractionStatus.UNSUPPORTED
    assert statuses["other"] == ExtractionStatus.UNSUPPORTED
    assert result.unsupported_items


def test_extractor_redacts_cisco_secrets():
    secret = "do-not-export"
    result = extract_cisco_asa_config(f"""
username admin password {secret}
tunnel-group peer ipsec-attributes pre-shared-key {secret}
snmp-server community {secret}
""")
    serialized = result.model_dump_json()
    assert secret not in serialized
    assert "[REDACTED]" in serialized

