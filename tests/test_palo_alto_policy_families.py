from pathlib import Path

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.palo_alto.parser import PANOSSourceParser


FIXTURE = Path(__file__).parent / "fixtures" / "palo_alto" / "policy_families.xml"
FAMILIES = {"decryption", "application-override", "authentication", "pbf", "qos", "dos",
            "tunnel-inspect", "sdwan", "network-packet-broker"}


def _result():
    return PANOSSourceParser().extract(FIXTURE.read_text(encoding="utf-8"))


def test_each_requested_policy_family_has_structured_terminal_extraction():
    items = [item for item in _result().inventory_items if item.domain.startswith("policy:")]
    structured = [item for item in items if item.domain.removeprefix("policy:") in FAMILIES]
    assert {item.domain.removeprefix("policy:") for item in structured} == FAMILIES
    assert all(item.status == ExtractionStatus.EXTRACT_ONLY for item in structured)
    assert all(item.source_attributes["pan_source_rule_id"] for item in structured)


def test_pre_local_post_positions_and_duplicate_names_preserve_identity():
    items = [item for item in _result().inventory_items if item.name == "duplicate-name"]
    assert {item.source_attributes["pan_rulebase_position"] for item in items} == {"pre", "post"}
    assert len({item.source_attributes["pan_source_rule_id"] for item in items}) == 2


def test_common_and_family_specific_fields_are_preserved():
    decrypt = next(item for item in _result().inventory_items if item.name == "decrypt-web")
    assert decrypt.source_attributes["pan_from"] == ["trust"]
    assert decrypt.source_attributes["pan_action"] == "decrypt"
    assert "profile" in decrypt.source_attributes["pan_family_specific"]
    assert "future-decrypt" in decrypt.source_attributes["pan_unknown_fields"]


def test_unknown_future_policy_family_remains_unsupported_per_rule():
    item = next(item for item in _result().inventory_items if item.domain == "policy:future-policy")
    assert item.name == "future-rule"
    assert item.status == ExtractionStatus.UNSUPPORTED
    assert "future-action" in str(item.source_attributes["pan_source_entry"])


def test_unknown_field_in_new_family_is_not_lost():
    broker = next(item for item in _result().inventory_items if item.domain == "policy:network-packet-broker")
    assert "future-broker" in broker.source_attributes["pan_unknown_fields"]
