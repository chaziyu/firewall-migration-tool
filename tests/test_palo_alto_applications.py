from pathlib import Path

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.palo_alto.parser import PANOSSourceParser
from fwmigrate.parsers.palo_alto.source_model import PANScope


FIXTURE = Path(__file__).parent / "fixtures" / "palo_alto" / "applications.xml"


def _extract():
    parser = PANOSSourceParser()
    result = parser.extract(FIXTURE.read_text(encoding="utf-8"))
    return parser, result


def _record(result, domain, name):
    return next(item for item in result.inventory_items if item.domain == domain and item.name == name)


def test_custom_application_inventory_created():
    _, result = _extract()
    assert _record(result, "applications", "custom-chat").name == "custom-chat"


def test_custom_application_not_converted_to_service():
    _, result = _extract()
    assert all(service.name != "custom-chat" for service in result.canonical_ir.services)


def test_custom_application_attributes_preserved():
    _, result = _extract()
    attrs = _record(result, "applications", "custom-chat").source_attributes
    assert attrs["pan_category"] == "collaboration"
    assert attrs["pan_subcategory"] == "instant-messaging"
    assert attrs["pan_technology"] == "client-server"
    assert attrs["pan_risk"] == "4"
    assert "tcp/7443" in str(attrs["pan_default"])


def test_custom_application_timeout_preserved():
    _, result = _extract()
    assert _record(result, "applications", "custom-chat").source_attributes["pan_tcp_timeout"] == "3600"


def test_custom_application_signature_preserved():
    _, result = _extract()
    signatures = str(_record(result, "applications", "custom-chat").source_attributes["pan_signatures"])
    assert "chat-signature" in signatures
    assert "pattern-match" in signatures
    assert "chat-protocol" in signatures


def test_custom_application_multiple_signatures_preserved():
    _, result = _extract()
    signatures = str(_record(result, "applications", "custom-chat").source_attributes["pan_signatures"])
    assert "chat-signature" in signatures
    assert "chat-equal" in signatures
    assert "equal-to" in signatures


def test_application_group_members_preserved():
    _, result = _extract()
    attrs = _record(result, "application_groups", "custom-apps").source_attributes
    assert attrs["pan_source_members"] == ["custom-chat", "ssl"]


def test_application_filter_criteria_preserved():
    _, result = _extract()
    criteria = str(_record(result, "application_filters", "risky-collaboration").source_attributes["pan_filter_criteria"])
    assert "collaboration" in criteria
    assert "evasive" in criteria
    assert "production" in criteria


def test_application_filter_not_expanded_to_static_members():
    _, result = _extract()
    attrs = _record(result, "application_filters", "risky-collaboration").source_attributes
    assert "pan_source_members" not in attrs


def test_application_objects_are_extract_only():
    _, result = _extract()
    assert _record(result, "applications", "custom-chat").status == ExtractionStatus.EXTRACT_ONLY
    assert _record(result, "application_groups", "custom-apps").status == ExtractionStatus.EXTRACT_ONLY
    assert _record(result, "application_filters", "risky-collaboration").status == ExtractionStatus.EXTRACT_ONLY


def test_application_unknown_field_not_silently_lost():
    _, result = _extract()
    attrs = _record(result, "applications", "custom-chat").source_attributes
    assert "retain-me" in str(attrs["pan_unknown_fields"])
    filter_attrs = _record(result, "application_filters", "risky-collaboration").source_attributes
    assert "retain-me" in str(filter_attrs["pan_filter_criteria"])


def test_application_scope_preserved():
    parser, result = _extract()
    record = _record(result, "applications", "custom-chat")
    assert record.source_attributes["scope_kind"] == "vsys"
    assert record.source_attributes["scope_name"] == "vsys1"
    resolved = parser.resolver.resolve("custom-chat", "application-reference", PANScope(kind="vsys", name="vsys1"))
    assert resolved.kind == "application"


def test_application_record_exactly_once():
    _, result = _extract()
    records = [item for item in result.inventory_items if item.domain == "applications" and item.name == "custom-chat"]
    assert len(records) == 1


def test_tag_object_inventory_created():
    _, result = _extract()
    tag = _record(result, "tags", "production")
    assert tag.status == ExtractionStatus.EXTRACT_ONLY
    assert tag.source_attributes["pan_color"] == "color1"
    assert tag.source_attributes["pan_comments"] == "Production workloads"
