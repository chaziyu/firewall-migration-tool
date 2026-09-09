from pathlib import Path

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.palo_alto.parser import PANOSSourceParser
from fwmigrate.parsers.palo_alto.source_model import PANScope


FIXTURE = Path(__file__).parent / "fixtures" / "palo_alto" / "objects.xml"


def _extract():
    parser = PANOSSourceParser()
    result = parser.extract(FIXTURE.read_text(encoding="utf-8"))
    return parser, result


def _group(result, name):
    return next(group for group in result.canonical_ir.address_groups if group.name == name)


def _records(result, name):
    return [item for item in result.inventory_items if item.domain == "address_groups" and item.name == name]


def test_static_address_group_extracted():
    _, result = _extract()
    group = _group(result, "Static-Group")
    assert group.is_dynamic is False
    assert group.members == ["IPv4-Host"]
    assert group.source_group_type == "static"


def test_dynamic_address_group_extracted():
    _, result = _extract()
    group = _group(result, "Dynamic-Group")
    assert group.is_dynamic is True
    assert group.dynamic_filter == "'production' and 'internet-facing'"
    assert group.source_group_type == "dynamic"


def test_address_group_description_preserved():
    _, result = _extract()
    assert _group(result, "Static-Group").description == "Static group description"


def test_address_group_tags_preserved():
    _, result = _extract()
    assert _group(result, "Static-Group").tags == ["production"]


def test_nested_address_group_reference_resolved():
    _, result = _extract()
    assert _group(result, "Nested-Group").members[0] == "Static-Group"


def test_address_group_member_uses_canonical_scoped_name():
    _, result = _extract()
    assert _group(result, "Nested-Group").members[1] == "vsys1::Scoped-Web"


def test_unresolved_address_group_member_requires_review():
    _, result = _extract()
    group = _group(result, "Unresolved-Group")
    assert group.members == ["Missing-Address"]
    assert group.requires_manual_review is True
    assert group.source_attributes["pan_unresolved_members"] == ["Missing-Address"]
    assert _records(result, "Unresolved-Group")[0].status == ExtractionStatus.PARTIALLY_NORMALIZED


def test_static_and_dynamic_same_entry_parse_error():
    _, result = _extract()
    assert all(group.name != "Both-Group" for group in result.canonical_ir.address_groups)
    assert _records(result, "Both-Group")[0].status == ExtractionStatus.PARSE_ERROR


def test_address_group_unknown_field_is_partial():
    _, result = _extract()
    group = _group(result, "Unknown-Group")
    assert group.source_attributes["pan_unknown_fields"] == {"future-setting": "retain-me"}
    assert _records(result, "Unknown-Group")[0].status == ExtractionStatus.PARTIALLY_NORMALIZED


def test_address_group_exactly_one_terminal_status():
    _, result = _extract()
    assert len(_records(result, "Static-Group")) == 1
    assert _records(result, "Static-Group")[0].status == ExtractionStatus.NORMALIZED


def test_address_and_group_same_name_is_ambiguous_not_order_dependent():
    parser, result = _extract()
    scope = PANScope(kind="vsys", name="vsys1")
    assert all(group.name != "IPv4-Host" for group in result.canonical_ir.address_groups)
    assert _records(result, "IPv4-Host")[0].status == ExtractionStatus.PARSE_ERROR
    resolved = parser.resolver.resolve("IPv4-Host", "address-reference", scope)
    assert resolved is not None
    assert resolved.kind == "address"


def test_address_group_scope_collision_is_deterministic():
    _, result = _extract()
    groups = {group.members[0]: group.name for group in result.canonical_ir.address_groups if group.name.endswith("Scoped-Group")}
    assert groups["IPv4-Host"] == "vsys1::Scoped-Group"
    assert groups["vsys2::Scoped-Web"] == "vsys2::Scoped-Group"
