import pytest

from fwmigrate.parsers.fortigate.command_evaluator import evaluate_commands
from fwmigrate.parsers.fortigate.phase_41_security_profiles import (
    _effective_node_attributes,
    _effective_profile_settings,
    _typed_values,
)
from fwmigrate.parsers.fortigate.section_registry import (
    SectionSpec,
    get_section_spec,
    register_section,
)
from fwmigrate.parsers.fortigate.source_tree import FGSourceCommand, FGSourceNode
from fwmigrate.parsers.fortigate.phase_43_webfilter import (
    FGWebFilterProfile746,
    _WEB_PROFILE_SPEC,
)


def _source(*commands: FGSourceCommand) -> FGSourceNode:
    return FGSourceNode(node_type="edit", name="test", commands=list(commands))


def test_registered_direct_fields_have_one_cardinality_category():
    categories = ("list_fields", "integer_fields", "integer_list_fields", "scalar_fields")
    for path in ("user group", "firewall policy", "router policy", "system sdwan service"):
        spec = get_section_spec(path)
        assert spec is not None
        fields: dict[str, set[str]] = {
            category: set(getattr(spec, category)) for category in categories
        }
        for field in set().union(*fields.values()):
            assert sum(field in values for values in fields.values()) == 1, (path, field)


def test_section_registration_rejects_overlapping_cardinality():
    with pytest.raises(ValueError, match=r"test section.*members.*list_fields.*scalar_fields"):
        register_section(
            SectionSpec(
                source_path="test section",
                list_fields=frozenset({"members"}),
                scalar_fields=frozenset({"members"}),
            )
        )


def test_shared_evaluator_covers_list_operations_and_malformed_integer_lists():
    result = evaluate_commands(
        [
            FGSourceCommand(operation="set", key="members", values=["one"]),
            FGSourceCommand(operation="append", key="members", values=["two", "three"]),
            FGSourceCommand(operation="set", key="ids", values=["1", "bad", "3"]),
        ],
        list_fields={"members"},
        integer_list_fields={"ids"},
    )

    assert result.attributes == {"members": ["one", "two", "three"], "ids": [1, 3]}
    assert result.extra_settings["unparsed_ids"] == ["bad"]


def test_profile_spec_controls_one_value_projection_and_empty_override():
    source = _source(
        FGSourceCommand(operation="set", key="options", values=["block-invalid-url"]),
        FGSourceCommand(operation="set", key="unknown", values=["preserve"]),
    )

    settings, extra = _effective_profile_settings(
        source,
        FGWebFilterProfile746,
        field_spec=_WEB_PROFILE_SPEC,
    )
    assert settings["options"] == ["block-invalid-url"]
    assert extra["unknown"] == "preserve"
    assert _typed_values(
        settings,
        FGWebFilterProfile746,
        field_spec=_WEB_PROFILE_SPEC,
    ) == {"options": ["block-invalid-url"]}

    empty_effective, empty_extra = _effective_node_attributes(
        source,
        model=FGWebFilterProfile746,
        field_spec={},
    )
    assert empty_effective["options"] == "block-invalid-url"
    assert empty_extra["options"] == "block-invalid-url"


def test_unclassified_direct_values_do_not_use_token_count_for_typed_projection():
    source = _source(
        FGSourceCommand(operation="set", key="options", values=["one"]),
    )
    settings, extra = _effective_profile_settings(
        source,
        FGWebFilterProfile746,
        field_spec={},
    )
    assert "options" not in _typed_values(
        settings,
        FGWebFilterProfile746,
        field_spec={},
    )
    assert extra["options"] == "one"
