from pathlib import Path

from fwmigrate.vendors.checkpoint.extraction import CheckPointSourceRecord
from fwmigrate.vendors.checkpoint.source_report import extract_checkpoint_source


def test_reference_views_are_derived_and_source_records_remain_unchanged():
    source = (Path(__file__).parents[2] / "fixtures" / "checkpoint" / "r81_golden_matrix.json").read_text()
    result = extract_checkpoint_source(source)
    assert isinstance(result.derived.broken_references, tuple)
    assert result.config.hosts
    assert all(not isinstance(item, CheckPointSourceRecord) for item in result.derived.references.by_uid.values())
    assert result.derived.references.by_name
    assert result.derived.by_uid is result.derived.references.by_uid
    assert result.derived.by_name is result.derived.references.by_name
    assert result.derived.package_layers == result.derived.policy_structure.package_layer_map
    assert result.derived.inline_layers == result.derived.policy_structure.inline_layer_map
    expected_memberships = {}
    for edge in result.derived.references.memberships:
        owner = edge.owner
        key = owner.uid or f"{owner.domain_uid or owner.domain or 'global'}:{owner.name}"
        expected_memberships.setdefault(key, []).append(edge.member_reference)
    assert result.derived.group_memberships == {
        key: tuple(values) for key, values in expected_memberships.items()
    }
    assert len(result.derived.unresolved_references) == len(result.derived.broken_references)
