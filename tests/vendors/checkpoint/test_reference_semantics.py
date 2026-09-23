from pathlib import Path

from fwmigrate.vendors.checkpoint.source_report import extract_checkpoint_source


def test_reference_views_are_derived_and_source_records_remain_unchanged():
    source = (Path(__file__).parents[2] / "fixtures" / "checkpoint" / "r81_golden_matrix.json").read_text()
    result = extract_checkpoint_source(source)
    assert isinstance(result.derived.unresolved_references, tuple)
    assert result.config.network_objects
