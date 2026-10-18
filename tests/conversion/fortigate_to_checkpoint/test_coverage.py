from dataclasses import replace

from fwmigrate.conversion.fortigate_to_checkpoint.application.workflow import build_review
from fwmigrate.conversion.fortigate_to_checkpoint.review.coverage import build_coverage


def test_inventory_coverage_preserves_scope_and_approval(checkpoint_analysis, checkpoint_options):
    analysis, options = checkpoint_analysis, checkpoint_options
    review = build_review(analysis, options, "source")
    coverage = review["report"]["coverage"]
    assert coverage["source_record_count"] == len(coverage["records"])
    assert coverage["inventory_available"]
    assert not coverage["export_is_complete_migration"]
    assert all(row["source_vdom"] in {None, options.source_vdom} for row in coverage["records"])
    assert "RENDERED" not in coverage["status_counts"]
    assert "REUSED" not in coverage["status_counts"]
    assert "PENDING" in coverage["status_counts"]
    exported = build_coverage(review["plan"], analysis.extracted.source_objects,
                              analysis.derived, approved_items=[])
    assert exported == coverage
    record = analysis.extracted.source_objects[0]
    unknown = replace(record, source_path="unsupported feature", object_name="opaque", vdom=options.source_vdom)
    result = build_coverage(review["plan"], (unknown, unknown), analysis.derived, approved_items=[])
    assert len(result["records"]) == 2
    assert result["status_counts"] == {"MANUAL": 2}
    assert all(not row["plan_item_keys"] for row in result["records"])
