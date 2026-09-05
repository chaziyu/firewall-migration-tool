from fwmigrate.extraction.models import ExtractionStatus, SourceInventoryItem
from fwmigrate.parsers.checkpoint.coverage import aggregate_checkpoint_coverage
from fwmigrate.parsers.checkpoint.models import CheckPointResponse


def _item(status, *, domain="D1", source_id=None, source_type="access-rule", name=None, notes=None, evidence_class="configuration", source_path=None):
    return SourceInventoryItem(
        domain=domain, source_path=source_path or "checkpoint/show-access-rulebase",
        source_id=source_id, source_type=source_type, name=name,
        status=status, notes=notes or [], evidence_class=evidence_class,
    )


def _summary(coverage, section, domain="D1", *, operational=False, scope="domain"):
    return next(item for item in coverage if item.section == section
                and item.domain_name == domain and item.operational == operational
                and item.scope == scope)


def test_final_status_counts_are_exact_and_parse_error_wins():
    coverage = aggregate_checkpoint_coverage(
        [_item(ExtractionStatus.NORMALIZED, source_id=f"n{i}") for i in range(5)]
        + [_item(ExtractionStatus.PARTIALLY_NORMALIZED, source_id=f"p{i}") for i in range(2)]
        + [_item(ExtractionStatus.PARSE_ERROR, source_id="e1")]
    )
    summary = _summary(coverage, "Access Control")
    assert (summary.total, summary.normalized, summary.partial, summary.parse_errors) == (8, 5, 2, 1)
    assert summary.status == ExtractionStatus.PARSE_ERROR


def test_operational_cluster_evidence_does_not_downgrade_persistent_coverage():
    coverage = aggregate_checkpoint_coverage([
        _item(ExtractionStatus.NORMALIZED, source_type="checkpoint-cluster", source_id="c1"),
        _item(ExtractionStatus.EXTRACT_ONLY, source_type="checkpoint-cluster-operational-state", source_id="runtime", evidence_class="operational"),
    ])
    assert _summary(coverage, "ClusterXL").status == ExtractionStatus.NORMALIZED
    assert _summary(coverage, "ClusterXL", operational=True).status == ExtractionStatus.EXTRACT_ONLY


def test_supported_empty_is_not_unsupported_or_parse_error():
    coverage = aggregate_checkpoint_coverage([
        ], [CheckPointResponse(command="show-radius-servers", collection_status="SUCCESS_EMPTY", data={})])
    summary = _summary(coverage, "Authentication", "global")
    assert summary.supported_empty
    assert summary.status not in {ExtractionStatus.UNSUPPORTED, ExtractionStatus.PARSE_ERROR}
    assert "supported-empty" in summary.review_reasons


def test_permission_denied_is_not_empty():
    coverage = aggregate_checkpoint_coverage([
        ], [CheckPointResponse(command="show-server-certificates", collection_status="PERMISSION_DENIED", error="denied")])
    summary = _summary(coverage, "Certificates", "global")
    assert not summary.supported_empty
    assert summary.status == ExtractionStatus.PARSE_ERROR
    assert summary.collection_errors
    assert "collection-requires-review" in summary.review_reasons


def test_unsupported_optional_family_remains_visible_without_full_section_failure():
    coverage = aggregate_checkpoint_coverage(
        [], [CheckPointResponse(command="show-groups-with-exclusion", collection_status="UNSUPPORTED_COMMAND")]
    )
    summary = _summary(coverage, "Objects", "global")
    assert summary.status != ExtractionStatus.UNSUPPORTED
    assert "show-groups-with-exclusion:UNSUPPORTED_COMMAND" in summary.collection_errors


def test_unsupported_required_object_family_downgrades_collected_objects():
    coverage = aggregate_checkpoint_coverage(
        [_item(ExtractionStatus.NORMALIZED, source_type="host", source_id="h1", source_path="checkpoint/show-hosts")],
        [CheckPointResponse(command="show-networks", domain="D1", collection_status="UNSUPPORTED_COMMAND")],
    )
    summary = _summary(coverage, "Objects")
    assert summary.status == ExtractionStatus.UNSUPPORTED
    assert summary.normalized == 1


def test_domain_aggregation_and_overall_status_do_not_overwrite_domains():
    coverage = aggregate_checkpoint_coverage([
        _item(ExtractionStatus.NORMALIZED, domain="A", source_id="a1"),
        _item(ExtractionStatus.PARTIALLY_NORMALIZED, domain="B", source_id="b1"),
    ])
    assert _summary(coverage, "Access Control", "A").status == ExtractionStatus.NORMALIZED
    assert _summary(coverage, "Access Control", "B").status == ExtractionStatus.PARTIALLY_NORMALIZED
    assert _summary(coverage, "Access Control", "overall", scope="overall").status == ExtractionStatus.PARTIALLY_NORMALIZED


def test_duplicate_inventory_is_counted_once_per_domain():
    coverage = aggregate_checkpoint_coverage([
        _item(ExtractionStatus.NORMALIZED, domain="A", source_id="same"),
        _item(ExtractionStatus.NORMALIZED, domain="A", source_id="same"),
        _item(ExtractionStatus.NORMALIZED, domain="B", source_id="same"),
    ])
    overall = _summary(coverage, "Access Control", "overall", scope="overall")
    assert overall.total == 2


def test_placeholder_and_unresolved_reference_cannot_count_as_normalized():
    coverage = aggregate_checkpoint_coverage([
        _item(ExtractionStatus.NORMALIZED, source_id="missing", name="<missing-access-layer-placeholder>", notes=["placeholder"]),
        _item(ExtractionStatus.NORMALIZED, source_id="blocked", notes=["cross-domain-reference-resolution-blocked"]),
    ])
    summary = _summary(coverage, "Access Control")
    assert summary.normalized == 0
    assert summary.partial == 2
    assert summary.status == ExtractionStatus.PARTIALLY_NORMALIZED


def test_mixed_threat_prevention_families_are_partial():
    coverage = aggregate_checkpoint_coverage([
        _item(ExtractionStatus.NORMALIZED, source_type="threat-prevention-profile", source_id="profile"),
        _item(ExtractionStatus.EXTRACT_ONLY, source_type="threat-prevention-rule", source_id="rule"),
    ])
    summary = _summary(coverage, "Threat Prevention")
    assert summary.status == ExtractionStatus.PARTIALLY_NORMALIZED
    assert summary.normalized == 1
    assert summary.extract_only == 1
