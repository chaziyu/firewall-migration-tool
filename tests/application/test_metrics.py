from tests.fixture_paths import CISCO_ASA_FIXTURE

from fwmigrate.application import MigrationPipeline, MigrationRequest


def test_pipeline_metrics_are_opt_in_and_cover_core_stages():
    request = MigrationRequest(
        source_vendor="cisco_asa",
        target_vendor="palo_alto",
        source_content=CISCO_ASA_FIXTURE.read_text(encoding="utf-8"),
        target_format="xml",
        collect_metrics=True,
    )

    result = MigrationPipeline().run(request)

    assert result.metrics is not None
    assert result.metrics.total_duration_ms > 0
    assert {metric.stage for metric in result.metrics.stages} >= {
        "extraction", "normalization", "generation"
    }
