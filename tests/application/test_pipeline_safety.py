from tests.fixture_paths import FORTIGATE_FIXTURE

from fwmigrate.application import MigrationPipeline, MigrationRequest


def test_pipeline_blocks_unsafe_source_before_generation():
    result = MigrationPipeline().run(MigrationRequest(
        source_vendor="fortigate",
        target_vendor="palo_alto",
        source_content=FORTIGATE_FIXTURE.read_text(encoding="utf-8"),
        target_format="xml",
    ))

    assert result.generation_allowed is False
    assert result.artifacts == []
    assert result.blocking_reasons
    assert result.final_ir is None
