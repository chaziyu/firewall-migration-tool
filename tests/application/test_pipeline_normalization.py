from tests.fixture_paths import CISCO_ASA_FIXTURE

from fwmigrate.application import MigrationPipeline, MigrationRequest


def test_pipeline_applies_mandatory_normalization_without_optimize():
    result = MigrationPipeline().run(MigrationRequest(
        source_vendor="cisco_asa",
        target_vendor="palo_alto",
        source_content=CISCO_ASA_FIXTURE.read_text(encoding="utf-8"),
        target_format="xml",
        source_name="example.cfg",
        optimize=False,
    ))

    assert result.generation_allowed
    assert result.final_ir is not None
    assert result.final_ir.metadata.input_type == "Configuration File"
