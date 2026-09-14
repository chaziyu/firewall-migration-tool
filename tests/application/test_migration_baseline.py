from tests.fixture_paths import CISCO_ASA_FIXTURE

from fwmigrate.application import MigrationPipeline, MigrationRequest


def test_pipeline_migrates_cisco_asa_to_palo_alto():
    result = MigrationPipeline().run(MigrationRequest(
        source_vendor="cisco_asa",
        target_vendor="palo_alto",
        source_content=CISCO_ASA_FIXTURE.read_text(encoding="utf-8"),
        target_format="xml",
        source_name="example.cfg",
    ))

    assert result.generation_allowed is True
    assert result.source_ir is not None
    assert result.final_ir is not None
    assert result.source_ir.metadata.source_vendor == "cisco_asa"
    assert result.final_ir.metadata.input_type == "Configuration File"
    assert len(result.final_ir.policies) == 3
    assert {artifact.filename for artifact in result.artifacts} == {"palo_alto_config.xml"}
    assert '<config version="11.1.0"' in result.artifacts[0].content
    assert "<devices>" in result.artifacts[0].content
