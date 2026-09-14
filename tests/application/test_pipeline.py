from unittest.mock import patch

from tests.fixture_paths import CISCO_ASA_FIXTURE

from fwmigrate.application import MigrationPipeline, MigrationRequest
from fwmigrate.application.models import MigrationArtifact
from fwmigrate.core.optimizer import RuleOptimizer


def request(**overrides):
    values = {
        "source_vendor": "cisco_asa",
        "target_vendor": "palo_alto",
        "source_content": CISCO_ASA_FIXTURE.read_text(encoding="utf-8"),
        "target_format": "xml",
    }
    values.update(overrides)
    return MigrationRequest(**values)


def test_pipeline_returns_source_and_final_ir():
    result = MigrationPipeline().run(request())

    assert result.source_ir is not result.final_ir
    assert result.extraction.canonical_ir is not result.final_ir
    assert result.artifacts
    assert result.target_display_name == "Palo Alto Networks (PAN-OS / Panorama)"


def test_optimizer_is_optional():
    with patch("fwmigrate.application.pipeline.RuleOptimizer", autospec=True) as optimizer:
        result = MigrationPipeline().run(request())

    assert result.generation_allowed
    optimizer.assert_not_called()


def test_pipeline_uses_optimizer_when_requested():
    with patch.object(RuleOptimizer, "find_unused_objects", return_value={
        "unused_addresses": [],
        "unused_services": [],
    }) as find_unused:
        result = MigrationPipeline().run(request(optimize=True))

    assert result.generation_allowed
    assert find_unused.call_count == 2
    assert result.unused_objects["unused_addresses"] == []


def test_pipeline_preserves_generator_artifacts():
    result = MigrationPipeline().run(request())

    assert all(isinstance(artifact, MigrationArtifact) for artifact in result.artifacts)
