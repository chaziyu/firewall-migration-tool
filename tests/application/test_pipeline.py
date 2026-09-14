from unittest.mock import Mock, patch

from fwmigrate.application import MigrationPipeline, MigrationRequest
from fwmigrate.core.base_generator import MigrationArtifact
from fwmigrate.extraction.models import ExtractionResult
from fwmigrate.ir.core import IRConfig, IRMetadata


def _ir():
    return IRConfig(metadata=IRMetadata(source_vendor="source"))


def test_pipeline_selects_parser_and_generator_and_forwards_format():
    ir = _ir()
    extraction = ExtractionResult(canonical_ir=ir)
    parser = Mock()
    parser.extract.return_value = extraction
    generator = Mock(display_name="Target")
    generator.generate.return_value = [
        MigrationArtifact(filename="out.txt", content="output", format="txt")
    ]

    with patch("fwmigrate.application.pipeline.PluginRegistry.get_parser", return_value=parser) as get_parser, \
         patch("fwmigrate.application.pipeline.PluginRegistry.get_generator", return_value=generator) as get_generator:
        result = MigrationPipeline().run(MigrationRequest(
            source_vendor="source",
            target_vendor="target",
            source_content="config",
            target_format="txt",
        ))

    get_parser.assert_called_once_with("source")
    parser.extract.assert_called_once_with("config", zone_mapping={})
    get_generator.assert_called_once_with("target")
    generator.generate.assert_called_once_with(result.final_ir, format="txt")
    assert result.artifacts[0].filename == "out.txt"
    assert result.source_ir is not result.final_ir
    assert result.unused_objects == {}


def test_pipeline_always_runs_mandatory_fix_and_only_optimizes_when_requested():
    ir = _ir()
    extraction = ExtractionResult(canonical_ir=ir)
    parser = Mock()
    parser.extract.return_value = extraction
    generator = Mock(display_name="Target")
    generator.generate.return_value = []
    normalizer = Mock()
    optimizer = Mock()
    optimizer.prune_unused_objects.return_value = ir.model_copy(deep=True)

    with patch("fwmigrate.application.pipeline.PluginRegistry.get_parser", return_value=parser), \
         patch("fwmigrate.application.pipeline.PluginRegistry.get_generator", return_value=generator), \
         patch("fwmigrate.application.pipeline.RuleNormalizer", return_value=normalizer), \
         patch("fwmigrate.application.pipeline.RuleOptimizer", return_value=optimizer):
        MigrationPipeline().run(MigrationRequest("source", "target", "config"))

    normalizer.normalize_outbound_threat_source_anomalies.assert_called_once_with()
    optimizer.assert_not_called()

    normalizer.reset_mock()
    optimizer.reset_mock()
    with patch("fwmigrate.application.pipeline.PluginRegistry.get_parser", return_value=parser), \
         patch("fwmigrate.application.pipeline.PluginRegistry.get_generator", return_value=generator), \
         patch("fwmigrate.application.pipeline.RuleNormalizer", return_value=normalizer), \
         patch("fwmigrate.application.pipeline.RuleOptimizer", return_value=optimizer):
        MigrationPipeline().run(MigrationRequest("source", "target", "config", optimize=True))

    normalizer.normalize_outbound_threat_source_anomalies.assert_called_once_with()
    optimizer.find_unused_objects.assert_called_once_with()
    optimizer.prune_unused_objects.assert_called_once_with()


def test_pipeline_real_cisco_asa_to_palo_alto():
    from fwmigrate import generators, parsers  # noqa: F401
    from tests.fixture_paths import CISCO_ASA_FIXTURE

    result = MigrationPipeline().run(MigrationRequest(
        source_vendor="cisco_asa",
        target_vendor="palo_alto",
        source_content=CISCO_ASA_FIXTURE.read_text(encoding="utf-8"),
        target_format="xml",
    ))

    assert result.extraction.canonical_ir.metadata.source_vendor == "cisco_asa"
    assert result.artifacts[0].filename == "palo_alto_config.xml"
