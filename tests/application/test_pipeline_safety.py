from types import SimpleNamespace
from unittest.mock import Mock, patch

from fwmigrate.application import MigrationPipeline, MigrationRequest
from fwmigrate.extraction.models import ExtractionResult
from fwmigrate.ir.core import IRConfig, IRMetadata, IRPolicy, IRZone
from fwmigrate.ir.enums import PolicyAction


def _ir(**kwargs):
    return IRConfig(metadata=IRMetadata(source_vendor="source"), **kwargs)


def _pipeline(extraction, generator):
    parser = Mock()
    parser.extract.return_value = extraction
    return parser, generator


def test_unsafe_extraction_never_calls_generator():
    extraction = ExtractionResult(
        canonical_ir=_ir(),
        generation_safe=False,
        blocking_reasons=["source is incomplete"],
    )
    parser, generator = _pipeline(extraction, Mock())

    with patch("fwmigrate.application.pipeline.PluginRegistry.get_parser", return_value=parser), \
         patch("fwmigrate.application.pipeline.PluginRegistry.get_generator", return_value=generator):
        result = MigrationPipeline().run(MigrationRequest("source", "target", "config"))

    assert result.generation_allowed is False
    assert result.blocking_reasons == ["source is incomplete"]
    generator.generate.assert_not_called()


def test_unsafe_final_ir_never_calls_generator():
    ir = _ir(
        generation_safe=False,
        generation_blocking_reasons=["unsafe final IR"],
    )
    parser, generator = _pipeline(ExtractionResult(canonical_ir=ir), Mock())

    with patch("fwmigrate.application.pipeline.PluginRegistry.get_parser", return_value=parser), \
         patch("fwmigrate.application.pipeline.PluginRegistry.get_generator", return_value=generator):
        result = MigrationPipeline().run(MigrationRequest("source", "target", "config"))

    assert result.generation_allowed is False
    assert result.blocking_reasons == ["unsafe final IR"]
    assert result.artifacts == []
    generator.generate.assert_not_called()


def test_safe_pipeline_still_generates():
    parser, generator = _pipeline(ExtractionResult(canonical_ir=_ir()), Mock())
    generator.display_name = "Target"
    generator.generate.return_value = []

    with patch("fwmigrate.application.pipeline.PluginRegistry.get_parser", return_value=parser), \
         patch("fwmigrate.application.pipeline.PluginRegistry.get_generator", return_value=generator):
        result = MigrationPipeline().run(MigrationRequest("source", "target", "config"))

    assert result.generation_allowed is True
    generator.generate.assert_called_once()


def test_normalization_marks_final_ir_unsafe_before_generator_selection():
    parser, generator = _pipeline(ExtractionResult(canonical_ir=_ir()), Mock())

    def mark_unsafe(ir):
        normalizer = Mock()
        ir.generation_safe = False
        ir.generation_blocking_reasons = ["normalization produced unsafe IR"]
        return normalizer

    with patch("fwmigrate.application.pipeline.PluginRegistry.get_parser", return_value=parser), \
         patch("fwmigrate.application.pipeline.PluginRegistry.get_generator", return_value=generator) as get_generator, \
         patch("fwmigrate.application.pipeline.RuleNormalizer", side_effect=mark_unsafe):
        result = MigrationPipeline().run(MigrationRequest("source", "target", "config"))

    assert result.generation_allowed is False
    assert "normalization produced unsafe IR" in result.blocking_reasons
    get_generator.assert_not_called()


def test_dependency_validation_blocks_before_generation():
    ir = _ir(
        zones=[IRZone(name="known")],
        policies=[IRPolicy(
            name="rule",
            from_zone=["missing"],
            source=["any"],
            destination=["any"],
            service=["any"],
            action=PolicyAction.ALLOW,
        )],
    )
    parser, generator = _pipeline(ExtractionResult(canonical_ir=ir), Mock())

    with patch("fwmigrate.application.pipeline.PluginRegistry.get_parser", return_value=parser), \
         patch("fwmigrate.application.pipeline.PluginRegistry.get_generator", return_value=generator) as get_generator:
        result = MigrationPipeline().run(MigrationRequest("source", "target", "config"))

    assert result.generation_allowed is False
    assert any("missing" in reason for reason in result.blocking_reasons)
    get_generator.assert_not_called()


def test_capability_blocking_issue_is_enforced_by_central_gate():
    parser, generator = _pipeline(ExtractionResult(canonical_ir=_ir()), Mock())
    capability = Mock()
    capability.analyze.return_value = [SimpleNamespace(
        severity="CRITICAL",
        blocking=True,
        message="Target cannot represent security rules",
        category="CAPABILITY_MISMATCH",
    )]

    with patch("fwmigrate.application.pipeline.PluginRegistry.get_parser", return_value=parser), \
         patch("fwmigrate.application.pipeline.PluginRegistry.get_generator", return_value=generator) as get_generator, \
         patch("fwmigrate.application.pipeline.CapabilityAnalyzer", return_value=capability):
        result = MigrationPipeline().run(MigrationRequest("source", "target", "config"))

    assert result.generation_allowed is False
    assert result.blocking_reasons == ["Target cannot represent security rules"]
    get_generator.assert_not_called()
