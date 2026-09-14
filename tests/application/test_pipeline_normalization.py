from unittest.mock import Mock, patch

from fwmigrate.application import MigrationPipeline, MigrationRequest
from fwmigrate.extraction.models import ExtractionResult
from fwmigrate.ir.core import IRConfig, IRMetadata


def test_normalization_always_runs_before_optional_optimization():
    ir = IRConfig(metadata=IRMetadata(source_vendor="source"))
    parser = Mock()
    parser.extract.return_value = ExtractionResult(canonical_ir=ir)
    generator = Mock(display_name="Target")
    generator.generate.return_value = []
    normalizer = Mock()
    optimizer = Mock()
    optimizer.find_unused_objects.return_value = {
        "unused_addresses": [],
        "unused_services": [],
    }
    optimizer.prune_unused_objects.return_value = ir

    with patch("fwmigrate.application.pipeline.PluginRegistry.get_parser", return_value=parser), \
         patch("fwmigrate.application.pipeline.PluginRegistry.get_generator", return_value=generator), \
         patch("fwmigrate.application.pipeline.RuleNormalizer", return_value=normalizer), \
         patch("fwmigrate.application.pipeline.RuleOptimizer", return_value=optimizer):
        MigrationPipeline().run(MigrationRequest("source", "target", "config", optimize=True))

    normalizer.normalize_outbound_threat_source_anomalies.assert_called_once_with()
    optimizer.find_unused_objects.assert_called_once_with()
    optimizer.prune_unused_objects.assert_called_once_with()
    assert normalizer.method_calls[0][0] == "normalize_outbound_threat_source_anomalies"
