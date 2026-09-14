from unittest.mock import patch

from tests.fixture_paths import CISCO_ASA_FIXTURE

from fwmigrate.application import MigrationPipeline, MigrationRequest
from fwmigrate.core.normalizer import IRNormalizer
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


def test_pipeline_normalizes_before_optional_optimization():
    events = []
    real_normalize = IRNormalizer.normalize
    real_find_unused = RuleOptimizer.find_unused_objects
    real_prune = RuleOptimizer.prune_unused_objects

    def normalize(normalizer, ir=None):
        events.append("normalize")
        return real_normalize(normalizer, ir)

    def find_unused(optimizer):
        events.append("find_unused")
        return real_find_unused(optimizer)

    def prune(optimizer):
        events.append("prune")
        return real_prune(optimizer)

    with (
        patch.object(IRNormalizer, "normalize", normalize),
        patch.object(RuleOptimizer, "find_unused_objects", find_unused),
        patch.object(RuleOptimizer, "prune_unused_objects", prune),
    ):
        result = MigrationPipeline().run(request(optimize=True))

    assert result.normalization is not None
    assert events[0] == "normalize"
    assert "prune" in events

