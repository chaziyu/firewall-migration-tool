from unittest.mock import Mock, patch

from tests.fixture_paths import CISCO_ASA_FIXTURE

from fwmigrate.application import MigrationPipeline, MigrationRequest
from fwmigrate.capabilities.schema import (
    CapabilityAnalysisResult,
    CapabilityIssue,
    CapabilityStatus,
    VendorCapabilityProfile,
)


def request(**overrides):
    values = dict(
        source_vendor="cisco_asa",
        target_vendor="palo_alto",
        source_content=CISCO_ASA_FIXTURE.read_text(encoding="utf-8"),
        target_format="xml",
    )
    values.update(overrides)
    return MigrationRequest(**values)


def test_blocking_capability_prevents_generator_call():
    analyzer = Mock()
    analyzer.analyze.return_value = CapabilityAnalysisResult([CapabilityIssue(
        feature="SecurityRule",
        status=CapabilityStatus.UNSUPPORTED,
        reason="rule semantics are unsupported",
        target_vendor="palo_alto",
        blocks_generation=True,
    )])

    with patch("fwmigrate.application.pipeline.PluginRegistry.get_generator") as get_generator:
        result = MigrationPipeline(analyzer).run(request())

    assert result.generation_allowed is False
    assert "rule semantics are unsupported" in result.blocking_reasons
    analyzer.analyze.assert_called_once_with(result.final_ir, "palo_alto")
    get_generator.assert_not_called()


def test_manual_review_capability_continues_to_generator():
    analyzer = Mock()
    analyzer.analyze.return_value = CapabilityAnalysisResult([CapabilityIssue(
        feature="description",
        status=CapabilityStatus.MANUAL_REVIEW,
        reason="review description mapping",
        target_vendor="palo_alto",
    )])

    result = MigrationPipeline(analyzer).run(request())

    assert result.generation_allowed is True
    assert result.artifacts
    assert result.requires_manual_review is True


def test_pipeline_loads_profile_for_canonical_target_and_version():
    loader = Mock()
    loader.load_profile.return_value = VendorCapabilityProfile(
        vendor_id="palo_alto", os_version="11.1"
    )

    result = MigrationPipeline(capability_loader=loader).run(
        request(target_version="11.1")
    )

    assert result.generation_allowed is True
    loader.load_profile.assert_called_once_with("palo_alto", "11.1")
