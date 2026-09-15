from unittest.mock import patch

from fwmigrate.application import MigrationPipeline, MigrationRequest
from fwmigrate.jobs.models import MigrationIssue
from fwmigrate.validation.models import ValidationResult
from tests.fixture_paths import CISCO_ASA_FIXTURE


def request():
    return MigrationRequest(
        source_vendor="cisco_asa",
        target_vendor="palo_alto",
        source_content=CISCO_ASA_FIXTURE.read_text(encoding="utf-8"),
        target_format="xml",
    )


def test_pipeline_runs_validation_once_and_returns_its_result():
    result = ValidationResult()
    with patch("fwmigrate.application.pipeline.validate_ir", return_value=result) as validate:
        migration = MigrationPipeline().run(request())

    assert migration.generation_allowed
    assert migration.validation_result is result
    validate.assert_called_once()


def test_pipeline_blocks_generator_on_validation_issue():
    result = ValidationResult([MigrationIssue(message="missing dependency", blocking=True)])
    with (
        patch("fwmigrate.application.pipeline.validate_ir", return_value=result),
        patch("fwmigrate.application.pipeline.PluginRegistry.get_generator") as get_generator,
    ):
        migration = MigrationPipeline().run(request())

    assert migration.generation_allowed is False
    assert migration.validation_result is result
    assert migration.blocking_reasons == ["missing dependency"]
    get_generator.assert_not_called()
