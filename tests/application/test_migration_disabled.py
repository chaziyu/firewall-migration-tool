import pytest

from fwmigrate.application import MigrationPipeline, MigrationUnavailableError


def test_legacy_pipeline_is_explicitly_disabled():
    pipeline = MigrationPipeline()

    with pytest.raises(MigrationUnavailableError, match="Configuration conversion is temporarily unavailable"):
        pipeline.run(object())

    with pytest.raises(MigrationUnavailableError, match="Configuration conversion is temporarily unavailable"):
        pipeline.analyze(object())
