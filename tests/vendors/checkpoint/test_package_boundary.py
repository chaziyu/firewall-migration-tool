import json

from fwmigrate.vendors.checkpoint.extraction import extract_checkpoint_config
from fwmigrate.vendors.checkpoint.model.source import CheckPointConfig
from fwmigrate.vendors.checkpoint.models import CheckPointExportBundle
from fwmigrate.vendors.checkpoint.source_report import CheckPointSourceReporter
from fwmigrate.vendors.checkpoint.extraction import CheckPointSourceMetadata, CheckPointSourceRecord
from fwmigrate.vendors.checkpoint.validation import (
    CheckPointValidationIssue,
    CheckPointValidationResult,
    validate_checkpoint_config,
)
from fwmigrate.vendors.checkpoint.validation.models import (
    CheckPointValidationIssue as ModelValidationIssue,
    CheckPointValidationResult as ModelValidationResult,
)
from fwmigrate.vendors.checkpoint.validation.validator import (
    validate_checkpoint_config as Validator,
)


def test_checkpoint_package_boundaries_preserve_canonical_types():
    from fwmigrate.vendors.checkpoint.model.source import CheckPointConfig as CanonicalConfig
    from fwmigrate.vendors.checkpoint.source_model import CheckPointConfig as LegacyConfig
    import fwmigrate.vendors.checkpoint.transform

    assert CanonicalConfig is CheckPointConfig
    assert LegacyConfig is CanonicalConfig
    from fwmigrate.vendors.checkpoint.source_model import CheckPointSourceMetadata as LegacyMetadata
    from fwmigrate.vendors.checkpoint.source_model import CheckPointSourceRecord as LegacyRecord
    assert LegacyMetadata is CheckPointSourceMetadata
    assert LegacyRecord is CheckPointSourceRecord
    assert CheckPointValidationIssue is ModelValidationIssue
    assert CheckPointValidationResult is ModelValidationResult
    assert validate_checkpoint_config is Validator

    extracted = extract_checkpoint_config(CheckPointExportBundle())
    assert isinstance(extracted.config, CanonicalConfig)

    analysis = CheckPointSourceReporter().analyze_source(json.dumps({"responses": []}))
    assert isinstance(analysis.config, CanonicalConfig)
    assert isinstance(analysis.validation, CheckPointValidationResult)
