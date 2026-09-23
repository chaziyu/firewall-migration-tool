from pathlib import Path

import yaml

from fwmigrate.conversion.fortigate_to_palo_alto import FortiGateToPaloAltoPlanner, PANMigrationOptions
from fwmigrate.conversion.fortigate_to_palo_alto.renderer import PANSetRenderer
from fwmigrate.conversion.fortigate_to_palo_alto.validation import validate_plan
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter


FIXTURES = Path(__file__).parents[2] / "fixtures" / "fortigate"


def test_fortigate_mvp_pipeline_matches_exact_set_golden():
    analysis = FortiGateSourceReporter().analyze_source((FIXTURES / "palo_alto_mvp.conf").read_text())
    options = PANMigrationOptions(**yaml.safe_load((FIXTURES / "palo_alto_mvp_mapping.yaml").read_text()))
    plan = FortiGateToPaloAltoPlanner().plan(analysis.extracted.config, analysis.derived, options)
    validation = validate_plan(plan)

    assert not validation.has_errors, [issue.message for issue in validation.issues]
    commands = PANSetRenderer().render(plan, validation).commands
    expected = tuple((FIXTURES / "palo_alto_mvp_expected.set").read_text().splitlines())
    assert commands == expected
