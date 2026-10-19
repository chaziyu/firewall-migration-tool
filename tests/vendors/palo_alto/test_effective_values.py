from pathlib import Path
import re

import pytest

from fwmigrate.vendors.palo_alto.source_report import PaloAltoSourceReporter
from fwmigrate.vendors.palo_alto.transform.effective_values import effective_value


SOURCE = (Path(__file__).parents[2] / "fixtures/palo_alto/fortigate_conversion.xml").read_text(encoding="utf-8")


def omitted_source():
    return re.sub(r"<(rule-type|log-start|log-end|source-user)>.*?</\1>", "", SOURCE)


def test_documented_effective_values_do_not_become_explicit_source():
    analysis = PaloAltoSourceReporter().analyze_source(omitted_source())
    rule = analysis.config.security_rules[0]
    before = analysis.config.model_dump()
    assert effective_value(analysis.derived, rule, "rule_type") == "universal"
    assert effective_value(analysis.derived, rule, "log_start") == "no"
    assert effective_value(analysis.derived, rule, "log_end") == "yes"
    assert effective_value(analysis.derived, rule, "source_user") == "any"
    assert effective_value(analysis.derived, rule, "schedule") == "always"
    assert effective_value(analysis.derived, rule, "category") is None
    assert rule.log_end is None and "log_end" not in rule.explicit_fields
    assert analysis.config.model_dump() == before
    assert all(row.version == "11.1.0" and row.reference.startswith("https://docs.paloaltonetworks.com/") for row in analysis.derived.effective_values)


@pytest.mark.parametrize("version", ["", "10.2.0", "11.2.0", "11.10.0", "unknown"])
def test_unknown_versions_have_no_effective_values(version):
    analysis = PaloAltoSourceReporter().analyze_source(omitted_source().replace('version="11.1.0"', f'version="{version}"'))
    assert analysis.derived.effective_values == ()


def test_explicit_values_and_managed_sources_are_not_defaulted():
    reporter = PaloAltoSourceReporter()
    analysis = reporter.analyze_source(SOURCE)
    assert effective_value(analysis.derived, analysis.config.security_rules[0], "log_end") is None
    managed = reporter.analyze_source(omitted_source().replace("<devices>", '<template><entry name="managed"/></template><devices>'))
    assert not managed.derived.effective_values


def test_explicit_unparsed_leaf_is_not_treated_as_an_omission():
    from fwmigrate.vendors.palo_alto.transform.effective_values import derive_effective_values

    analysis = PaloAltoSourceReporter().analyze_source(SOURCE)
    source = analysis.config.model_copy(deep=True)
    source.security_rules[0].log_end = None
    assert "log_end" in source.security_rules[0].explicit_fields
    assert not any(row.field == "log_end" for row in derive_effective_values(source))
