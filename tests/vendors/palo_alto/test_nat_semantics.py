from pathlib import Path

from fwmigrate.vendors.palo_alto.source_builder import build_panos_config


def test_nat_translation_variants_remain_explicit():
    path = Path(__file__).parents[2] / "fixtures" / "palo_alto" / "nat_pipeline_conformance.xml"
    rules = {rule.name: rule for rule in build_panos_config(path.read_text()).nat_rules}
    assert rules["static-twice-rule"].source_translation.bi_directional == "yes"
    assert rules["disabled-no-translation"].source_translation is None
