from pathlib import Path

from fwmigrate.vendors.palo_alto.source_builder import build_panos_config


def test_nat_translation_variants_remain_explicit():
    path = Path(__file__).parents[2] / "fixtures" / "palo_alto" / "nat_pipeline_conformance.xml"
    rules = {rule.name: rule for rule in build_panos_config(path.read_text()).nat_rules}
    assert rules["static-twice-rule"].source_translation.bi_directional == "yes"
    assert rules["disabled-no-translation"].source_translation is None


def test_destination_translation_dns_rewrite_is_typed_without_inferred_enablement():
    config = build_panos_config("""<config><shared><rulebase><nat><rules><entry name='rewrite'>
      <destination-translation><translated-address>192.0.2.5</translated-address><dns-rewrite><direction>reverse</direction><future-rewrite>keep</future-rewrite></dns-rewrite></destination-translation>
    </entry></rules></nat></rulebase></shared></config>""")
    destination = config.nat_rules[0].destination_translation
    assert destination.translated_address == "192.0.2.5"
    assert destination.dns_rewrite.enabled is None
    assert destination.dns_rewrite.direction == "reverse"
    assert destination.dns_rewrite.explicit_fields == {"direction"}
    assert destination.dns_rewrite.raw_extra["future-rewrite"] == "keep"
    assert "dns_rewrite" in destination.explicit_fields
