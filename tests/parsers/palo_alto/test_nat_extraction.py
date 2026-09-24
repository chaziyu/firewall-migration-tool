from pathlib import Path

from fwmigrate.vendors.palo_alto.model import PANNATRule
from fwmigrate.vendors.palo_alto.source_builder import build_panos_config


FIXTURES = Path(__file__).parents[2] / "fixtures" / "palo_alto"


def test_nat_translation_variants_are_extracted_from_source():
    config = build_panos_config((FIXTURES / "nat_pipeline_conformance.xml").read_text())
    rules = {item.name: item for item in config.nat_rules}

    assert rules["dipp-pool-rule"].source_translation.translated_addresses == ["dipp-pool"]
    assert rules["dipp-interface-rule"].source_translation.interface == "ethernet1/1"
    assert rules["static-twice-rule"].source_translation.bi_directional == "yes"
    assert rules["dynamic-dnat-rule"].dynamic_destination_translation.distribution == "round-robin"
    assert rules["translated-port-rule"].destination_translation.translated_port == "8443"
    assert rules["disabled-no-translation"].source_translation is None


def test_nat_contract_preserves_explicit_state_scope_inventory_and_redaction(assert_source_contract):
    secret = "nat-secret-value"
    config = build_panos_config(
        f"""<config><shared><rulebase><nat><rules>
          <entry name='explicit'><from><member>trust</member></from><to><member>untrust</member></to><source><member>any</member></source><destination><member>any</member></destination><service>any</service><disabled>no</disabled><source-translation><dynamic-ip-and-port><interface-address><interface>ethernet1/1</interface><future-nested>keep-nested</future-nested><future-password>{secret}</future-password></interface-address></dynamic-ip-and-port></source-translation><future-field>keep</future-field></entry>
          <entry name='missing'/>
        </rules></nat></rulebase></shared></config>"""
    )
    explicit, missing = config.nat_rules

    assert isinstance(explicit, PANNATRule)
    assert explicit.service == "any"
    assert explicit.disabled == "no"
    assert missing.disabled is None
    assert missing.source_translation is None
    assert explicit.raw_extra["future-field"] == "keep"
    assert explicit.source_translation.raw_extra["interface-address"]["future-nested"] == "keep-nested"
    assert "future-nested" not in explicit.raw_extra
    assert explicit.scope.kind == "shared"
    assert_source_contract(explicit, config)
    assert secret not in str(config.model_dump())
