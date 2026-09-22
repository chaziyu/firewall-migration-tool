from pathlib import Path

from fwmigrate.vendors.palo_alto.model import PANDefaultSecurityRule, PANSecurityRule
from fwmigrate.vendors.palo_alto.source_builder import build_panos_config


FIXTURES = Path(__file__).parents[2] / "fixtures" / "palo_alto"


def test_security_and_default_policy_values_are_extracted_from_source():
    config = build_panos_config((FIXTURES / "policies.xml").read_text())
    rules = {item.name: item for item in config.security_rules}

    assert rules["Allow-Basic"].action == "allow"
    assert rules["Explicit-Any"].source == ["any"]
    assert rules["Explicit-No"].disabled == "no"
    assert rules["Missing-Action"].action is None
    assert rules["Unknown-Field"].raw_extra["future-setting"] == {"nested": "retain-me"}

    defaults = build_panos_config((FIXTURES / "default_security_rules.xml").read_text()).default_security_rules
    assert defaults
    assert all(isinstance(rule, PANDefaultSecurityRule) for rule in defaults)


def test_policy_contract_preserves_explicit_state_scope_inventory_and_redaction(assert_source_contract):
    secret = "policy-secret-value"
    config = build_panos_config(
        f"""<config><shared><rulebase><security><rules>
          <entry name='explicit'><from><member>trust</member></from><to><member>untrust</member></to><source><member>any</member></source><destination><member>any</member></destination><action>allow</action><disabled>no</disabled><profile-setting><profiles><virus><member>default</member><future-nested>keep-nested</future-nested></virus></profiles></profile-setting><future-field>keep</future-field><future-password>{secret}</future-password></entry>
          <entry name='missing'/>
        </rules></security></rulebase></shared></config>"""
    )
    explicit, missing = config.security_rules

    assert isinstance(explicit, PANSecurityRule)
    assert explicit.action == "allow"
    assert explicit.disabled == "no"
    assert missing.action is None
    assert missing.disabled is None
    assert explicit.raw_extra["future-field"] == "keep"
    assert explicit.profile_setting.raw_extra["profiles-extra"]["virus"]["future-nested"] == "keep-nested"
    assert "future-nested" not in explicit.raw_extra
    assert explicit.scope.kind == "shared"
    assert_source_contract(explicit, config)
    assert secret not in str(config.model_dump())
