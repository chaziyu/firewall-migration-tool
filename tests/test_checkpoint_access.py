import pytest
from fwmigrate.parsers.checkpoint.models import CheckPointResponse, ScopeSelectionResult
from fwmigrate.parsers.checkpoint.resolver import CheckPointObjectResolver
from fwmigrate.parsers.checkpoint.access import extract_access_rulebase
from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.ir.enums import PolicyAction


def test_extract_access_rules_basic():
    resolver = CheckPointObjectResolver()
    resolver.register_object({"uid": "uid-h1", "name": "Host1", "type": "host"})
    resolver.set_object_normalization("uid-h1", "Host1", ExtractionStatus.NORMALIZED)
    resolver.register_object({"uid": "uid-s-http", "name": "http", "type": "service-tcp", "port": "80"})
    resolver.set_object_normalization("uid-s-http", "http", ExtractionStatus.NORMALIZED)
    resolver.register_object({"uid": "uid-act-accept", "name": "Accept", "type": "RulebaseAction"})

    scope = ScopeSelectionResult(selected_package="Standard", selected_access_layer="Network")

    responses = [
        CheckPointResponse(
            command="show-access-rulebase",
            package="Standard",
            layer="Network",
            data={
                "rulebase": [
                    {
                        "uid": "uid-rule-1",
                        "rule-number": 1,
                        "name": "Allow_HTTP",
                        "type": "access-rule",
                        "source": ["Any"],
                        "destination": ["uid-h1"],
                        "service": ["uid-s-http"],
                        "action": "uid-act-accept",
                        "enabled": True
                    }
                ]
            }
        )
    ]

    pols, items, unsupp = extract_access_rulebase(responses, resolver, scope)

    assert len(pols) == 1
    assert pols[0].name == "Allow_HTTP"
    assert pols[0].action == PolicyAction.ALLOW
    assert pols[0].safe_for_target_generation
    assert not pols[0].requires_manual_review


def test_unresolved_uid_taints_policy():
    resolver = CheckPointObjectResolver()
    resolver.register_object({"uid": "uid-act-accept", "name": "Accept", "type": "RulebaseAction"})
    scope = ScopeSelectionResult(selected_package="Standard", selected_access_layer="Network")

    responses = [
        CheckPointResponse(
            command="show-access-rulebase",
            package="Standard",
            layer="Network",
            data={
                "rulebase": [
                    {
                        "uid": "uid-rule-bad",
                        "rule-number": 1,
                        "name": "Rule_With_Ghost_Source",
                        "type": "access-rule",
                        "source": ["unknown-ghost-uid-12345678901234567890"],
                        "destination": ["Any"],
                        "service": ["Any"],
                        "action": "uid-act-accept",
                        "enabled": True
                    }
                ]
            }
        )
    ]

    pols, items, unsupp = extract_access_rulebase(responses, resolver, scope)

    assert len(pols) == 1
    pol = pols[0]
    assert pol.requires_manual_review
    assert not pol.safe_for_target_generation
    assert any("unresolved-source" in reason for reason in pol.review_reasons)


def test_unsupported_action_ask_marks_policy_for_review():
    resolver = CheckPointObjectResolver()
    resolver.register_object({"uid": "uid-act-ask", "name": "Ask", "type": "RulebaseAction"})
    scope = ScopeSelectionResult(selected_package="Standard", selected_access_layer="Network")

    responses = [
        CheckPointResponse(
            command="show-access-rulebase",
            package="Standard",
            layer="Network",
            data={
                "rulebase": [
                    {
                        "uid": "uid-rule-ask",
                        "rule-number": 1,
                        "name": "Rule_User_Prompt",
                        "type": "access-rule",
                        "source": ["Any"],
                        "destination": ["Any"],
                        "service": ["Any"],
                        "action": "uid-act-ask",
                        "enabled": True
                    }
                ]
            }
        )
    ]

    pols, items, unsupp = extract_access_rulebase(responses, resolver, scope)

    assert len(pols) == 1
    pol = pols[0]
    assert pol.requires_manual_review
    assert not pol.safe_for_target_generation
    assert len(unsupp) == 1
    assert "Ask" in unsupp[0].reason


def test_security_zones_separated_from_addresses():
    resolver = CheckPointObjectResolver()
    resolver.register_object({"uid": "uid-zone-in", "name": "TrustZone", "type": "security-zone"})
    resolver.register_object({"uid": "uid-zone-out", "name": "UntrustZone", "type": "security-zone"})
    resolver.register_object({"uid": "uid-h1", "name": "Web_Server", "type": "host"})
    resolver.set_object_normalization("uid-h1", "Web_Server", ExtractionStatus.NORMALIZED)
    resolver.register_object({"uid": "uid-act-accept", "name": "Accept", "type": "RulebaseAction"})

    scope = ScopeSelectionResult(selected_package="Standard", selected_access_layer="Network")

    responses = [
        CheckPointResponse(
            command="show-access-rulebase",
            package="Standard",
            layer="Network",
            data={
                "rulebase": [
                    {
                        "uid": "uid-rule-zone",
                        "rule-number": 1,
                        "name": "Zone_Restricted_Rule",
                        "type": "access-rule",
                        "source": ["uid-zone-in"],
                        "destination": ["uid-zone-out", "uid-h1"],
                        "service": ["Any"],
                        "action": "uid-act-accept",
                        "enabled": True
                    }
                ]
            }
        )
    ]

    pols, items, unsupp = extract_access_rulebase(responses, resolver, scope)

    assert len(pols) == 1
    pol = pols[0]
    assert pol.from_zone == ["TrustZone"]
    assert pol.to_zone == ["UntrustZone"]
    assert pol.source == ["any"]
    assert pol.destination == ["Web_Server"]
    assert pol.safe_for_target_generation
