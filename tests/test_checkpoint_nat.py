import pytest
from fwmigrate.parsers.checkpoint.models import CheckPointResponse, ScopeSelectionResult
from fwmigrate.parsers.checkpoint.resolver import CheckPointObjectResolver
from fwmigrate.parsers.checkpoint.nat import extract_nat_rulebase
from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.ir.enums import NATType


def test_extract_source_nat_hide():
    resolver = CheckPointObjectResolver()
    resolver.register_object({"uid": "uid-net-corp", "name": "Net_Corp", "type": "network"})
    resolver.set_object_normalization("uid-net-corp", "Net_Corp", ExtractionStatus.NORMALIZED)
    scope = ScopeSelectionResult(selected_package="Standard")

    responses = [
        CheckPointResponse(
            command="show-nat-rulebase",
            package="Standard",
            data={
                "rulebase": [
                    {
                        "uid": "uid-nat-1",
                        "rule-number": 1,
                        "name": "NAT_Hide_Corp",
                        "type": "nat-rule",
                        "original-source": "uid-net-corp",
                        "original-destination": "Any",
                        "original-service": "Any",
                        "translated-source": "Any",
                        "translated-destination": "Original",
                        "translated-service": "Original",
                        "enabled": True
                    }
                ]
            }
        )
    ]

    nat_rules, items, unsupp = extract_nat_rulebase(responses, resolver, scope)

    assert len(nat_rules) == 1
    nat = nat_rules[0]
    assert nat.name == "NAT_Hide_Corp"
    assert nat.type == NATType.SOURCE
    assert nat.source == ["Net_Corp"]
    assert nat.safe_for_target_generation


def test_extract_destination_and_twice_nat():
    resolver = CheckPointObjectResolver()
    resolver.register_object({"uid": "uid-ext-ip", "name": "Host_Ext_Web", "type": "host"})
    resolver.set_object_normalization("uid-ext-ip", "Host_Ext_Web", ExtractionStatus.NORMALIZED)
    resolver.register_object({"uid": "uid-int-ip", "name": "Host_Int_Web", "type": "host"})
    resolver.set_object_normalization("uid-int-ip", "Host_Int_Web", ExtractionStatus.NORMALIZED)
    resolver.register_object({"uid": "uid-pool", "name": "Pool_NAT", "type": "address-range"})
    resolver.set_object_normalization("uid-pool", "Pool_NAT", ExtractionStatus.NORMALIZED)

    scope = ScopeSelectionResult(selected_package="Standard")

    responses = [
        CheckPointResponse(
            command="show-nat-rulebase",
            package="Standard",
            data={
                "rulebase": [
                    {
                        "uid": "uid-dnat",
                        "rule-number": 1,
                        "name": "DNAT_Web",
                        "type": "nat-rule",
                        "original-source": "Any",
                        "original-destination": "uid-ext-ip",
                        "original-service": "Any",
                        "translated-source": "Original",
                        "translated-destination": "uid-int-ip",
                        "translated-service": "Original",
                        "enabled": True
                    },
                    {
                        "uid": "uid-twice-nat",
                        "rule-number": 2,
                        "name": "Twice_NAT_Web",
                        "type": "nat-rule",
                        "original-source": "Any",
                        "original-destination": "uid-ext-ip",
                        "original-service": "Any",
                        "translated-source": "uid-pool",
                        "translated-destination": "uid-int-ip",
                        "translated-service": "Original",
                        "enabled": True
                    }
                ]
            }
        )
    ]

    nat_rules, items, unsupp = extract_nat_rulebase(responses, resolver, scope)

    assert len(nat_rules) == 2
    dnat = nat_rules[0]
    assert dnat.type == NATType.DESTINATION
    assert dnat.translated_destinations == ["Host_Int_Web"]
    assert dnat.safe_for_target_generation

    twice = nat_rules[1]
    assert twice.type == NATType.TWICE
    assert twice.translated_sources == ["Pool_NAT"]
    assert twice.translated_destinations == ["Host_Int_Web"]
    assert twice.safe_for_target_generation


def test_unresolved_translated_destination_taints_nat():
    resolver = CheckPointObjectResolver()
    scope = ScopeSelectionResult(selected_package="Standard")

    responses = [
        CheckPointResponse(
            command="show-nat-rulebase",
            package="Standard",
            data={
                "rulebase": [
                    {
                        "uid": "uid-broken-nat",
                        "rule-number": 1,
                        "name": "Broken_DNAT",
                        "type": "nat-rule",
                        "original-source": "Any",
                        "original-destination": "Any",
                        "original-service": "Any",
                        "translated-source": "Original",
                        "translated-destination": "unknown-ghost-uid-88888888888888888888",
                        "translated-service": "Original",
                        "enabled": True
                    }
                ]
            }
        )
    ]

    nat_rules, items, unsupp = extract_nat_rulebase(responses, resolver, scope)

    assert len(nat_rules) == 1
    nat = nat_rules[0]
    assert nat.requires_manual_review
    assert not nat.safe_for_target_generation
    assert any("unresolved-translated-destination" in reason for reason in nat.review_reasons)
