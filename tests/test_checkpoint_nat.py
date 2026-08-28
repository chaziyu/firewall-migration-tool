import pytest
from fwmigrate.parsers.checkpoint.models import CheckPointResponse, ScopeSelectionResult
from fwmigrate.parsers.checkpoint.resolver import CheckPointObjectResolver
from fwmigrate.parsers.checkpoint.nat import extract_nat_rulebase
from fwmigrate.parsers.checkpoint.loader import build_rulebase_safety_map
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

    assert nat_rules == []
    assert items[0].requires_manual_review
    assert any("unresolved-translated-destination" in reason for reason in items[0].notes)


def _valid_nat_rule(**overrides):
    rule = {
        "uid": "nat-uid", "rule-number": 7, "name": "Strict_NAT",
        "original-source": "Any", "original-destination": "Any", "original-service": "Any",
        "translated-source": "Any", "translated-destination": "Original",
        "translated-service": "Original", "enabled": True,
    }
    rule.update(overrides)
    return rule


@pytest.mark.parametrize("field", ["original-source", "original-destination", "original-service"])
def test_missing_original_nat_match_is_never_replaced_with_any(field):
    rule = _valid_nat_rule()
    rule.pop(field)
    response = CheckPointResponse(command="show-nat-rulebase", package="Standard", data={"rulebase": [rule]})
    rules, items, _ = extract_nat_rulebase(
        [response], CheckPointObjectResolver(), ScopeSelectionResult(selected_package="Standard")
    )
    assert rules == []
    assert f"missing-{field}" in items[0].notes
    assert items[0].status == ExtractionStatus.PARSE_ERROR


def test_missing_nat_enabled_is_withheld():
    rule = _valid_nat_rule()
    rule.pop("enabled")
    response = CheckPointResponse(command="show-nat-rulebase", package="Standard", data={"rulebase": [rule]})
    rules, items, _ = extract_nat_rulebase(
        [response], CheckPointObjectResolver(), ScopeSelectionResult(selected_package="Standard")
    )
    assert rules == []
    assert "missing-enabled" in items[0].notes


def test_no_effective_nat_translation_does_not_guess_source_nat():
    rule = _valid_nat_rule(**{"translated-source": "Original"})
    response = CheckPointResponse(command="show-nat-rulebase", package="Standard", data={"rulebase": [rule]})
    rules, items, _ = extract_nat_rulebase(
        [response], CheckPointObjectResolver(), ScopeSelectionResult(selected_package="Standard")
    )
    assert rules == []
    assert "no-effective-nat-translation" in items[0].notes


def test_translated_service_nat_is_preserved_but_never_target_safe():
    resolver = CheckPointObjectResolver()
    resolver.register_object({"uid": "svc-https", "name": "https", "type": "service-tcp"})
    resolver.set_object_normalization("svc-https", "https", ExtractionStatus.NORMALIZED)
    rule = _valid_nat_rule(**{"translated-service": "svc-https"})
    response = CheckPointResponse(command="show-nat-rulebase", package="Standard", data={"rulebase": [rule]})
    rules, items, _ = extract_nat_rulebase(
        [response], resolver, ScopeSelectionResult(selected_package="Standard")
    )
    assert len(rules) == 1
    assert rules[0].sequence == 7
    assert rules[0].translated_services == ["https"]
    assert not rules[0].safe_for_target_generation
    assert "translated-service" in rules[0].review_reasons


@pytest.mark.parametrize("translations,expected_type", [
    ({"translated-source": "Original", "translated-destination": "dst"}, NATType.DESTINATION),
    ({"translated-source": "src", "translated-destination": "Original"}, NATType.SOURCE),
    ({"translated-source": "src", "translated-destination": "dst"}, NATType.TWICE),
])
def test_translated_service_taints_every_address_nat_shape(translations, expected_type):
    resolver = CheckPointObjectResolver()
    for uid, name, obj_type in (("src", "TranslatedSrc", "host"), ("dst", "TranslatedDst", "host"),
                                ("svc", "TranslatedSvc", "service-tcp")):
        resolver.register_object({"uid": uid, "name": name, "type": obj_type})
        resolver.set_object_normalization(uid, name, ExtractionStatus.NORMALIZED)
    rule = _valid_nat_rule(**translations, **{"translated-service": "svc"})
    response = CheckPointResponse(command="show-nat-rulebase", package="Standard", data={"rulebase": [rule]})
    rules, _, _ = extract_nat_rulebase(
        [response], resolver, ScopeSelectionResult(selected_package="Standard")
    )
    assert rules[0].type == expected_type
    assert not rules[0].safe_for_target_generation
    assert "translated-service" in rules[0].review_reasons


def test_service_only_translation_is_source_accounted_without_guessed_nat_type():
    resolver = CheckPointObjectResolver()
    resolver.register_object({"uid": "svc", "name": "TranslatedSvc", "type": "service-tcp"})
    resolver.set_object_normalization("svc", "TranslatedSvc", ExtractionStatus.NORMALIZED)
    rule = _valid_nat_rule(**{
        "translated-source": "Original", "translated-destination": "Original", "translated-service": "svc",
    })
    response = CheckPointResponse(command="show-nat-rulebase", package="Standard", data={"rulebase": [rule]})
    rules, items, _ = extract_nat_rulebase(
        [response], resolver, ScopeSelectionResult(selected_package="Standard")
    )
    assert rules == []
    assert "translated-service-only" in items[0].notes


def test_nat_inventory_order_follows_native_page_boundaries():
    pages = [
        CheckPointResponse(command="show-nat-rulebase", package="Standard",
                           **{"from": 2, "to": 2, "total": 2}, data={"rulebase": [_valid_nat_rule(
                               uid="n2", **{"rule-number": 2})]}),
        CheckPointResponse(command="show-nat-rulebase", package="Standard",
                           **{"from": 1, "to": 1, "total": 2}, data={"rulebase": [_valid_nat_rule(
                               uid="n1", **{"rule-number": 1})]}),
    ]
    rules, items, _ = extract_nat_rulebase(
        pages, CheckPointObjectResolver(), ScopeSelectionResult(selected_package="Standard"),
        build_rulebase_safety_map(pages),
    )
    assert [item.source_id for item in items] == ["n1", "n2"]
    assert [rule.sequence for rule in rules] == [1, 2]
