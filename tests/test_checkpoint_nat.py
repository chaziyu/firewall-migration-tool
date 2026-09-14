import pytest
from fwmigrate.parsers.checkpoint.models import CheckPointResponse, ScopeSelectionResult
from fwmigrate.parsers.checkpoint.resolver import CheckPointObjectResolver
from fwmigrate.parsers.checkpoint.nat import extract_nat_rulebase
from fwmigrate.parsers.checkpoint.loader import build_rulebase_safety_map
from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.ir.core import IRConfig
from fwmigrate.parsers.checkpoint.dependencies import build_checkpoint_dependencies
from fwmigrate.ir.enums import NATTranslationMode, NATType


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
                        "method": "hide",
                        "hide-behind": "gateway",
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
    assert nat.source_translation_mode == NATTranslationMode.INTERFACE_ADDRESS
    assert nat.source == ["Net_Corp"]
    assert nat.safe_for_target_generation


def test_nat_dependencies_use_domain_scope_without_package_suffix():
    resolver = CheckPointObjectResolver()
    resolver.register_object(
        {"uid": "host-a", "name": "SameName", "type": "host"},
        domain="Domain-A", domain_uid="domain-a-uid",
    )
    resolver.register_object(
        {"uid": "host-b", "name": "SameName", "type": "host"},
        domain="Domain-B", domain_uid="domain-b-uid",
    )
    resolver.set_object_normalization("host-a", "SameName", ExtractionStatus.NORMALIZED, domain="Domain-A")
    response = CheckPointResponse(
        command="show-nat-rulebase", domain="Domain-A", domain_uid="domain-a-uid",
        domain_name="Domain-A", package="Package-A", package_uid="package-a-uid",
        data={"rulebase": [{
            **_valid_nat_rule(), "original-source": "host-a",
        }]},
    )
    rules, _, _ = extract_nat_rulebase([response], resolver, ScopeSelectionResult(selected_package="Package-A"))
    dependencies = build_checkpoint_dependencies(IRConfig(metadata={}, nat_rules=rules), resolver)

    assert rules[0].checkpoint_domain_uid == "domain-a-uid"
    assert rules[0].checkpoint_package_uid == "package-a-uid"
    assert rules[0].source_context == "Domain-A/Package-A"
    assert next(
        item for item in dependencies
        if item.source_object == rules[0].name and item.source_field == "original-source"
    ).result == "RESOLVED"


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
                        "method": "hide",
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
                        "method": "hide",
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
        "translated-service": "Original", "method": "hide",
        "hide-behind": "gateway", "enabled": True,
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


def test_original_translations_are_identity_nat_not_guessed_source_nat():
    rule = _valid_nat_rule(**{"translated-source": "Original"})
    response = CheckPointResponse(command="show-nat-rulebase", package="Standard", data={"rulebase": [rule]})
    rules, items, _ = extract_nat_rulebase(
        [response], CheckPointObjectResolver(), ScopeSelectionResult(selected_package="Standard")
    )
    assert len(rules) == 1
    assert rules[0].identity is True
    assert rules[0].source_translation_mode is None


def test_identity_nat_is_preserved_in_order_and_disabled_state():
    identity = _valid_nat_rule(**{
        "uid": "identity-uid", "rule-number": 3, "name": "No_NAT",
        "translated-source": "Original", "translated-destination": "Original",
        "translated-service": "Original", "enabled": False,
    })
    later = _valid_nat_rule(**{
        "uid": "later-uid", "rule-number": 4, "name": "Later_NAT",
    })
    rules, _, _ = extract_nat_rulebase(
        [CheckPointResponse(command="show-nat-rulebase", package="Standard",
                            data={"rulebase": [identity, later]})],
        CheckPointObjectResolver(), ScopeSelectionResult(selected_package="Standard"),
    )
    assert [rule.name for rule in rules] == ["No_NAT", "Later_NAT"]
    assert rules[0].identity is True
    assert rules[0].exemption is True
    assert rules[0].sequence == 3
    assert rules[0].enabled is False
    assert rules[0].safe_for_target_generation is False


def test_destination_static_nat_preserves_destination_translation_mode():
    resolver = CheckPointObjectResolver()
    resolver.register_object({"uid": "private", "name": "Private", "type": "host"})
    resolver.set_object_normalization("private", "Private", ExtractionStatus.NORMALIZED)
    rule = _valid_nat_rule(**{
        "translated-source": "Original", "translated-destination": "private",
        "method": "static",
    })
    rules, _, _ = extract_nat_rulebase(
        [CheckPointResponse(command="show-nat-rulebase", package="Standard",
                            data={"rulebase": [rule]})],
        resolver, ScopeSelectionResult(selected_package="Standard"),
    )
    assert rules[0].type == NATType.DESTINATION
    assert rules[0].destination_translation_mode == NATTranslationMode.STATIC


def test_source_nat_merges_rule_method_and_object_hide_behind_evidence():
    resolver = CheckPointObjectResolver()
    resolver.register_object({
        "uid": "source", "name": "Source", "type": "host",
        "nat-settings": {"hide-behind": "gateway"},
    })
    resolver.set_object_normalization("source", "Source", ExtractionStatus.NORMALIZED)
    rule = _valid_nat_rule(**{
        "original-source": "source", "method": "hide", "hide-behind": None,
    })
    rules, _, _ = extract_nat_rulebase(
        [CheckPointResponse(command="show-nat-rulebase", package="Standard",
                            data={"rulebase": [rule]})],
        resolver, ScopeSelectionResult(selected_package="Standard"),
    )
    assert rules[0].source_translation_mode == NATTranslationMode.INTERFACE_ADDRESS
    evidence = rules[0].source_attributes["checkpoint-source-nat-method-resolution"]["evidence"]
    assert "rule:method=hide" in evidence
    assert "object-nat-settings:source:hide-behind=gateway" in evidence


def test_source_nat_merges_object_method_and_rule_hide_behind_evidence():
    resolver = CheckPointObjectResolver()
    resolver.register_object({
        "uid": "source", "name": "Source", "type": "host",
        "nat-settings": {"method": "hide"},
    })
    resolver.set_object_normalization("source", "Source", ExtractionStatus.NORMALIZED)
    rule = _valid_nat_rule(**{
        "original-source": "source", "method": None, "hide-behind": "gateway",
    })
    rules, _, _ = extract_nat_rulebase(
        [CheckPointResponse(command="show-nat-rulebase", package="Standard",
                            data={"rulebase": [rule]})],
        resolver, ScopeSelectionResult(selected_package="Standard"),
    )
    assert rules[0].source_translation_mode == NATTranslationMode.INTERFACE_ADDRESS


def test_conflicting_rule_and_object_nat_methods_require_review():
    resolver = CheckPointObjectResolver()
    resolver.register_object({
        "uid": "source", "name": "Source", "type": "host",
        "nat-settings": {"method": "static"},
    })
    resolver.set_object_normalization("source", "Source", ExtractionStatus.NORMALIZED)
    rule = _valid_nat_rule(**{"original-source": "source", "method": "hide"})
    rules, items, _ = extract_nat_rulebase(
        [CheckPointResponse(command="show-nat-rulebase", package="Standard",
                            data={"rulebase": [rule]})],
        resolver, ScopeSelectionResult(selected_package="Standard"),
    )
    assert rules == []
    assert "conflicting-source-nat-method-evidence" in items[0].notes


def test_twice_nat_resolves_source_and_destination_modes_independently():
    resolver = CheckPointObjectResolver()
    for uid, name in (("source", "Source"), ("destination", "Destination")):
        resolver.register_object({"uid": uid, "name": name, "type": "host"})
        resolver.set_object_normalization(uid, name, ExtractionStatus.NORMALIZED)
    rule = _valid_nat_rule(**{
        "original-source": "source", "translated-source": "source",
        "original-destination": "destination", "translated-destination": "destination",
        "source-nat-method": "static", "destination-nat-method": "static",
        "method": None, "hide-behind": None,
    })
    rules, _, _ = extract_nat_rulebase(
        [CheckPointResponse(command="show-nat-rulebase", package="Standard",
                            data={"rulebase": [rule]})],
        resolver, ScopeSelectionResult(selected_package="Standard"),
    )
    assert rules[0].type == NATType.TWICE
    assert rules[0].source_translation_mode == NATTranslationMode.STATIC
    assert rules[0].destination_translation_mode == NATTranslationMode.STATIC


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
    rule = _valid_nat_rule(
        **translations,
        **{"translated-service": "svc", "hide-behind": None},
    )
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
    assert len(rules) == 1
    assert rules[0].type == NATType.SERVICE
    assert rules[0].translated_services == ["TranslatedSvc"]
    assert "translated-service" in items[0].notes


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


def test_nat_missing_package_scope_is_withheld():
    response = CheckPointResponse(
        command="show-nat-rulebase", data={"rulebase": [_valid_nat_rule()]},
    )
    rules, items, _ = extract_nat_rulebase(
        [response], CheckPointObjectResolver(), ScopeSelectionResult(),
    )
    assert rules == []
    assert "missing-package-scope" in items[0].notes
    assert "<missing-package>" in items[0].source_path


@pytest.mark.parametrize("value", ["false", "true", 0, 1, "yes", [], {}])
def test_invalid_nat_enabled_types_are_rejected(value):
    response = CheckPointResponse(
        command="show-nat-rulebase", package="Standard",
        data={"rulebase": [_valid_nat_rule(enabled=value)]},
    )
    rules, items, _ = extract_nat_rulebase(
        [response], CheckPointObjectResolver(),
        ScopeSelectionResult(selected_package="Standard"),
    )
    assert rules == []
    assert items[0].status == ExtractionStatus.PARSE_ERROR
    assert "invalid-enabled-value" in items[0].notes


@pytest.mark.parametrize("value", [True, False])
def test_nat_enabled_requires_real_boolean(value):
    response = CheckPointResponse(
        command="show-nat-rulebase", package="Standard",
        data={"rulebase": [_valid_nat_rule(enabled=value)]},
    )
    rules, _, _ = extract_nat_rulebase(
        [response], CheckPointObjectResolver(),
        ScopeSelectionResult(selected_package="Standard"),
    )
    assert len(rules) == 1
    assert rules[0].enabled is value


def test_translated_source_presence_alone_does_not_prove_dynamic_pat():
    resolver = CheckPointObjectResolver()
    resolver.register_object({"uid": "translated", "name": "Translated", "type": "host"})
    resolver.set_object_normalization("translated", "Translated", ExtractionStatus.NORMALIZED)
    rule = _valid_nat_rule(**{
        "translated-source": "translated",
        "method": None,
        "hide-behind": None,
    })
    response = CheckPointResponse(
        command="show-nat-rulebase", package="Standard", data={"rulebase": [rule]},
    )
    rules, items, _ = extract_nat_rulebase(
        [response], resolver, ScopeSelectionResult(selected_package="Standard"),
    )
    assert rules == []
    assert "source-nat-method-unresolved" in items[0].notes


def test_hide_nat_method_maps_only_when_proven():
    resolver = CheckPointObjectResolver()
    resolver.register_object({"uid": "translated", "name": "Translated", "type": "host"})
    resolver.set_object_normalization("translated", "Translated", ExtractionStatus.NORMALIZED)
    rule = _valid_nat_rule(**{
        "translated-source": "translated", "method": "hide", "hide-behind": None,
    })
    response = CheckPointResponse(
        command="show-nat-rulebase", package="Standard", data={"rulebase": [rule]},
    )
    rules, _, _ = extract_nat_rulebase(
        [response], resolver, ScopeSelectionResult(selected_package="Standard"),
    )
    assert len(rules) == 1
    assert rules[0].source_translation_mode == NATTranslationMode.DYNAMIC_IP_AND_PORT


def test_static_source_nat_method_not_treated_as_dynamic_pat():
    resolver = CheckPointObjectResolver()
    resolver.register_object({"uid": "translated", "name": "Translated", "type": "host"})
    resolver.set_object_normalization("translated", "Translated", ExtractionStatus.NORMALIZED)
    rule = _valid_nat_rule(**{
        "translated-source": "translated", "method": "static", "hide-behind": None,
    })
    response = CheckPointResponse(
        command="show-nat-rulebase", package="Standard", data={"rulebase": [rule]},
    )
    rules, _, _ = extract_nat_rulebase(
        [response], resolver, ScopeSelectionResult(selected_package="Standard"),
    )
    assert len(rules) == 1
    assert rules[0].source_translation_mode == NATTranslationMode.STATIC


def test_unknown_source_nat_method_is_withheld():
    resolver = CheckPointObjectResolver()
    resolver.register_object({"uid": "translated", "name": "Translated", "type": "host"})
    resolver.set_object_normalization("translated", "Translated", ExtractionStatus.NORMALIZED)
    rule = _valid_nat_rule(**{
        "translated-source": "translated", "method": "mystery", "hide-behind": None,
    })
    response = CheckPointResponse(
        command="show-nat-rulebase", package="Standard", data={"rulebase": [rule]},
    )
    rules, items, _ = extract_nat_rulebase(
        [response], resolver, ScopeSelectionResult(selected_package="Standard"),
    )
    assert rules == []
    assert "source-nat-method-unresolved" in items[0].notes
    assert "source-nat-method-unrepresentable:mystery" in items[0].notes


def test_object_nat_settings_correlate_without_duplicate_rule():
    resolver = CheckPointObjectResolver()
    resolver.register_object({
        "uid": "original", "name": "OriginalHost", "type": "host",
        "nat-settings": {"auto-rule": True, "method": "hide"},
    })
    resolver.set_object_normalization("original", "OriginalHost", ExtractionStatus.NORMALIZED)
    resolver.register_object({"uid": "translated", "name": "Translated", "type": "host"})
    resolver.set_object_normalization("translated", "Translated", ExtractionStatus.NORMALIZED)
    rule = _valid_nat_rule(**{
        "original-source": "original", "translated-source": "translated",
        "method": None, "hide-behind": None,
    })
    response = CheckPointResponse(
        command="show-nat-rulebase", package="Standard", data={"rulebase": [rule]},
    )
    rules, _, _ = extract_nat_rulebase(
        [response], resolver, ScopeSelectionResult(selected_package="Standard"),
    )
    assert len(rules) == 1
    assert rules[0].source_translation_mode == NATTranslationMode.DYNAMIC_IP_AND_PORT
