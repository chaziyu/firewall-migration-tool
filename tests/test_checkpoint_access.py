import pytest
from fwmigrate.parsers.checkpoint.models import CheckPointResponse, ScopeSelectionResult
from fwmigrate.parsers.checkpoint.resolver import CheckPointObjectResolver, SemanticKind
from fwmigrate.parsers.checkpoint.access import extract_access_rulebase
from fwmigrate.parsers.checkpoint.loader import build_rulebase_safety_map
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

    assert pols == []
    assert items[0].status == ExtractionStatus.PARTIALLY_NORMALIZED
    assert items[0].requires_manual_review
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

    assert pols == []
    assert items[0].status == ExtractionStatus.PARTIALLY_NORMALIZED
    assert items[0].requires_manual_review
    assert "mixed-zone-address-or-semantics" in items[0].notes


def test_missing_enabled_is_source_accounted_but_withheld():
    resolver = CheckPointObjectResolver()
    resolver.register_object({"uid": "accept", "name": "Accept", "type": "RulebaseAction"})
    response = CheckPointResponse(command="show-access-rulebase", package="Standard", layer="Network", data={
        "rulebase": [{"uid": "r1", "rule-number": 1, "source": ["Any"],
                      "destination": ["Any"], "service": ["Any"], "action": "accept"}]
    })
    policies, items, _ = extract_access_rulebase(
        [response], resolver, ScopeSelectionResult(selected_package="Standard", selected_access_layer="Network")
    )
    assert policies == []
    assert items[0].status == ExtractionStatus.PARSE_ERROR
    assert "missing-enabled" in items[0].notes


def test_mixed_service_application_or_semantics_is_withheld():
    resolver = CheckPointObjectResolver()
    resolver.register_object({"uid": "accept", "name": "Accept", "type": "RulebaseAction"})
    resolver.register_object({"uid": "svc", "name": "https", "type": "service-tcp"})
    resolver.set_object_normalization("svc", "https", ExtractionStatus.NORMALIZED)
    resolver.register_object({"uid": "app", "name": "Office365", "type": "application-site"})
    resolver.set_object_normalization(
        "app", "Office365", ExtractionStatus.NORMALIZED,
        semantic_kind=SemanticKind.APPLICATION,
    )
    response = CheckPointResponse(command="show-access-rulebase", package="Standard", layer="Network", data={
        "rulebase": [{"uid": "r1", "rule-number": 1, "source": ["Any"],
                      "destination": ["Any"], "service": ["svc", "app"],
                      "action": "accept", "enabled": True}]
    })
    policies, items, _ = extract_access_rulebase(
        [response], resolver, ScopeSelectionResult(selected_package="Standard", selected_access_layer="Network")
    )
    assert policies == []
    assert "mixed-service-application-or-semantics" in items[0].notes


def test_ambiguous_package_scope_accounts_rules_without_canonical_merge():
    resolver = CheckPointObjectResolver()
    resolver.register_object({"uid": "accept", "name": "Accept", "type": "RulebaseAction"})
    responses = [
        CheckPointResponse(command="show-access-rulebase", package=package, layer="Network", data={
            "rulebase": [{"uid": f"r-{package}", "rule-number": 1, "source": ["Any"],
                          "destination": ["Any"], "service": ["Any"],
                          "action": "accept", "enabled": True}]
        }) for package in ("Corp", "Branch")
    ]
    policies, items, _ = extract_access_rulebase(
        responses, resolver,
        ScopeSelectionResult(ambiguous=True, reasons=["multiple-packages-without-selector"]),
    )
    assert policies == []
    assert len(items) == 2
    assert all("scope-selection-required" in item.notes for item in items)


def test_reject_is_preserved_as_deny_with_source_action():
    response = CheckPointResponse(command="show-access-rulebase", package="Standard", layer="Network", data={
        "rulebase": [{"uid": "reject-rule", "rule-number": 1, "source": ["Any"],
                      "destination": ["Any"], "service": ["Any"],
                      "action": "Reject", "enabled": True}]
    })
    policies, _, _ = extract_access_rulebase(
        [response], CheckPointObjectResolver(),
        ScopeSelectionResult(selected_package="Standard", selected_access_layer="Network"),
    )
    assert policies[0].action == PolicyAction.DENY
    assert policies[0].source_action == "Reject"


def test_missing_action_with_enabled_creates_no_canonical_policy():
    response = CheckPointResponse(command="show-access-rulebase", package="Standard", layer="Network", data={
        "rulebase": [{"uid": "missing-action", "rule-number": 1, "source": ["Any"],
                      "destination": ["Any"], "service": ["Any"], "enabled": True}]
    })
    policies, items, _ = extract_access_rulebase(
        [response], CheckPointObjectResolver(),
        ScopeSelectionResult(selected_package="Standard", selected_access_layer="Network"),
    )
    assert policies == []
    assert items[0].status == ExtractionStatus.PARSE_ERROR
    assert "missing-action" in items[0].notes


def test_time_group_dependency_taints_policy():
    resolver = CheckPointObjectResolver()
    resolver.register_object({"uid": "tg", "name": "Maintenance", "type": "time-group"})
    resolver.set_object_normalization(
        "tg", "Maintenance", ExtractionStatus.PARTIALLY_NORMALIZED,
        requires_manual_review=True, usable=False, semantic_kind=SemanticKind.TIME_GROUP,
    )
    response = CheckPointResponse(command="show-access-rulebase", package="Standard", layer="Network", data={
        "rulebase": [{"uid": "timed", "rule-number": 1, "source": ["Any"],
                      "destination": ["Any"], "service": ["Any"], "action": "Accept",
                      "enabled": True, "time": "tg"}]
    })
    policies, _, _ = extract_access_rulebase(
        [response], resolver,
        ScopeSelectionResult(selected_package="Standard", selected_access_layer="Network"),
    )
    assert len(policies) == 1
    assert not policies[0].safe_for_target_generation
    assert "tainted-schedule:Maintenance" in policies[0].review_reasons


def test_install_on_selected_gateway_is_enforced():
    rules = [
        {"uid": "selected", "rule-number": 1, "source": ["Any"], "destination": ["Any"],
         "service": ["Any"], "action": "Accept", "enabled": True, "install-on": ["GW1"]},
        {"uid": "excluded", "rule-number": 2, "source": ["Any"], "destination": ["Any"],
         "service": ["Any"], "action": "Accept", "enabled": True, "install-on": ["GW2"]},
    ]
    response = CheckPointResponse(command="show-access-rulebase", package="Standard", layer="Network", data={"rulebase": rules})
    policies, items, _ = extract_access_rulebase(
        [response], CheckPointObjectResolver(),
        ScopeSelectionResult(selected_package="Standard", selected_access_layer="Network", selected_gateway="GW1"),
    )
    assert [policy.source_uuid for policy in policies] == ["selected"]
    excluded = next(item for item in items if item.source_id == "excluded")
    assert excluded.status == ExtractionStatus.IGNORED_BY_POLICY


def test_access_inventory_order_follows_native_page_boundaries():
    pages = [
        CheckPointResponse(command="show-access-rulebase", package="Standard", layer="Network",
                           **{"from": 2, "to": 2, "total": 2}, data={"rulebase": [{
                               "uid": "r2", "rule-number": 2, "source": ["Any"], "destination": ["Any"],
                               "service": ["Any"], "action": "Accept", "enabled": True}]}),
        CheckPointResponse(command="show-access-rulebase", package="Standard", layer="Network",
                           **{"from": 1, "to": 1, "total": 2}, data={"rulebase": [{
                               "uid": "r1", "rule-number": 1, "source": ["Any"], "destination": ["Any"],
                               "service": ["Any"], "action": "Accept", "enabled": True}]}),
    ]
    policies, items, _ = extract_access_rulebase(
        pages, CheckPointObjectResolver(),
        ScopeSelectionResult(selected_package="Standard", selected_access_layer="Network"),
        build_rulebase_safety_map(pages),
    )
    assert [item.source_id for item in items] == ["r1", "r2"]
    assert [policy.source_uuid for policy in policies] == ["r1", "r2"]
