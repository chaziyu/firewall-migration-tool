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
                        "vpn": "Any",
                        "time": ["Any"],
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
                        "vpn": "Any",
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
                      "action": "Reject", "vpn": "Any", "enabled": True}]
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
                      "vpn": "Any", "enabled": True, "time": "tg"}]
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
         "service": ["Any"], "action": "Accept", "vpn": "Any", "enabled": True, "install-on": ["GW1"]},
        {"uid": "excluded", "rule-number": 2, "source": ["Any"], "destination": ["Any"],
         "service": ["Any"], "action": "Accept", "vpn": "Any", "enabled": True, "install-on": ["GW2"]},
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
                               "service": ["Any"], "action": "Accept", "vpn": "Any", "enabled": True}]}),
        CheckPointResponse(command="show-access-rulebase", package="Standard", layer="Network",
                           **{"from": 1, "to": 1, "total": 2}, data={"rulebase": [{
                               "uid": "r1", "rule-number": 1, "source": ["Any"], "destination": ["Any"],
                               "service": ["Any"], "action": "Accept", "vpn": "Any", "enabled": True}]}),
    ]
    policies, items, _ = extract_access_rulebase(
        pages, CheckPointObjectResolver(),
        ScopeSelectionResult(selected_package="Standard", selected_access_layer="Network"),
        build_rulebase_safety_map(pages),
    )
    assert [item.source_id for item in items] == ["r1", "r2"]
    assert [policy.source_uuid for policy in policies] == ["r1", "r2"]


def _safe_access_rule(**overrides):
    rule = {
        "uid": "rule-uid",
        "rule-number": 1,
        "name": "Rule",
        "type": "access-rule",
        "source": ["Any"],
        "destination": ["Any"],
        "service": ["Any"],
        "action": "Accept",
        "vpn": "Any",
        "time": ["Any"],
        "enabled": True,
    }
    rule.update(overrides)
    return rule


def _extract_single_access(rule, *, package="Standard", layer="Network", resolver=None):
    response = CheckPointResponse(
        command="show-access-rulebase",
        package=package,
        layer=layer,
        data={"rulebase": [rule]},
    )
    return extract_access_rulebase(
        [response],
        resolver or CheckPointObjectResolver(),
        ScopeSelectionResult(selected_package="Standard", selected_access_layer="Network"),
    )


def test_vpn_community_rule_is_withheld():
    resolver = CheckPointObjectResolver()
    resolver.register_object({
        "uid": "vpn-community-uid",
        "name": "RemoteAccessCommunity",
        "type": "vpn-community-meshed",
    })
    policies, items, _ = _extract_single_access(
        _safe_access_rule(vpn="vpn-community-uid"), resolver=resolver,
    )
    assert policies == []
    assert items[0].status == ExtractionStatus.PARTIALLY_NORMALIZED
    assert items[0].requires_manual_review
    assert "checkpoint-vpn-community" in items[0].notes


def test_unresolved_vpn_uid_is_withheld():
    policies, items, _ = _extract_single_access(
        _safe_access_rule(vpn="unresolved-vpn-uid-00000000"),
    )
    assert policies == []
    assert any(reason.startswith("unresolved-vpn:") for reason in items[0].notes)


def test_explicit_vpn_any_remains_eligible():
    policies, items, _ = _extract_single_access(_safe_access_rule())
    assert len(policies) == 1
    assert policies[0].safe_for_target_generation
    assert items[0].status == ExtractionStatus.NORMALIZED


def test_vpn_source_value_preserved_in_inventory():
    raw_vpn = {"uid": "vpn-community-uid", "name": "Community", "type": "vpn-community-star"}
    policies, items, _ = _extract_single_access(_safe_access_rule(vpn=raw_vpn))
    assert policies == []
    assert items[0].source_attributes["vpn"] == raw_vpn


def test_inline_layer_reference_withholds_parent_rule_and_preserves_uid():
    inline_ref = {"uid": "inline-layer-uid", "name": "ChildLayer", "type": "access-layer"}
    policies, items, _ = _extract_single_access(
        _safe_access_rule(**{"inline-layer": inline_ref}),
    )
    assert policies == []
    assert "checkpoint-inline-layer" in items[0].notes
    provenance = items[0].source_attributes["checkpoint-provenance"]
    assert provenance["inline-layer"]["uid"] == "inline-layer-uid"
    assert provenance["parent-rule-uid"] == "rule-uid"


def test_inline_layer_child_rules_not_flattened_into_parent_policy_order():
    parent = CheckPointResponse(
        command="show-access-rulebase", package="Standard", layer="Network",
        data={"rulebase": [_safe_access_rule(
            uid="parent", **{"inline-layer": {"uid": "child-layer", "name": "ChildLayer"}},
        )]},
    )
    child = CheckPointResponse(
        command="show-access-rulebase", package="Standard", layer="ChildLayer",
        data={"uid": "child-layer", "name": "ChildLayer", "rulebase": [
            _safe_access_rule(uid="child-1", **{"rule-number": 1}),
            _safe_access_rule(uid="child-2", **{"rule-number": 2}),
        ]},
    )
    policies, items, _ = extract_access_rulebase(
        [parent, child], CheckPointObjectResolver(),
        ScopeSelectionResult(selected_package="Standard"),
    )
    assert policies == []
    child_items = [item for item in items if item.source_id.startswith("child-")]
    assert [item.source_id for item in child_items] == ["child-1", "child-2"]
    assert all("checkpoint-inline-layer" in item.notes for item in child_items)


def test_command_bundle_access_missing_package_is_withheld():
    policies, items, _ = _extract_single_access(_safe_access_rule(), package=None)
    assert policies == []
    assert "missing-package-scope" in items[0].notes
    assert "<missing-package>" in items[0].source_path


def test_command_bundle_access_missing_layer_is_withheld():
    policies, items, _ = _extract_single_access(_safe_access_rule(), layer=None)
    assert policies == []
    assert "missing-access-layer-scope" in items[0].notes
    assert "<missing-layer>" in items[0].source_path


@pytest.mark.parametrize("value", ["false", "true", 0, 1, "yes", [], {}])
def test_invalid_access_enabled_types_are_rejected(value):
    policies, items, _ = _extract_single_access(_safe_access_rule(enabled=value))
    assert policies == []
    assert items[0].status == ExtractionStatus.PARSE_ERROR
    assert "invalid-enabled-value" in items[0].notes


@pytest.mark.parametrize("value,expected_disabled", [(True, False), (False, True)])
def test_access_enabled_requires_real_boolean(value, expected_disabled):
    policies, _, _ = _extract_single_access(_safe_access_rule(enabled=value))
    assert len(policies) == 1
    assert policies[0].disabled is expected_disabled


def _resolver_with_time(name="Business_Hours", uid="time-uid", *, kind=SemanticKind.TIME, safe=True):
    resolver = CheckPointObjectResolver()
    resolver.register_object({"uid": uid, "name": name, "type": "time" if kind == SemanticKind.TIME else "time-group"})
    resolver.set_object_normalization(
        uid, name, ExtractionStatus.NORMALIZED if safe else ExtractionStatus.PARTIALLY_NORMALIZED,
        requires_manual_review=not safe, usable=safe, semantic_kind=kind,
    )
    return resolver


@pytest.mark.parametrize("raw_time", [["Any"], ["97aeb369-9aea-11d5-bd16-0090272ccb30"]])
def test_time_any_list_is_unrestricted_and_safe(raw_time):
    policies, items, _ = _extract_single_access(_safe_access_rule(time=raw_time))
    assert len(policies) == 1
    assert policies[0].schedule is None
    assert policies[0].safe_for_target_generation
    assert items[0].source_attributes["time"] == raw_time


def test_one_safe_time_object_maps_to_schedule():
    resolver = _resolver_with_time()
    policies, _, _ = _extract_single_access(
        _safe_access_rule(time=["time-uid"]), resolver=resolver,
    )
    assert policies[0].schedule == "Business_Hours"
    assert policies[0].safe_for_target_generation


@pytest.mark.parametrize("time_override,reason", [
    ([], "empty-time-dimension"),
    (None, "missing-time-dimension"),
    (["missing-time-uid"], "unresolved-schedule:"),
])
def test_empty_missing_and_unresolved_time_are_unsafe(time_override, reason):
    rule = _safe_access_rule()
    if time_override is None:
        rule.pop("time")
    else:
        rule["time"] = time_override
    policies, items, _ = _extract_single_access(rule)
    assert len(policies) == 1
    assert not policies[0].safe_for_target_generation
    assert any(entry.startswith(reason) for entry in items[0].notes)


def test_multiple_time_objects_are_not_collapsed():
    resolver = _resolver_with_time("Schedule1", "time-1")
    resolver.register_object({"uid": "time-2", "name": "Schedule2", "type": "time"})
    resolver.set_object_normalization("time-2", "Schedule2", ExtractionStatus.NORMALIZED, semantic_kind=SemanticKind.TIME)
    policies, items, _ = _extract_single_access(
        _safe_access_rule(time=["time-1", "time-2"]), resolver=resolver,
    )
    assert policies[0].schedule is None
    assert not policies[0].safe_for_target_generation
    assert "multiple-time-constraints" in items[0].notes
    assert items[0].source_attributes["time"] == ["time-1", "time-2"]


def test_time_group_and_any_plus_schedule_are_unsafe():
    group_resolver = _resolver_with_time("TimeGroup", "time-group", kind=SemanticKind.TIME_GROUP, safe=False)
    policies, items, _ = _extract_single_access(
        _safe_access_rule(time=["time-group"]), resolver=group_resolver,
    )
    assert not policies[0].safe_for_target_generation
    assert "tainted-schedule:TimeGroup" in items[0].notes

    resolver = _resolver_with_time()
    policies, items, _ = _extract_single_access(
        _safe_access_rule(time=["Any", "time-uid"]), resolver=resolver,
    )
    assert not policies[0].safe_for_target_generation
    assert "any-with-other-time-match" in items[0].notes


def test_content_awareness_gates_non_any_negate_direction_and_unresolved():
    safe, _, _ = _extract_single_access(_safe_access_rule(content=["Any"]))
    assert safe[0].safe_for_target_generation

    resolver = CheckPointObjectResolver()
    resolver.register_object({"uid": "content-uid", "name": "Credit Cards", "type": "data-type"})
    policies, items, _ = _extract_single_access(
        _safe_access_rule(content=["content-uid"]), resolver=resolver,
    )
    assert not policies[0].safe_for_target_generation
    assert "checkpoint-content-awareness" in items[0].notes

    policies, items, _ = _extract_single_access(_safe_access_rule(
        content=["Any"], **{"content-negate": True, "content-direction": "upload"},
    ))
    assert not policies[0].safe_for_target_generation
    assert "content-negate" in items[0].notes
    assert "content-direction:upload" in items[0].notes

    policies, items, _ = _extract_single_access(_safe_access_rule(content=["missing-content-uid"]))
    assert any(reason.startswith("unresolved-content:") for reason in items[0].notes)


def test_track_uid_resolution_and_action_modifier_gating():
    resolver = CheckPointObjectResolver()
    resolver.register_object({"uid": "track-none", "name": "None", "type": "Track"})
    policies, _, _ = _extract_single_access(
        _safe_access_rule(track={"type": "track-none"}), resolver=resolver,
    )
    assert policies[0].log_end is False
    assert policies[0].source_log_setting == "None"

    resolver.register_object({"uid": "track-log", "name": "Log", "type": "Track"})
    policies, _, _ = _extract_single_access(
        _safe_access_rule(track={"type": "track-log"}), resolver=resolver,
    )
    assert policies[0].log_end is True

    policies, items, _ = _extract_single_access(
        _safe_access_rule(track={"type": "track-log", "accounting": True}), resolver=resolver,
    )
    assert "checkpoint-track-accounting" in items[0].notes
    assert not policies[0].safe_for_target_generation

    policies, items, _ = _extract_single_access(
        _safe_access_rule(track={"type": "track-log", "alert": "mail"}), resolver=resolver,
    )
    assert "checkpoint-track-alert" in items[0].notes

    policies, items, _ = _extract_single_access(
        _safe_access_rule(track={"type": "unresolved-track-uid"}), resolver=resolver,
    )
    assert any(reason.startswith("unresolved-track:") for reason in items[0].notes)
    assert not policies[0].safe_for_target_generation

    policies, items, _ = _extract_single_access(_safe_access_rule(**{"action-settings": {"user-check": True}}))
    assert policies == []
    assert "checkpoint-action-settings" in items[0].notes
