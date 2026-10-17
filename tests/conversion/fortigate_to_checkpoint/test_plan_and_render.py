from dataclasses import replace
from types import SimpleNamespace
import json
import pytest

from fwmigrate.conversion.fortigate_to_checkpoint.planner import FortiGateToCheckPointPlanner
from fwmigrate.conversion.fortigate_to_checkpoint.plan_dependencies import dispositions, ordered_items
from fwmigrate.conversion.fortigate_to_checkpoint.rendering.management import (
    BINDINGS_FILE, GAIA_FILE, MANAGEMENT_FILE, CPManagementRenderer,
)
from fwmigrate.vendors.fortigate.derived import build_derived_views
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter
from tests.conversion.fortigate_to_checkpoint.conftest import SOURCE


def _plan(analysis, options):
    return FortiGateToCheckPointPlanner().plan(
        analysis.extracted.config, analysis.derived, options,
        source_inventory=analysis.extracted.source_objects,
    )


def test_management_requests_bind_returned_uids_and_keep_rule_order(checkpoint_analysis, checkpoint_options):
    plan = _plan(checkpoint_analysis, checkpoint_options)
    rendered = CPManagementRenderer().render(plan)
    state = dispositions(plan)
    assert all(value == "CREATE" for value in state.values())

    payload = json.loads(rendered.management_text)
    assert payload["api_version"] == "1.8.1"
    assert payload["operation_count"] == 7
    assert [row["path"] for row in payload["operations"]] == [
        "/web_api/add-network", "/web_api/add-host", "/web_api/add-host",
        "/web_api/add-service-tcp", "/web_api/add-service-udp",
        "/web_api/add-access-rule", "/web_api/add-access-rule",
    ]
    rules = [row for row in payload["operations"] if row["path"] == "/web_api/add-access-rule"]
    assert rules[0]["request_body_template"]["position"] == {"above": "Cleanup Drop"}
    assert rules[1]["request_body_template"]["position"] == {
        "below": {"$response_binding": f"{rules[0]['operation_id']}.uid"},
    }
    client_address = next(item for item in rendered.report["items"]
                          if item["family"] == "address" and item["source_name"] == "clients")
    assert rules[0]["request_body_template"]["source"] == [{"$response_binding": f"{client_address['key']}.uid"}]
    assert rules[0]["request_body_template"]["destination"][0]["$response_binding"].endswith(".uid")
    assert rules[0]["request_body_template"]["install-on"] == ["cp-gw-test"]
    assert rules[0]["request_body_template"]["track"] == {"type": "Log"}
    assert rules[1]["request_body_template"]["action"] == "Drop"
    assert rules[1]["request_body_template"]["service"] == ["Any"]
    assert BINDINGS_FILE in rendered.files and GAIA_FILE in rendered.files and MANAGEMENT_FILE in rendered.files
    assert rendered.file_hashes[MANAGEMENT_FILE]
    assert rendered.report["destination_snapshot_compared"] is False


def test_gaia_route_is_separate_and_has_no_save_or_activation(checkpoint_analysis, checkpoint_options):
    rendered = CPManagementRenderer().render(_plan(checkpoint_analysis, checkpoint_options))
    assert rendered.gaia_text == (
        "set static-route 10.20.0.0/24 nexthop gateway address 10.10.0.254 on\n"
    )
    assert "save config" not in rendered.gaia_text.casefold()
    assert "set static-route" not in rendered.management_text


def test_interface_bound_earlier_policy_blocks_later_rule(checkpoint_analysis, checkpoint_options):
    source = checkpoint_analysis.extracted.config
    policies = list(source.policies)
    policies[0] = policies[0].model_copy(update={"srcintf": ["lan"]})
    broken_source = source.model_copy(update={"policies": policies})
    plan = FortiGateToCheckPointPlanner().plan(
        broken_source, checkpoint_analysis.derived, checkpoint_options,
        source_inventory=checkpoint_analysis.extracted.source_objects,
    )
    rule_items = [item for item in plan.items if item.family == "policy"]
    assert "POLICY_INTERFACE_CONSTRAINT_UNREPRESENTABLE" in rule_items[0].blockers
    assert dispositions(plan)[rule_items[1].key] == "BLOCK"


def test_policy_unknown_negation_nat_and_ipv6_state_stay_blocked(checkpoint_analysis, checkpoint_options):
    source = checkpoint_analysis.extracted.config
    first = source.policies[0]
    policies = list(source.policies)
    policies[0] = first.model_copy(update={"srcaddr_negate": None})
    changed = source.model_copy(update={"policies": policies})
    missing_negation = FortiGateToCheckPointPlanner().plan(changed, checkpoint_analysis.derived, checkpoint_options)
    first_rule = next(item for item in missing_negation.items if item.family == "policy")
    assert "POLICY_SRCADDR_NEGATE_UNKNOWN" in first_rule.blockers

    policies[0] = first.model_copy(update={"nat": "enable"})
    changed = source.model_copy(update={"policies": policies})
    nat_plan = FortiGateToCheckPointPlanner().plan(changed, checkpoint_analysis.derived, checkpoint_options)
    first_rule = next(item for item in nat_plan.items if item.family == "policy")
    assert "POLICY_NAT_REMAINS_MANUAL" in first_rule.blockers

    policies[0] = first.model_copy(update={"srcaddr6": ["all6"]})
    changed = source.model_copy(update={"policies": policies})
    ipv6_plan = FortiGateToCheckPointPlanner().plan(changed, checkpoint_analysis.derived, checkpoint_options)
    first_rule = next(item for item in ipv6_plan.items if item.family == "policy")
    assert "POLICY_IDENTITY_INSPECTION_OR_IPV6_UNSUPPORTED" in first_rule.blockers


def test_only_a_real_source_all_reference_maps_to_checkpoint_any(checkpoint_analysis, checkpoint_options):
    source = checkpoint_analysis.extracted.config
    policies = list(source.policies)
    policies[0] = policies[0].model_copy(update={"srcaddr": ["any"]})
    changed = source.model_copy(update={"policies": policies})
    plan = FortiGateToCheckPointPlanner().plan(changed, checkpoint_analysis.derived, checkpoint_options)
    rendered = CPManagementRenderer().render(plan)
    operations = json.loads(rendered.management_text)["operations"]
    rule = next(row for row in operations if row["path"] == "/web_api/add-access-rule")
    source_ref = rule["request_body_template"]["source"][0]
    assert source_ref != "Any"
    assert "$response_binding" in source_ref


def test_destination_comparison_and_unsupported_route_paths_remain_blocked(checkpoint_analysis, checkpoint_options):
    plan = _plan(checkpoint_analysis, checkpoint_options)
    changed_options = replace(checkpoint_options, gaia_target="")
    blocked = FortiGateToCheckPointPlanner().plan(
        checkpoint_analysis.extracted.config, checkpoint_analysis.derived, changed_options,
        source_inventory=checkpoint_analysis.extracted.source_objects,
    )
    route = next(item for item in blocked.items if item.family == "static_route")
    assert "GAIA_TARGET_REQUIRED" in route.blockers
    assert plan.options["management_domain"] == "Default Domain"


def test_nested_address_and_mixed_protocol_service_groups_expand_to_leaf_objects(checkpoint_analysis, checkpoint_options):
    source_text = SOURCE.replace(
        '''            next
        end
        config firewall service custom''',
        '''            next
            edit "outer-group"
                set member "client-group"
            next
        end
        config firewall service custom''',
        1,
    ).replace('set srcaddr "client-group"', 'set srcaddr "outer-group"', 1).replace(
        '''            next
        end
        config firewall policy''',
        '''            next
            edit "outer-services"
                set member "web-services"
            next
        end
        config firewall policy''',
        1,
    ).replace('set service "https"', 'set service "outer-services"', 1)
    analysis = FortiGateSourceReporter().analyze_source(source_text)
    plan = FortiGateToCheckPointPlanner().plan(
        analysis.extracted.config, analysis.derived, checkpoint_options,
        source_inventory=analysis.extracted.source_objects,
    )
    rendered = CPManagementRenderer().render(plan)
    operations = json.loads(rendered.management_text)["operations"]
    rule = next(row for row in operations if row["path"] == "/web_api/add-access-rule")
    assert len(rule["request_body_template"]["source"]) == 1
    assert len(rule["request_body_template"]["service"]) == 2
    assert {row["path"] for row in operations} >= {"/web_api/add-service-tcp", "/web_api/add-service-udp"}
    assert not any("group" in row["path"] for row in operations)


def test_central_snat_remains_visible_and_blocks_policy_output(checkpoint_options):
    source_text = SOURCE.replace(
        "        config router static\n",
        '''        config firewall central-snat-map
            edit 1
                set orig-addr "clients"
                set dst-addr "web"
                set nat-ippool "pool"
            next
        end
        config router static
''',
        1,
    )
    analysis = FortiGateSourceReporter().analyze_source(source_text)
    plan = FortiGateToCheckPointPlanner().plan(
        analysis.extracted.config, analysis.derived, checkpoint_options,
        source_inventory=analysis.extracted.source_objects,
    )
    policies = [item for item in plan.items if item.family == "policy"]
    assert all("UNREPRESENTED_CENTRAL_SNAT_BLOCKS_POLICY_EXPORT" in item.blockers for item in policies)
    assert all(not dict(item.settings).get("management_operation") for item in policies)


def test_duplicate_source_address_names_block_ambiguous_uid_bindings(checkpoint_options):
    analysis = FortiGateSourceReporter().analyze_source(SOURCE)
    config = analysis.extracted.config
    duplicate = config.addresses[0].model_copy(update={"subnet": "10.11.0.0 255.255.255.0"})
    config = config.model_copy(update={"addresses": [*config.addresses, duplicate]})
    derived = build_derived_views(config)
    plan = FortiGateToCheckPointPlanner().plan(
        config, derived, checkpoint_options,
        source_inventory=analysis.extracted.source_objects,
    )
    duplicates = [item for item in plan.items if item.family == "address" and item.source_name == "clients"]
    assert len(duplicates) == 2
    assert all("DUPLICATE_SOURCE_ADDRESS" in item.blockers for item in duplicates)
    policy = next(item for item in plan.items if item.family == "policy")
    assert "DUPLICATE_SOURCE_ADDRESS" in policy.blockers
    assert not dict(policy.settings).get("management_operation")


def test_same_address_name_in_another_vdom_keeps_a_distinct_scoped_identity(checkpoint_options):
    analysis = FortiGateSourceReporter().analyze_source(SOURCE)
    config = analysis.extracted.config
    other_vdom = config.addresses[0].model_copy(update={"vdom": "other", "subnet": "10.11.0.0 255.255.255.0"})
    config = config.model_copy(update={"addresses": [*config.addresses, other_vdom]})
    derived = build_derived_views(config)
    planner = FortiGateToCheckPointPlanner()
    root_plan = planner.plan(config, derived, checkpoint_options, source_inventory=analysis.extracted.source_objects)
    other_plan = planner.plan(
        config, derived, replace(checkpoint_options, source_vdom="other"),
        source_inventory=analysis.extracted.source_objects,
    )
    root_address = next(item for item in root_plan.items if item.family == "address" and item.source_name == "clients")
    other_address = next(item for item in other_plan.items if item.family == "address" and item.source_name == "clients")
    assert root_address.key != other_address.key
    assert not root_address.blockers
    assert other_address.source_vdom == "other"


def test_sanitized_target_name_collisions_get_deterministic_distinct_names(checkpoint_analysis, checkpoint_options):
    config = checkpoint_analysis.extracted.config
    first = config.addresses[0].model_copy(update={"name": "web/service", "subnet": "10.12.0.0 255.255.255.0"})
    second = config.addresses[0].model_copy(update={"name": "web service", "subnet": "10.13.0.0 255.255.255.0"})
    config = config.model_copy(update={"addresses": [*config.addresses, first, second]})
    plan = FortiGateToCheckPointPlanner().plan(config, build_derived_views(config), checkpoint_options)
    targets = [item.target_name for item in plan.items if item.family == "address" and item.source_name in {first.name, second.name}]
    assert len(targets) == 2
    assert len(set(targets)) == 2
    assert all("web_service" in name for name in targets)


def test_cyclic_address_and_service_groups_block_dependent_rules(checkpoint_analysis, checkpoint_options):
    source = checkpoint_analysis.extracted.config
    address_group = source.address_groups[0]
    address_cycle = source.model_copy(update={
        "address_groups": [
            address_group.model_copy(update={"members": ["outer-group"]}),
            address_group.model_copy(update={"name": "outer-group", "members": [address_group.name]}),
        ],
    })
    address_plan = FortiGateToCheckPointPlanner().plan(
        address_cycle, build_derived_views(address_cycle), checkpoint_options,
    )
    address_rule = next(item for item in address_plan.items if item.family == "policy")
    assert "ADDRESS_GROUP_CYCLE" in address_rule.blockers
    assert not dict(address_rule.settings).get("management_operation")

    service_group = source.service_groups[0]
    service_cycle = source.model_copy(update={
        "service_groups": [
            service_group.model_copy(update={"members": ["outer-services"]}),
            service_group.model_copy(update={"name": "outer-services", "members": [service_group.name]}),
        ],
        "policies": [source.policies[0].model_copy(update={"service": [service_group.name]}), *source.policies[1:]],
    })
    service_plan = FortiGateToCheckPointPlanner().plan(
        service_cycle, build_derived_views(service_cycle), checkpoint_options,
    )
    first, later = [item for item in service_plan.items if item.family == "policy"]
    assert "SERVICE_GROUP_CYCLE" in first.blockers
    assert "EARLIER_SOURCE_POLICY_REMAINS_MANUAL" in later.blockers
    assert not dict(first.settings).get("management_operation")


def test_unknown_source_value_and_secret_canary_never_enter_export(checkpoint_options):
    canary = "SYNTHETIC_SECRET_CANARY_91a2"
    source_text = SOURCE.replace(
        '                set subnet 10.10.0.0 255.255.255.0',
        f'                set subnet 10.10.0.0 255.255.255.0\n                set unsupported-option "{canary}"',
        1,
    )
    analysis = FortiGateSourceReporter().analyze_source(source_text)
    plan = FortiGateToCheckPointPlanner().plan(
        analysis.extracted.config, analysis.derived, checkpoint_options,
        source_inventory=analysis.extracted.source_objects,
    )
    rendered = CPManagementRenderer().render(plan)
    serialized = b"".join(rendered.files.values()).decode("utf-8") + json.dumps(rendered.report, sort_keys=True)
    assert canary not in serialized
    address = next(item for item in plan.items if item.family == "address" and item.source_name == "clients")
    assert "ADDRESS_HAS_UNSUPPORTED_SOURCE_SETTINGS" in address.blockers


def test_gaia_ipv6_route_uses_separate_verified_file(checkpoint_options):
    source_text = '''config router static6
    edit 21
        set dst 2001:db8:1::/64
        set gateway 2001:db8::1
        set status enable
        set blackhole disable
    next
end
'''
    analysis = FortiGateSourceReporter().analyze_source(source_text)
    plan = FortiGateToCheckPointPlanner().plan(
        analysis.extracted.config, analysis.derived, checkpoint_options,
        source_inventory=analysis.extracted.source_objects,
    )
    rendered = CPManagementRenderer().render(plan)
    assert "set ipv6 static-route 2001:db8:1::/64 nexthop gateway 2001:db8::1 on\n" in rendered.gaia_text
    assert "set ipv6 static-route" not in rendered.management_text


def test_dependency_order_handles_long_chain_and_rejects_cycle():
    chain = [SimpleNamespace(key=f"item-{index}", dependencies=(() if index == 0 else (f"item-{index - 1}",)),
                             blockers=(), settings=()) for index in range(2500)]
    assert len(ordered_items(SimpleNamespace(items=chain))) == 2500
    assert all(value == "CREATE" for value in dispositions(SimpleNamespace(items=chain)).values())

    cycle = [
        SimpleNamespace(key="first", dependencies=("second",), blockers=(), settings=()),
        SimpleNamespace(key="second", dependencies=("first",), blockers=(), settings=()),
    ]
    with pytest.raises(ValueError, match="dependency cycle"):
        ordered_items(SimpleNamespace(items=cycle))
