from dataclasses import replace

from fwmigrate.conversion.fortigate_to_cisco_asa.planner import FortiGateToCiscoASAPlanner
from fwmigrate.conversion.fortigate_to_cisco_asa.rendering.renderer import ASACLIRenderer
from fwmigrate.conversion.fortigate_to_cisco_asa.planning.naming import item_key


def test_ordered_asa_export_contains_objects_policy_and_default_deny(asa_source, asa_options):
    plan = FortiGateToCiscoASAPlanner().plan(asa_source.extracted.config, asa_source.derived, asa_options)
    rendered = ASACLIRenderer().render(plan)
    assert "interface GigabitEthernet0/1" in rendered.commands
    assert " no shutdown" in rendered.commands
    assert any(line.startswith("object network fg_addr_clients_") for line in rendered.commands)
    policy_line = next(line for line in rendered.commands if " extended permit tcp " in line)
    assert "object fg_addr_clients_" in policy_line
    assert "object fg_addr_web_" in policy_line
    assert policy_line.endswith("eq 443")
    assert any(line.endswith("extended deny ip any any") for line in rendered.commands)
    assert not any(line.startswith("access-group ") for line in rendered.commands)
    assert rendered.command_sha256


def test_destination_interface_restriction_is_not_dropped(asa_source, asa_options):
    config = asa_source.extracted.config.model_copy(deep=True)
    config.policies[0].dstintf = ["outside"]
    plan = FortiGateToCiscoASAPlanner().plan(config, asa_source.derived, asa_options)
    policy = next(item for item in plan.items if item.family == "policy")
    assert "POLICY_EGRESS_CONSTRAINT_UNREPRESENTABLE" in policy.blockers
    assert not dict(policy.settings).get("commands")


def test_unknown_policy_state_and_logging_are_blocked(asa_source, asa_options):
    config = asa_source.extracted.config.model_copy(deep=True)
    config.policies[0].status = None
    config.policies[0].logtraffic = "all"
    plan = FortiGateToCiscoASAPlanner().plan(config, asa_source.derived, asa_options)
    policy = next(item for item in plan.items if item.family == "policy")
    assert "POLICY_EXPLICIT_MATCH_OR_STATE_REQUIRED" in policy.blockers
    assert not dict(policy.settings).get("commands")


def test_acl_binding_is_not_generated_without_target_snapshot(asa_source, asa_options):
    plan = FortiGateToCiscoASAPlanner().plan(asa_source.extracted.config, asa_source.derived, asa_options)
    binding = next(item for item in plan.items if item.family == "acl_binding" and item.source_name == "inside")
    assert "TARGET_ACL_BINDING_SNAPSHOT_REQUIRED" in binding.blockers
    assert not dict(binding.settings)["commands"]


def test_inactive_policy_is_preserved_as_inactive_ace(asa_source, asa_options):
    config = asa_source.extracted.config.model_copy(deep=True)
    config.policies[0].status = "disable"
    plan = FortiGateToCiscoASAPlanner().plan(config, asa_source.derived, asa_options)
    rendered = ASACLIRenderer().render(plan)
    rule = next(line for line in rendered.commands if " extended permit tcp " in line)
    assert rule.endswith("inactive")


def test_missing_source_interface_type_and_status_block_target_activation(asa_source, asa_options):
    config = asa_source.extracted.config.model_copy(deep=True)
    config.interfaces[0].explicit_fields.discard("type")
    config.interfaces[0].status = None
    config.interfaces[0].explicit_fields.discard("status")
    plan = FortiGateToCiscoASAPlanner().plan(config, asa_source.derived, asa_options)
    interface = next(item for item in plan.items if item.family == "interface" and item.source_name == "inside")
    assert "INTERFACE_TYPE_NOT_EXPLICITLY_PHYSICAL" in interface.blockers
    assert "INTERFACE_STATUS_NOT_EXPLICIT" in interface.blockers
    assert not dict(interface.settings)["commands"]


def test_address_requires_explicit_supported_source_form(asa_source, asa_options):
    config = asa_source.extracted.config.model_copy(deep=True)
    config.addresses[0].explicit_fields.discard("type")
    plan = FortiGateToCiscoASAPlanner().plan(config, asa_source.derived, asa_options)
    address = next(item for item in plan.items if item.family == "address" and item.source_name == "clients")
    assert "ADDRESS_REPRESENTATION_UNSUPPORTED" in address.blockers
    assert not dict(address.settings)["commands"]
