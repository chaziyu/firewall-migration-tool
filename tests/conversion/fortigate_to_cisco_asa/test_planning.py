from dataclasses import replace

import pytest

from fwmigrate.conversion.fortigate_to_cisco_asa.planner import FortiGateToCiscoASAPlanner
from fwmigrate.conversion.fortigate_to_cisco_asa.rendering.renderer import ASACLIRenderer
from fwmigrate.conversion.fortigate_to_cisco_asa.planning.naming import item_key


@pytest.mark.parametrize("reverse", [False, True])
def test_nested_groups_use_group_object_and_dependency_order(asa_source_text, asa_options, reverse):
    from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter

    text = asa_source_text
    for section, leaf, extra in [("addrgrp", "clients", "set exclude disable"),
                                 ("service group", "https", "set proxy disable")]:
        rows = [f'edit a_parent\nset member z_child {leaf}\n{extra}\nnext\n',
                f'edit z_child\nset member {leaf}\n{extra}\nnext\n']
        text += f"config firewall {section}\n" + "".join(reversed(rows) if reverse else rows) + "end\n"
    source = FortiGateSourceReporter().analyze_source(text)
    plan = FortiGateToCiscoASAPlanner().plan(source.extracted.config, source.derived, asa_options)
    rendered = ASACLIRenderer().render(plan)
    for family in ("address_group", "service_group"):
        parent = next(item for item in plan.items if item.family == family and item.source_name == "a_parent")
        child = next(item for item in plan.items if item.family == family and item.source_name == "z_child")
        assert not parent.blockers
        assert f" group-object {child.target_name}" in rendered.commands
        kind = "network" if family == "address_group" else "service"
        assert rendered.commands.index(f"object-group {kind} {child.target_name}") < rendered.commands.index(f"object-group {kind} {parent.target_name}")


def test_renderer_satisfies_reused_group_and_rejects_bad_dependencies(asa_source, asa_options):
    from fwmigrate.conversion.fortigate_to_cisco_asa.models import ASAPlanItem

    original = FortiGateToCiscoASAPlanner().plan(asa_source.extracted.config, asa_source.derived, asa_options)
    child = ASAPlanItem("child", "address_group", "root", "z_child", "z_child",
                        (("commands", ("must not render",)),), target_disposition="REUSE")
    parent = ASAPlanItem("parent", "address_group", "root", "a_parent", "a_parent",
                         (("commands", ("object-group network a_parent", " group-object z_child")),), ("child",))
    plan = replace(original, items=(parent, child), findings=())
    rendered = ASACLIRenderer().render(plan, approved_items={"parent", "child"})
    assert rendered.commands == ("object-group network a_parent", " group-object z_child")
    with pytest.raises(ValueError, match="unresolved dependency"):
        ASACLIRenderer().render(replace(plan, items=(parent,)))
    with pytest.raises(ValueError, match="cycle"):
        ASACLIRenderer().render(replace(plan, items=(parent, replace(child, dependencies=("parent",)))))


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
