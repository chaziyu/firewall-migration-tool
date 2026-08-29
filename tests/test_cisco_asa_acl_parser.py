from fwmigrate.core.constants import IR_KEYWORD_ANY
from fwmigrate.parsers.cisco_asa.parser import CiscoASAParser


def test_acl_line_sequence_source_port_destination_port_and_logging():
    ir = CiscoASAParser("""
interface Gi0/0
 nameif inside
access-list A line 10 extended permit tcp any eq 1024 host 10.1.1.1 eq 443 log disable inactive
access-group A in interface inside
""").transform_to_ir()
    policy = ir.policies[0]
    service = next(item for item in ir.services if item.name in policy.service)
    assert policy.source == [IR_KEYWORD_ANY]
    assert policy.destination[0].startswith("asa_inline_host_")
    assert service.ports[0].source_port == "1024"
    assert service.ports[0].port == "443"
    assert policy.log_end is False
    assert policy.disabled is True
    assert policy.source_from_interfaces == ["inside"]
    assert policy.to_zone == []


def test_out_global_control_plane_and_multiple_bindings_are_distinct():
    ir = CiscoASAParser("""
interface Gi0/0
 nameif outside
access-list A extended deny ip any any
access-group A out interface outside
access-group A global
access-group A in interface outside control-plane
""").transform_to_ir()
    assert len(ir.policies) == 3
    outbound = next(p for p in ir.policies if p.source_extra_settings.get("binding_direction") == "out")
    assert outbound.source_to_interfaces == ["outside"]
    assert outbound.from_zone == []
    global_rule = next(p for p in ir.policies if p.source_extra_settings.get("global"))
    assert global_rule.requires_manual_review
    control = next(p for p in ir.policies if p.source_extra_settings.get("control_plane"))
    assert control.migration_status == "EXTRACT_ONLY"
