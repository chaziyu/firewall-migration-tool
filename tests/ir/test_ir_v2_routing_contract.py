from fwmigrate.ir import (
    IRExecutionContext,
    IRForwardingPolicy,
    IRPathMonitor,
    IRPolicyBasedForwardingRule,
    IRRoutePathMonitor,
    IRVirtualFirewallContext,
)
from fwmigrate.ir.enums import IRRouteNextHopType


def test_legacy_routing_python_names_are_aliases():
    assert IRExecutionContext is IRVirtualFirewallContext
    assert IRPolicyBasedForwardingRule is IRForwardingPolicy
    assert IRRoutePathMonitor is IRPathMonitor


def test_legacy_context_fields_populate_canonical_identity():
    context = IRExecutionContext(vdom="tenant-a", scope="vdom")

    assert context.context_id == "tenant-a"
    assert context.context_type == "vdom"


def test_routing_instance_next_hop_is_canonical_and_legacy_values_remain():
    assert IRRouteNextHopType.NEXT_ROUTING_INSTANCE.value == "next-routing-instance"
    assert IRRouteNextHopType.NEXT_VR.value == "next-vr"
    assert IRRouteNextHopType.NEXT_LR.value == "next-lr"
