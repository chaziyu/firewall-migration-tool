from dataclasses import replace

import pytest

from fwmigrate.conversion.fortigate_to_cisco_asa.application.workflow import (
    approve_design, build_artifact, build_review,
)
from fwmigrate.conversion.fortigate_to_cisco_asa.planning.naming import item_key
from fwmigrate.conversion.fortigate_to_cisco_asa.rendering.renderer import ASACLIRenderer
from fwmigrate.vendors.cisco_asa import CiscoASASourceReporter
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter


def fixed_source(text):
    text = text.replace('set subnet 10.0.0.0 255.255.255.0', 'set subnet 10.0.0.10 255.255.255.255')
    return text.replace('config firewall policy', '''config firewall ippool
    edit "pool"
        set type one-to-one
        set startip 198.51.100.10
        set endip 198.51.100.10
        set arp-reply disable
    next
end
config firewall policy''').replace('set logtraffic disable', '''set nat enable
        set ippool enable
        set poolname "pool"
        set fixedport enable
        set port-preserve enable
        set nat64 disable
        set nat46 disable
        set natinbound disable
        set natoutbound disable
        set utm-status disable
        set logtraffic disable''')


def destination():
    text = "! Reviewed complete empty target snapshot\n"
    return {"target": CiscoASASourceReporter().analyze_source(text), "target_source_text": text,
            "target_metadata": {"context": "single", "version": "9.20", "mode": "routed",
                                "complete_families": ["interfaces", "objects", "schedules", "routes", "access_rules", "acl_bindings", "nat"]}}


def test_fixed_pool_nat_requires_atomic_policy_and_binding_approval(asa_source_text, asa_options):
    analysis = FortiGateSourceReporter().analyze_source(fixed_source(asa_source_text))
    options = replace(asa_options, nat_evidence={item_key("root", "nat", "10"): {"return_routing_confirmed": True}})
    review = build_review(analysis, options, "source", **destination())
    nat = next(item for item in review["plan"].items if item.family == "nat")
    assert not nat.blockers
    approval = approve_design(review, review["draft"], [nat.key])
    selected = set(approval["selected_items"])
    assert item_key("root", "policy", "10") in selected
    assert item_key("root", "acl_binding", "inside") in selected
    assert item_key("root", "acl_binding", "outside") in selected
    with pytest.raises(ValueError, match="atomic"):
        ASACLIRenderer().render(review["plan"], approved_items=set(nat.dependencies) | {nat.key})
    artifact = build_artifact(analysis, options, "source", approval, **destination())
    commands = artifact["command_text"]
    assert 'nat (inside,any) source static' in commands
    assert 'no-proxy-arp' in commands
    assert 'unidirectional' not in commands
    assert 'access-group ' in commands
    assert commands.index('object network ') < commands.index('nat (inside,any)')


@pytest.mark.parametrize("old,new", [("set fixedport enable", "set fixedport disable"),
    ("set arp-reply disable", "set arp-reply enable"),
    ("set logtraffic disable", "set logtraffic all")])
def test_unproven_or_blocked_policy_never_exports_fixed_nat(asa_source_text, asa_options, old, new):
    analysis = FortiGateSourceReporter().analyze_source(fixed_source(asa_source_text).replace(old, new))
    options = replace(asa_options, nat_evidence={item_key("root", "nat", "10"): {"return_routing_confirmed": True}})
    review = build_review(analysis, options, "source", **destination())
    assert 'nat (inside,any)' not in ASACLIRenderer().render(review["plan"]).command_text
