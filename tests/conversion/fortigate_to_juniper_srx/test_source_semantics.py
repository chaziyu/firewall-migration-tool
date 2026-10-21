from dataclasses import replace

import pytest

from fwmigrate.conversion.fortigate_to_juniper_srx.planner import FortiGateToJuniperSRXPlanner
from fwmigrate.conversion.fortigate_to_juniper_srx.rendering.renderer import JunosSetRenderer
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter


HEADER = '#config-version=FG100E-7.2.13-FW-build1762-260128\n'


def _plan(text, options):
    analysis = FortiGateSourceReporter().analyze_source(text)
    before = analysis.extracted.config.model_dump(mode="json")
    plan = FortiGateToJuniperSRXPlanner().plan(
        analysis.extracted.config, analysis.derived, options,
        source_inventory=analysis.extracted.source_objects,
    )
    assert analysis.extracted.config.model_dump(mode="json") == before
    return analysis, plan


@pytest.mark.parametrize("header,supported", [(HEADER, True), ("", False), (HEADER.replace("7.2.13", "7.4.6"), False)])
def test_address_defaults_are_version_bound_and_metadata_stays_in_source(header, supported, complete_options):
    analysis, plan = _plan(header + '''config firewall address
edit clients
set uuid 00000000-0000-0000-0000-000000000001
set color 3
set subnet 192.0.2.0 255.255.255.0
next
end
config firewall addrgrp
edit group
set uuid 00000000-0000-0000-0000-000000000002
set member clients
next
end
''', complete_options)
    address = next(row for row in plan.items if row.family == "address")
    assert (not address.blockers) is supported
    assert analysis.extracted.config.addresses[0].type is None
    assert "uuid" in analysis.extracted.config.addresses[0].raw_extra
    rendered = JunosSetRenderer().render(plan)
    assert bool(rendered.commands) is supported
    if supported:
        assert dict(address.settings)["value"] == "192.0.2.0/24"
        evidence = dict(address.settings)["source_effective_values"]
        assert evidence[0]["version"] == "7.2.13"
        assert evidence[0]["field"] == "type"
        assert "#page=355" in evidence[0]["reference"]
        assert len(rendered.commands) == 2


@pytest.mark.parametrize("extra", ['set vendor-option unknown', 'set associated-interface lan', 'set fqdn example.test'])
def test_address_metadata_allowlist_does_not_hide_semantic_settings(extra, complete_options):
    _, plan = _plan(HEADER + f'''config firewall address
edit clients
set subnet 192.0.2.0 255.255.255.0
{extra}
next
end
''', complete_options)
    assert all(row.blockers for row in plan.items)
    assert not JunosSetRenderer().render(plan).commands


@pytest.mark.parametrize("subnet", ["", "set type ipmask\nset subnet 0.0.0.0 0.0.0.0"])
def test_fabric_runtime_membership_never_becomes_an_unrestricted_prefix(subnet, complete_options):
    _, plan = _plan(HEADER + f'''config firewall address
edit FABRIC_DEVICE
{subnet}
next
end
config firewall addrgrp
edit fabric-group
set member FABRIC_DEVICE
next
end
''', complete_options)
    address = next(row for row in plan.items if row.family == "address")
    group = next(row for row in plan.items if row.family == "address_group")
    assert "DYNAMIC_FABRIC_ADDRESS_UNSUPPORTED" in address.blockers
    assert "ADDRESS_GROUP_MEMBER_BLOCKED" in group.blockers
    assert not JunosSetRenderer().render(plan).commands


@pytest.mark.parametrize("header,supported", [(HEADER, True), ("", False), (HEADER.replace("7.2.13", "7.4.6"), False)])
def test_ordinary_policy_defaults_keep_order_without_guessing(header, supported, policy_analysis, complete_options):
    from pathlib import Path
    source = (Path(__file__).parents[2] / "fixtures/fortigate/multi_vendor_explicit.conf").read_text(encoding="utf-8")
    source = source.replace('set interface "lan" "app-vlan"', 'set interface "lan"', 1)
    for setting in ("status enable", "nat disable", "utm-status disable", "srcaddr-negate disable", "dstaddr-negate disable", "service-negate disable"):
        source = source.replace(f"set {setting}", "")
    analysis, plan = _plan(header + source, complete_options)
    policies = [row for row in plan.items if row.family == "policy"]
    assert all(not row.blockers for row in policies) is supported
    assert analysis.extracted.config.policies[0].status is None
    assert policies[0].key in policies[1].dependencies
    commands = JunosSetRenderer().render(plan).command_text
    assert ("set security policies" in commands) is supported
    if supported:
        assert dict(policies[0].settings)["action"] == "permit"
        assert dict(policies[1].settings)["action"] == "deny"


def test_active_utm_and_unknown_policy_settings_stay_blocked(policy_analysis, complete_options):
    source = policy_analysis.extracted.config.model_copy(deep=True)
    source.policies[0] = source.policies[0].model_copy(update={"utm_status": "enable", "logtraffic": "utm"})
    from fwmigrate.vendors.fortigate.derived import build_derived_views
    plan = FortiGateToJuniperSRXPlanner().plan(source, build_derived_views(source), complete_options,
        source_inventory=policy_analysis.extracted.source_objects)
    assert not any("security policies" in line for line in JunosSetRenderer().render(plan).commands)


def test_interface_and_route_defaults_are_reviewed_not_written_to_source(complete_options):
    complete_options = replace(complete_options, interface_zones={"root": {"lan": "lan-zone"}})
    analysis, plan = _plan(HEADER + '''config system interface
edit lan
set type physical
set ip 192.0.2.1 255.255.255.0
set snmp-index 1
next
end
config router static
edit 1
set gateway 192.0.2.254
set device lan
next
end
''', complete_options)
    assert analysis.extracted.config.interfaces[0].mode is None
    assert analysis.extracted.config.static_routes[0].distance is None
    assert all(not row.blockers for row in plan.items)
    commands = JunosSetRenderer().render(plan).command_text
    assert "family inet address 192.0.2.1/24" in commands
    assert "static route 0.0.0.0/0 next-hop 192.0.2.254" in commands
    assert "static route 0.0.0.0/0 preference 10" in commands
    changed = replace(complete_options, interfaces={})
    _, blocked = _plan(HEADER + '''config system interface
edit lan
set type physical
set ip 192.0.2.1 255.255.255.0
next
end
''', changed)
    assert not JunosSetRenderer().render(blocked).commands


@pytest.mark.parametrize("consumer,allowed", [("lan", True), ("wan", False)])
def test_interface_bound_addresses_require_every_nested_consumer_to_match(consumer, allowed, complete_options):
    _, plan = _plan(HEADER + f'''config system interface
edit lan
set type physical
set ip 192.0.2.1 255.255.255.0
next
end
config firewall address
edit bound
set subnet 192.0.2.0 255.255.255.0
set associated-interface lan
next
end
config firewall addrgrp
edit nested
set member bound
next
end
config firewall policy
edit 1
set srcintf {consumer}
set srcaddr nested
next
end
''', complete_options)
    address = next(row for row in plan.items if row.family == "address")
    assert (not address.blockers) is allowed
