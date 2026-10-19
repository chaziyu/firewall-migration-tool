from dataclasses import replace

import pytest

from fwmigrate.conversion.fortigate_to_cisco_asa.application.workflow import approve_design, build_artifact, build_review
from fwmigrate.vendors.cisco_asa import CiscoASASourceReporter
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter


VLAN = '''config system interface
    edit "tagged"
        set type vlan
        set interface "inside"
        set vlanid 120
        set ip 10.120.0.1 255.255.255.0
        set status up
    next
end
'''


def vlan_options(options):
    return replace(options, target_platform="asav", vlan_interfaces_available=True,
                   interfaces={"root": {**options.interfaces["root"], "tagged": {
                       "interface": "GigabitEthernet0/1.120", "nameif": "app", "security_level": 50}}})


def test_asav_vlan_approval_includes_physical_parent_before_subinterface(asa_source_text, asa_options):
    analysis = FortiGateSourceReporter().analyze_source(asa_source_text + VLAN)
    options = vlan_options(asa_options)
    review = build_review(analysis, options, "source")
    child = next(item for item in review["plan"].items if item.family == "interface" and item.source_name == "tagged")
    assert not child.blockers
    approval = approve_design(review, review["draft"], [child.key])
    artifact = build_artifact(analysis, options, "source", approval)
    commands = artifact["command_text"]
    assert " vlan 120\n" in commands
    assert commands.index("interface GigabitEthernet0/1\n") < commands.index("interface GigabitEthernet0/1.120\n")
    parsed = CiscoASASourceReporter().analyze_source(commands)
    assert next(row for row in parsed.config.interfaces if row.vlan_id == 120).parent_interface == "GigabitEthernet0/1"
    with pytest.raises(ValueError):
        build_artifact(analysis, replace(options, vlan_interfaces_available=False), "source", approval)


@pytest.mark.parametrize("change", ["platform", "availability", "parent", "duplicate_tag"])
def test_asav_vlan_requires_platform_availability_and_unique_parent_tag(asa_source_text, asa_options, change):
    text = asa_source_text + VLAN
    options = vlan_options(asa_options)
    if change == "platform":
        options = replace(options, target_platform=None)
    elif change == "availability":
        options = replace(options, vlan_interfaces_available=False)
    elif change == "parent":
        text = text.replace('set interface "inside"', 'set interface "missing"')
    else:
        text += VLAN.replace('edit "tagged"', 'edit "duplicate"')
    analysis = FortiGateSourceReporter().analyze_source(text)
    review = build_review(analysis, options, "source")
    child = next(item for item in review["plan"].items if item.family == "interface" and item.source_name == "tagged")
    assert child.blockers
    with pytest.raises(ValueError):
        approve_design(review, review["draft"], [child.key])
