from dataclasses import replace

import pytest

from fwmigrate.conversion.fortigate_to_juniper_srx.application.workflow import approve_design, build_artifact, build_review
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter
from fwmigrate.vendors.juniper_srx.source_report import JuniperSRXSourceReporter


SOURCE = '''config system interface
    edit "trunk"
        set type physical
        set mode static
        set status up
        set ip 0.0.0.0 0.0.0.0
    next
    edit "tagged"
        set type vlan
        set interface "trunk"
        set vlanid 120
        set mode static
        set status up
        set ip 10.120.0.1 255.255.255.0
    next
end
'''


def vlan_options(options):
    return replace(options, target_platform="vsrx", vlan_interfaces_available=True, zones={},
                   interfaces={"root": {"trunk": {"target_interface": "ge-0/0/0", "unit": 0},
                                        "tagged": {"target_interface": "ge-0/0/0", "unit": 120}}})


def test_vsrx_tagged_only_trunk_binds_parent_and_emits_vlan_tag(complete_options):
    analysis = FortiGateSourceReporter().analyze_source(SOURCE)
    options = vlan_options(complete_options)
    review = build_review(analysis, options, "source")
    child = next(item for item in review["plan"].items if item.source_name == "tagged")
    assert not child.blockers
    approval = approve_design(review, review["draft"], [child.key])
    artifact = build_artifact(analysis, options, "source", approval)
    assert artifact["command_text"].splitlines() == [
        'set interfaces ge-0/0/0 vlan-tagging',
        'set interfaces ge-0/0/0 unit 120 vlan-id 120',
        'set interfaces ge-0/0/0 unit 120 family inet address 10.120.0.1/24',
    ]
    with pytest.raises(ValueError):
        build_artifact(analysis, replace(options, target_platform=None), "source", approval)
    target_text = 'set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24\n'
    compared = build_review(analysis, options, "source",
        target=JuniperSRXSourceReporter().analyze_source(target_text), target_source_text=target_text,
        target_metadata={"context": "root", "version": "25.2R1", "mode": "standalone", "complete_families": ["interfaces"]})
    with pytest.raises(ValueError):
        approve_design(compared, compared["draft"], [child.key])


@pytest.mark.parametrize("change", ["platform", "availability", "untagged_address", "missing_parent", "duplicate_tag"])
def test_vsrx_vlan_rejects_unproven_parent_and_platform(complete_options, change):
    options = vlan_options(complete_options)
    text = SOURCE
    if change == "platform":
        options = replace(options, target_platform=None)
    elif change == "availability":
        options = replace(options, vlan_interfaces_available=False)
    elif change == "untagged_address":
        text = text.replace("0.0.0.0 0.0.0.0", "192.0.2.1 255.255.255.0")
    elif change == "missing_parent":
        text = text.replace('set interface "trunk"', 'set interface "missing"')
    else:
        text += 'config system interface\n    edit "duplicate"' + SOURCE.split('    edit "tagged"')[1]
    analysis = FortiGateSourceReporter().analyze_source(text)
    review = build_review(analysis, options, "source")
    child = next(item for item in review["plan"].items if item.source_name == "tagged")
    assert child.blockers
    with pytest.raises(ValueError):
        approve_design(review, review["draft"], [child.key])
