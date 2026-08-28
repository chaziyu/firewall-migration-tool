import pytest
from fwmigrate.parsers.checkpoint.models import CheckPointResponse
from fwmigrate.parsers.checkpoint.resolver import CheckPointObjectResolver, SemanticKind
from fwmigrate.parsers.checkpoint.objects import extract_address_objects
from fwmigrate.parsers.checkpoint.schedules import extract_time_objects
from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.ir.enums import AddressType


def test_extract_hosts_networks_and_ranges():
    resolver = CheckPointObjectResolver()
    responses = [
        CheckPointResponse(
            command="show-hosts",
            data={
                "objects": [
                    {
                        "uid": "uid-h1",
                        "name": "Host1",
                        "type": "host",
                        "ipv4-address": "10.0.0.1",
                        "comments": "App Server",
                        "nat-settings": {"auto-stat": True}
                    },
                    {
                        "uid": "uid-h2",
                        "name": "Host2_v6",
                        "type": "host",
                        "ipv6-address": "2001:db8::1",
                    }
                ]
            }
        ),
        CheckPointResponse(
            command="show-networks",
            data={
                "objects": [
                    {
                        "uid": "uid-n1",
                        "name": "Net_Corp",
                        "type": "network",
                        "subnet4": "192.168.1.0",
                        "mask-length4": 24,
                    },
                    {
                        "uid": "uid-n2",
                        "name": "Net_MaskString",
                        "type": "network",
                        "subnet4": "172.16.0.0",
                        "subnet-mask": "255.240.0.0",
                    }
                ]
            }
        ),
        CheckPointResponse(
            command="show-address-ranges",
            data={
                "objects": [
                    {
                        "uid": "uid-r1",
                        "name": "Range_Pool",
                        "type": "address-range",
                        "ipv4-address-first": "10.1.1.100",
                        "ipv4-address-last": "10.1.1.200",
                    }
                ]
            }
        )
    ]

    addrs, grps, items, unsupp = extract_address_objects(responses, resolver)

    assert len(addrs) == 5
    assert len(grps) == 0
    assert len(items) == 5
    assert len(unsupp) == 0

    h1 = next(a for a in addrs if a.name == "Host1")
    assert h1.type == AddressType.HOST
    assert h1.subnet == "10.0.0.1/32"

    n1 = next(a for a in addrs if a.name == "Net_Corp")
    assert n1.type == AddressType.NETWORK
    assert n1.subnet == "192.168.1.0/24"

    n2 = next(a for a in addrs if a.name == "Net_MaskString")
    assert n2.type == AddressType.NETWORK
    assert n2.subnet == "172.16.0.0/12"

    r1 = next(a for a in addrs if a.name == "Range_Pool")
    assert r1.type == AddressType.RANGE
    assert r1.ip_range_start == "10.1.1.100"
    assert r1.ip_range_end == "10.1.1.200"


def test_invalid_netmask_does_not_fallback_to_default():
    resolver = CheckPointObjectResolver()
    responses = [
        CheckPointResponse(
            command="show-networks",
            data={
                "objects": [
                    {
                        "uid": "uid-bad-net",
                        "name": "Net_Corrupt",
                        "type": "network",
                        "subnet4": "10.0.0.0",
                        "mask-length4": "invalid_mask"
                    }
                ]
            }
        )
    ]

    addrs, grps, items, unsupp = extract_address_objects(responses, resolver)

    assert len(addrs) == 0
    assert len(items) == 1
    assert items[0].status == ExtractionStatus.PARTIALLY_NORMALIZED
    assert items[0].requires_manual_review
    res = resolver.resolve("uid-bad-net")
    assert not res.usable_in_canonical_reference


def test_group_with_exclusion_and_special_types():
    resolver = CheckPointObjectResolver()
    responses = [
        CheckPointResponse(
            command="show-groups-with-exclusion",
            data={
                "objects": [
                    {
                        "uid": "uid-ex-grp",
                        "name": "Grp_Exclude_DMZ",
                        "type": "group-with-exclusion",
                        "include": "Net_All",
                        "except": "Net_DMZ"
                    }
                ]
            }
        ),
        CheckPointResponse(
            command="show-objects",
            data={
                "objects": [
                    {
                        "uid": "uid-dyn-1",
                        "name": "Dyn_Local",
                        "type": "dynamic-object"
                    },
                    {
                        "uid": "uid-upd-1",
                        "name": "Office365",
                        "type": "updatable-object"
                    },
                    {
                        "uid": "uid-dc-1",
                        "name": "AWS_VPC",
                        "type": "data-center-object"
                    }
                ]
            }
        )
    ]

    addrs, grps, items, unsupp = extract_address_objects(responses, resolver)

    assert len(unsupp) == 4
    for item in items:
        assert item.requires_manual_review
        assert item.status in (ExtractionStatus.PARTIALLY_NORMALIZED, ExtractionStatus.EXTRACT_ONLY)


def test_extract_schedules_and_time_groups():
    resolver = CheckPointObjectResolver()
    responses = [
        CheckPointResponse(
            command="show-times",
            data={
                "objects": [
                    {
                        "uid": "uid-time-work",
                        "name": "WorkHours",
                        "type": "time",
                        "start-time": "08:00",
                        "end-time": "17:00",
                        "recurrence": "daily"
                    }
                ]
            }
        ),
        CheckPointResponse(
            command="show-time-groups",
            data={
                "objects": [
                    {
                        "uid": "uid-tgrp-1",
                        "name": "MaintenanceWindows",
                        "type": "time-group",
                        "members": ["WorkHours"]
                    }
                ]
            }
        )
    ]

    scheds, items, unsupp = extract_time_objects(responses, resolver)

    assert len(scheds) == 1
    assert scheds[0].name == "WorkHours"
    assert scheds[0].start == "08:00"
    assert scheds[0].end == "17:00"
    assert len(unsupp) == 1
    assert unsupp[0].source_name == "MaintenanceWindows"


@pytest.mark.parametrize("obj", [
    {"uid": "dual-host", "name": "DualHost", "type": "host",
     "ipv4-address": "10.0.0.1", "ipv6-address": "2001:db8::1"},
    {"uid": "dual-net", "name": "DualNet", "type": "network",
     "subnet4": "10.0.0.0", "mask-length4": 24,
     "subnet6": "2001:db8::", "mask-length6": 64},
])
def test_dual_stack_object_is_not_silently_reduced_to_ipv4(obj):
    resolver = CheckPointObjectResolver()
    addresses, _, items, _ = extract_address_objects([
        CheckPointResponse(command="show-objects", data={"objects": [obj]})
    ], resolver)
    assert addresses == []
    assert items[0].status == ExtractionStatus.PARTIALLY_NORMALIZED
    assert "dual-stack-object" in items[0].notes
    assert not resolver.resolve(obj["uid"]).usable_in_canonical_reference


def test_unnamed_and_unknown_objects_are_accounted_conservatively():
    resolver = CheckPointObjectResolver()
    _, _, items, unsupported = extract_address_objects([
        CheckPointResponse(command="show-objects", data={"objects": [
            {"uid": "unnamed", "type": "host", "ipv4-address": "10.0.0.1"},
            {"uid": "mystery", "name": "Mystery", "type": "future-r81-object"},
        ]})
    ], resolver)
    assert len(items) == 2
    assert items[0].status == ExtractionStatus.PARSE_ERROR
    assert items[1].status == ExtractionStatus.UNSUPPORTED
    assert any(item.source_name == "Mystery" for item in unsupported)


def test_object_nat_settings_are_available_as_translation_evidence():
    resolver = CheckPointObjectResolver()
    _, _, items, _ = extract_address_objects([
        CheckPointResponse(command="show-hosts", data={"objects": [{
            "uid": "auto-nat-host",
            "name": "AutoNATHost",
            "type": "host",
            "ipv4-address": "10.0.0.10",
            "nat-settings": {
                "auto-rule": True,
                "method": "hide",
                "hide-behind": "gateway",
            },
        }]})
    ], resolver, nat_rulebase_complete=True)
    metadata = resolver.get_automatic_nat_metadata("auto-nat-host")
    assert metadata == {
        "auto-rule": True,
        "method": "hide",
        "hide-behind": "gateway",
    }
    assert "automatic-nat-method:hide" in items[0].notes
