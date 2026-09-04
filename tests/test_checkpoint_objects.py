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
    assert unsupp == []


@pytest.mark.parametrize("obj", [
    {"uid": "dual-host", "name": "DualHost", "type": "host",
     "ipv4-address": "10.0.0.1", "ipv6-address": "2001:db8::1"},
    {"uid": "dual-net", "name": "DualNet", "type": "network",
     "subnet4": "10.0.0.0", "mask-length4": 24,
     "subnet6": "2001:db8::", "mask-length6": 64},
])
def test_dual_stack_object_expands_deterministically_and_keeps_uid(obj):
    resolver = CheckPointObjectResolver()
    addresses, _, items, _ = extract_address_objects([
        CheckPointResponse(command="show-objects", data={"objects": [obj]})
    ], resolver)
    assert [address.name for address in addresses] == [f"{obj['name']}__ipv4", f"{obj['name']}__ipv6"]
    assert all(address.source_uuid == obj["uid"] for address in addresses)
    resolution = resolver.resolve(obj["uid"])
    assert resolution.canonical_name is None
    assert resolution.canonical_names == [f"{obj['name']}__ipv4", f"{obj['name']}__ipv6"]


def test_dual_stack_group_expands_member_reference_without_arbitrary_family_choice():
    resolver = CheckPointObjectResolver()
    addresses, groups, _, _ = extract_address_objects([
        CheckPointResponse(command="show-objects", data={"objects": [
            {"uid": "dual", "name": "Dual", "type": "host", "ipv4-address": "10.0.0.1", "ipv6-address": "2001:db8::1"},
            {"uid": "group", "name": "Both", "type": "group", "members": ["dual"]},
        ]})
    ], resolver)
    assert len(addresses) == 2
    assert groups[0].members == ["Dual__ipv4", "Dual__ipv6"]


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


def test_r81_api_shaped_time_objects_preserve_fidelity():
    resolver = CheckPointObjectResolver()
    objects = [{
        "uid": "daily", "name": "DailyWindow", "type": "time",
        "hours-ranges": [{"enabled": True, "from": "08:00", "to": "17:00", "index": 1}],
        "recurrence": {"pattern": "Daily", "weekdays": [], "days": [], "month": None},
    }, {
        "uid": "weekly", "name": "WeeklyWindow", "type": "time",
        "hours-ranges": [{"enabled": True, "from": "09:00", "to": "12:00", "index": 1}],
        "recurrence": {"pattern": "Weekly", "weekdays": ["Mon", "Wed"]},
    }, {
        "uid": "bounded", "name": "Bounded", "type": "time",
        "start": {"date": "2026-01-01", "time": "00:00", "iso-8601": "2026-01-01T00:00:00Z"},
        "end-never": True,
        "hours-ranges": [{"enabled": True, "from": "08:00", "to": "17:00", "index": 1}],
        "recurrence": {"pattern": "Daily"},
    }, {
        "uid": "multi", "name": "Multi", "type": "time",
        "hours-ranges": [
            {"enabled": True, "from": "08:00", "to": "10:00", "index": 1},
            {"enabled": True, "from": "14:00", "to": "16:00", "index": 2},
        ],
        "recurrence": {"pattern": "Daily"},
    }]
    schedules, items, _ = extract_time_objects([
        CheckPointResponse(command="show-times", data={"objects": objects})
    ], resolver)
    assert {schedule.name for schedule in schedules} == {"DailyWindow", "WeeklyWindow", "Bounded", "Multi"}
    assert next(schedule for schedule in schedules if schedule.name == "WeeklyWindow").days == ["Mon", "Wed"]
    by_name = {item.name: item for item in items}
    assert by_name["Bounded"].status == ExtractionStatus.NORMALIZED
    assert by_name["Multi"].status == ExtractionStatus.NORMALIZED


@pytest.mark.parametrize("extra,reason", [
    ({"start-now": True}, "start-now-constraint"),
    ({"start-now": False}, "missing-start-endpoint"),
    ({"end-never": True}, "end-never-constraint"),
    ({"end-never": False}, "missing-end-endpoint"),
    ({"start-now": "false"}, "invalid-start-now"),
    ({"end-never": 0}, "invalid-end-never"),
    ({"recurrence": {"pattern": "Monthly", "days": [1], "month": 8}}, "unsupported-recurrence:monthly"),
    ({"recurrence": None}, "missing-or-malformed-recurrence"),
])
def test_r81_time_constraints_are_never_defaulted_to_daily(extra, reason):
    obj = {
        "uid": "time-uid", "name": "Constrained", "type": "time",
        "hours-ranges": [{"enabled": True, "from": "08:00", "to": "17:00"}],
        "recurrence": {"pattern": "Daily"},
        **extra,
    }
    schedules, items, _ = extract_time_objects([
        CheckPointResponse(command="show-times", data={"objects": [obj]})
    ], CheckPointObjectResolver())
    invalid = {"missing-start-endpoint", "missing-end-endpoint", "invalid-start-now", "invalid-end-never", "missing-or-malformed-recurrence"}
    assert len(schedules) == (0 if reason in invalid else 1)
    assert items[0].status == (ExtractionStatus.PARTIALLY_NORMALIZED if reason in invalid else ExtractionStatus.NORMALIZED)
    if reason in invalid:
        assert reason in items[0].notes
    assert items[0].source_attributes == obj


def test_r81_time_structured_endpoints_and_disabled_window_are_preserved():
    obj = {
        "uid": "bounded", "name": "Bounded", "type": "time",
        "start-now": False,
        "start": {"date": "2026-08-30", "time": "08:00", "posix": 1788057600},
        "end-never": False,
        "end": {"date": "2026-08-31", "time": "17:00", "iso-8601": "2026-08-31T17:00:00Z"},
        "hours-ranges": [
            {"enabled": True, "from": "08:00", "to": "17:00", "index": 1},
            {"enabled": False, "from": "18:00", "to": "19:00", "index": 2},
        ],
        "recurrence": {"pattern": "Weekly", "weekdays": ["Mon", "Tue"]},
    }
    schedules, items, _ = extract_time_objects([
        CheckPointResponse(command="show-times", data={"objects": [obj]})
    ], CheckPointObjectResolver())
    assert len(schedules) == 1
    assert items[0].status == ExtractionStatus.NORMALIZED
    assert schedules[0].start_endpoint["posix"] == 1788057600
    assert schedules[0].end_endpoint["iso-8601"] == "2026-08-31T17:00:00Z"
    assert items[0].source_attributes["hours-ranges"][1]["enabled"] is False


@pytest.mark.parametrize("version,first,last", [
    (4, "10.0.0.10", "10.0.0.1"),
    (6, "2001:db8::10", "2001:db8::1"),
])
def test_reversed_address_range_is_rejected(version, first, last):
    prefix = "ipv4" if version == 4 else "ipv6"
    addresses, _, items, _ = extract_address_objects([
        CheckPointResponse(command="show-address-ranges", data={"objects": [{
            "uid": "reversed", "name": "Reversed", "type": "address-range",
            f"{prefix}-address-first": first, f"{prefix}-address-last": last,
        }]})
    ], CheckPointObjectResolver())
    assert addresses == []
    assert items[0].requires_manual_review


def test_automatic_nat_completeness_is_domain_and_package_scoped():
    response = CheckPointResponse(
        command="show-hosts", domain="Domain-A", package="Package-A",
        data={"objects": [{
            "uid": "auto", "name": "Auto", "type": "host",
            "ipv4-address": "10.0.0.1", "nat-settings": {"auto-rule": True, "method": "hide"},
        }]},
    )
    _, _, items, _ = extract_address_objects(
        [response], CheckPointObjectResolver(), nat_rulebase_complete=True,
        nat_completeness_by_scope={("Domain-B", "Package-B"): True},
    )
    assert items[0].status == ExtractionStatus.PARTIALLY_NORMALIZED
    assert "automatic-nat-scope:Domain-A/Package-A" in items[0].notes

    _, _, complete_items, _ = extract_address_objects(
        [response], CheckPointObjectResolver(), nat_rulebase_complete=False,
        nat_completeness_by_scope={("Domain-A", "Package-A"): True},
    )
    assert complete_items[0].status == ExtractionStatus.NORMALIZED
