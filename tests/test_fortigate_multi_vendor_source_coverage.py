import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from fwmigrate.collection import (
    CollectedSource,
    CollectionPart,
    CollectionStatus,
)
from fwmigrate.collection.snapshot import make_snapshot
from fwmigrate.conversion.fortigate_to_palo_alto import FortiGateToPaloAltoPlanner
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter
from fwmigrate.web import create_app
from fwmigrate.web_support.request_source import (
    _require_complete_collection,
    analyze_request_source,
)


FIXTURES = Path(__file__).parent / "fixtures" / "fortigate"


def _analyze(name):
    return FortiGateSourceReporter().analyze_source((FIXTURES / name).read_text(encoding="utf-8"))


def test_explicit_source_fixture_covers_planning_inputs_without_defaults_or_mutation():
    reporter = FortiGateSourceReporter()
    analysis = _analyze("multi_vendor_explicit.conf")
    config = analysis.extracted.config

    assert {item.vdom for item in config.interfaces} == {"root"}
    assert {item.name for item in config.interfaces} == {"lan", "wan", "app-vlan"}
    vlan = next(item for item in config.interfaces if item.name == "app-vlan")
    assert (vlan.type, vlan.interface, vlan.vlanid, vlan.ip) == (
        "vlan", "lan", 120, "10.20.0.1 255.255.255.0"
    )
    assert next(item for item in config.zones if item.name == "inside").members == ["lan", "app-vlan"]
    assert next(item for item in config.addresses if item.name == "client-net").subnet == (
        "10.10.0.0 255.255.255.0"
    )
    assert next(item for item in config.address_groups if item.name == "trusted-clients").members == [
        "client-net"
    ]
    assert {item.name for item in config.services} == {"tcp-app", "udp-dns"}
    assert next(item for item in config.service_groups if item.name == "application-services").members == [
        "tcp-app", "udp-dns"
    ]
    assert [item.policy_id for item in config.policies] == [10, 20]
    assert [(item.action, item.status, item.logtraffic) for item in config.policies] == [
        ("accept", "enable", "all"), ("deny", "enable", "all")
    ]
    assert [item.name for item in config.recurring_schedules] == ["weekday-hours"]
    assert [item.name for item in config.one_time_schedules] == ["change-window"]
    assert [item.seq_num for item in config.static_routes] == [1, 2]

    address = next(item for item in config.addresses if item.name == "future-address")
    assert address.raw_extra == {"future-address-setting": "retained-evidence"}
    before = hashlib.sha256(
        json.dumps(config.model_dump(mode="json"), sort_keys=True).encode("utf-8")
    ).hexdigest()
    planner = FortiGateToPaloAltoPlanner()
    planner.plan(config, analysis.derived)
    planner.plan(config, analysis.derived)
    reporter.build_preview(analysis)
    after = hashlib.sha256(
        json.dumps(config.model_dump(mode="json"), sort_keys=True).encode("utf-8")
    ).hexdigest()
    assert after == before


def test_blocker_fixture_preserves_unmodeled_and_ambiguous_source_evidence():
    analysis = _analyze("multi_vendor_blockers.conf")
    config = analysis.extracted.config

    shared_names = [item for item in config.addresses if item.name == "shared-name"]
    assert [(item.vdom, item.subnet) for item in shared_names] == [
        ("root", "10.0.0.1 255.255.255.255"),
        ("tenant-a", "192.0.2.1 255.255.255.255"),
    ]
    groups = {item.name: item.members for item in config.address_groups}
    assert groups["cycle-a"] == ["cycle-b"]
    assert groups["cycle-b"] == ["cycle-a"]
    assert groups["missing-member"] == ["not-present"]

    policy = next(item for item in config.policies if item.policy_id == 50)
    assert policy.action is None and policy.status is None
    assert "action" not in policy.explicit_fields and "status" not in policy.explicit_fields
    inspection = next(item for item in config.policies if item.policy_id == 40)
    assert (inspection.utm_status, inspection.inspection_mode) == ("enable", "proxy")
    assert next(item for item in config.vips if item.name == "web-port-forward").portforward == "enable"
    assert next(item for item in config.ip_pools if item.name == "overload-pool").type == "overload"

    source_only_paths = {record.source_path for record in analysis.extracted.source_objects}
    assert {"firewall central-snat-map", "router policy"} <= source_only_paths
    unknown = [
        command
        for record in analysis.extracted.source_objects
        for command in record.commands
        if command.operation == "unknown"
    ]
    assert next(item for item in config.policies if item.policy_id == 30).raw_extra[
        "unrecognized-match"
    ] == "preserve-source"
    assert any(command.key == "future-command" for command in unknown)
    assert analysis.derived.broken_references


@pytest.mark.parametrize(
    "status,parts",
    [
        (CollectionStatus.PARTIAL, (CollectionPart("policies", "PARTIAL", False),)),
        (CollectionStatus.SUCCESS, (CollectionPart("policies", "PARTIAL", False),)),
    ],
)
def test_incomplete_collection_parts_never_become_migration_source(status, parts):
    snapshot = make_snapshot(
        CollectedSource(
            "fortigate",
            "config system interface\nend\n",
            "synthetic-partial.conf",
            "ssh",
            status=status,
            parts=parts,
        )
    )
    with create_app({"TESTING": True}).test_request_context("/"):
        entry = analyze_request_source({"source": snapshot}, "fortigate")

        with pytest.raises(ValueError, match="complete live collection"):
            _require_complete_collection(entry)


def test_complete_empty_collection_part_is_accepted():
    snapshot = make_snapshot(
        CollectedSource(
            "fortigate",
            "config system interface\nend\n",
            "synthetic-empty.conf",
            "ssh",
            parts=(CollectionPart("optional-section", "EMPTY", True, 0),),
        )
    )
    with create_app({"TESTING": True}).test_request_context("/"):
        _require_complete_collection(analyze_request_source({"source": snapshot}, "fortigate"))


def test_empty_collection_metadata_on_native_file_is_not_misclassified():
    entry = SimpleNamespace(collection_status=None, evidence={"vendor": "fortigate"})
    _require_complete_collection(entry)
