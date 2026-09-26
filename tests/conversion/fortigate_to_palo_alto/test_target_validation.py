import io
from pathlib import Path
from types import SimpleNamespace

from fwmigrate.web import create_app
from fwmigrate.conversion.fortigate_to_palo_alto import PANDecisionReviewState, PANMigrationDecision, PANMigrationDecisionSet
from fwmigrate.conversion.fortigate_to_palo_alto.target_validation import validate_against_target
from fwmigrate.vendors.palo_alto.relationships.topology import PANInterfaceTopologyEntry
from fwmigrate.vendors.palo_alto.source_model import PANScope, pan_scope_identity


SOURCE = Path(__file__).parents[2] / "fixtures" / "fortigate" / "palo_alto_mvp.conf"
TARGET = Path(__file__).parents[2] / "fixtures" / "palo_alto" / "integrated_firewall.xml"


def _preview(client, path, vendor):
    return client.post("/api/preview", data={
        "source_vendor": vendor,
        "file": (io.BytesIO(path.read_bytes()), path.name),
    }, content_type="multipart/form-data").get_json()["preview_id"]


def test_confirmed_target_conflict_is_report_only():
    client = create_app({"TESTING": True}).test_client()
    source_preview = _preview(client, SOURCE, "fortigate")
    target_preview = _preview(client, TARGET, "palo_alto")
    requirements = client.post("/api/migration/requirements", json={
        "preview_id": source_preview,
        "target_preview_id": target_preview,
    }).get_json()
    document = requirements["decision_document"]
    for item in document["decisions"]:
        if item["source_kind"] == "interface" and item["source_name"] == "lan" and item["target_field"] == "target_interface":
            item.update(value="ethernet1/1", review_state="CONFIRMED")
        if item["source_kind"] == "interface" and item["source_name"] == "lan" and item["target_field"] == "target_zone":
            item.update(value="untrust", review_state="CONFIRMED")
    result = client.post("/api/migrate", json={
        "preview_id": source_preview,
        "decision_document": document,
        "target_preview_id": target_preview,
        "target_device": "integrated-fw",
    }).get_json()
    findings = result["target_findings"]
    assert any(item["code"] == "TARGET_ZONE_CONFLICT" for item in findings)
    zone_key = next(item["key"] for item in document["decisions"]
                    if item["source_kind"] == "interface" and item["source_name"] == "lan"
                    and item["target_field"] == "target_zone")
    assert result["decision_evidence"][zone_key] == "CONFLICT"
    assert result["evidence_summary"]["conflicts"] >= 1
    assert result["support_guidance"]


def _direct_target(*, target_address="198.51.100.1/24", target_tag=None, target_parent=None,
                   zones=("trust",), imported_vsys=("vsys1",), virtual_routers=("vr-main",)):
    scope = PANScope(kind="device", name="dev", device_name="dev")
    item = SimpleNamespace(name="ethernet1/1", interface_family="vlan" if target_tag else "ethernet",
                           ipv4_addresses=[target_address], scope=scope, tag=target_tag,
                           parent=target_parent)
    return SimpleNamespace(
        config=SimpleNamespace(interfaces=[item], interface_units=[], scopes=[], virtual_routers=[]),
        derived=SimpleNamespace(interface_topology=[
            PANInterfaceTopologyEntry("ethernet1/1", pan_scope_identity(scope),
                                      imported_vsys=imported_vsys, zones=zones,
                                      virtual_routers=virtual_routers, parent=target_parent),
        ]),
    )


def _confirmed(*items):
    return PANMigrationDecisionSet(tuple(
        PANMigrationDecision(*identity, value=value, review_state=PANDecisionReviewState.CONFIRMED)
        for identity, value in items
    ))


def test_target_validation_reports_missing_interface_and_address_difference():
    source = SimpleNamespace(interfaces=[SimpleNamespace(vdom="root", name="lan", type="ethernet", vlanid=None, interface=None, ip="192.0.2.1/24")])
    missing = _confirmed(( ("root", "interface", "lan", "target_interface"), "missing" ))
    assert {item.code for item in validate_against_target(source, missing, _direct_target(), "dev")} == {"TARGET_INTERFACE_NOT_FOUND"}

    different = _confirmed(( ("root", "interface", "lan", "target_interface"), "ethernet1/1" ))
    findings = validate_against_target(source, different, _direct_target(), "dev")
    assert any(item.code == "TARGET_ADDRESS_DIFFERS" for item in findings)


def test_target_validation_reports_vlan_parent_zone_vsys_and_router_conflicts():
    scope = PANScope(kind="device", name="dev", device_name="dev")
    parent = SimpleNamespace(name="ethernet1/1", interface_family="ethernet", ipv4_addresses=[], scope=scope, tag=None, parent=None)
    child = SimpleNamespace(name="ethernet1/1.100", interface_family="vlan", ipv4_addresses=[], scope=scope, tag="200", parent="ethernet1/2")
    target = SimpleNamespace(
        config=SimpleNamespace(interfaces=[parent, child], interface_units=[], scopes=[], virtual_routers=[]),
        derived=SimpleNamespace(interface_topology=[
            PANInterfaceTopologyEntry("ethernet1/1", pan_scope_identity(scope), imported_vsys=("vsys1",),
                                      zones=(), virtual_routers=()),
            PANInterfaceTopologyEntry("ethernet1/1.100", pan_scope_identity(scope), imported_vsys=("vsys1",),
                                      zones=("trust",), virtual_routers=("vr-main",), parent="ethernet1/2"),
        ]),
    )
    source = SimpleNamespace(interfaces=[
        SimpleNamespace(vdom="root", name="port1", type="ethernet", vlanid=None, interface=None, ip=None),
        SimpleNamespace(vdom="root", name="vlan100", type="vlan", vlanid=100, interface="port1", ip=None),
    ])
    decisions = _confirmed(
        (("root", "interface", "port1", "target_interface"), "ethernet1/1"),
        (("root", "interface", "vlan100", "target_interface"), "ethernet1/1.100"),
        (("root", "interface", "vlan100", "target_zone"), "untrust"),
        (("root", "vdom", "root", "vsys"), "vsys2"),
        (("root", "vdom", "root", "virtual_router"), "vr-other"),
    )
    codes = {item.code for item in validate_against_target(source, decisions, target, "dev")}
    assert {"TARGET_VLAN_TAG_MISMATCH", "TARGET_PARENT_MISMATCH", "TARGET_ZONE_CONFLICT",
            "TARGET_VSYS_CONFLICT", "TARGET_VIRTUAL_ROUTER_CONFLICT"} <= codes
