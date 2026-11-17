import io
from pathlib import Path
from types import SimpleNamespace
from fwmigrate.web import create_app
from fwmigrate.conversion.fortigate_to_palo_alto import PANDecisionReviewState, PANMigrationDecision, PANMigrationDecisionSet
from fwmigrate.conversion.fortigate_to_palo_alto.target.target_validation import validate_against_target
from fwmigrate.vendors.palo_alto.relationships.topology import PANInterfaceTopologyEntry
from fwmigrate.vendors.palo_alto.source_model import PANScope, pan_scope_identity
from fwmigrate.conversion.fortigate_to_palo_alto.target.target_evidence import bind_legacy_target_evidence, reconcile_target_evidence, target_evidence_changed
import pytest
from fwmigrate.conversion.fortigate_to_palo_alto.target.target_intent import apply_target_intent, export_target_intent, parse_target_intent
from fwmigrate.vendors.fortigate.model.interface import FGInterface
from fwmigrate.vendors.fortigate.model.source import FGConfig
from fwmigrate.vendors.fortigate.model.zone import FGZone
from fwmigrate.conversion.fortigate_to_palo_alto.models import PANMigrationPlan, PANMigrationStatus, PlannedAddress, PlannedAddressGroup, PlannedInterface, PlannedNATRule, PlannedStaticRoute, PlannedSchedule, PlannedZone, PlannedSecurityRule, PlannedService
from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import PANSetRenderer
from fwmigrate.conversion.fortigate_to_palo_alto.plan_dependencies import build_plan_dependency_index, item_key
from fwmigrate.conversion.fortigate_to_palo_alto.target.target_object_reuse import classify_target_object_reuse, _address, _members, _schedule, _service
from fwmigrate.conversion.fortigate_to_palo_alto.target.target_plan_validation import PANRenderDisposition, assess_target_plan, validate_target_plan
from fwmigrate.conversion.fortigate_to_palo_alto.target.target_validation import PANTargetFinding
from fwmigrate.vendors.palo_alto.model.address import PANAddress, PANAddressGroup
from fwmigrate.vendors.palo_alto.model.schedule import PANSchedule, PANScheduleRecurring
from fwmigrate.vendors.palo_alto.model.service import PANService, PANServiceProtocol, PANServiceOverride
from fwmigrate.vendors.palo_alto.model.routing import PANStaticRoute, PANVirtualRouter
from fwmigrate.vendors.palo_alto.model.nat import PANNATRule
from fwmigrate.vendors.palo_alto.model.policy import PANSecurityRule
from fwmigrate.vendors.palo_alto.model.interface import PANInterface
from fwmigrate.vendors.palo_alto.model.zone import PANZone
from fwmigrate.conversion.fortigate_to_palo_alto.target.target_suggestions import discover_target_candidates, suggest_from_target, target_device_metadata, target_devices
from fwmigrate.conversion.fortigate_to_palo_alto.interface_candidates import candidate_evidence
from fwmigrate.conversion.fortigate_to_palo_alto.target.target_suggestions import _compatible
from fwmigrate.conversion.fortigate_to_palo_alto.target.target_candidates import PANTargetCandidateMatchClass, build_target_candidates, classify_candidate
from fwmigrate.vendors.palo_alto.model.dhcp import PANDHCPServer
from fwmigrate.vendors.palo_alto.model.source import PANOSConfig
from fwmigrate.vendors.palo_alto.native import build_derived_views
from dataclasses import replace
from fwmigrate.conversion.fortigate_to_palo_alto.validation import validate_plan
from fwmigrate.conversion.fortigate_to_palo_alto import PANMigrationOptions, apply_explicit_options

# --- test_target_validation.py ---
SOURCE = Path(__file__).parents[2] / "fixtures" / "fortigate" / "palo_alto_mvp.conf"
TARGET = Path(__file__).parents[2] / "fixtures" / "palo_alto" / "integrated_firewall.xml"


def _preview(client, path, vendor):
    return client.post("/api/preview", data={
        "source_vendor": vendor,
        "file": (io.BytesIO(path.read_bytes()), path.name),
    }, content_type="multipart/form-data").get_json()["source_evidence"]


def test_confirmed_target_conflict_is_report_only():
    client = create_app({"TESTING": True}).test_client()
    source_preview = _preview(client, SOURCE, "fortigate")
    target_preview = _preview(client, TARGET, "palo_alto")
    requirements = client.post("/api/migration/requirements", json={
        "source": source_preview,
        "target_source": target_preview,
    }).get_json()
    document = requirements["decision_document"]
    for item in document["decisions"]:
        if item["source_kind"] == "interface" and item["source_name"] == "lan" and item["target_field"] == "target_interface":
            item.update(value="ethernet1/1", review_state="CONFIRMED")
        if item["source_kind"] == "interface" and item["source_name"] == "lan" and item["target_field"] == "target_zone":
            item.update(value="untrust", review_state="CONFIRMED")
    result = client.post("/api/migration/requirements", json={
        "source": source_preview,
        "decision_document": document,
        "target_source": target_preview,
        "target_device": "integrated-fw",
    }).get_json()
    findings = result["target_findings"]
    assert any(item["code"] == "TARGET_ZONE_CONFLICT" for item in findings)
    zone_key = next(item["key"] for item in document["decisions"]
                    if item["source_kind"] == "interface" and item["source_name"] == "lan"
                    and item["target_field"] == "target_zone")
    assert result["decision_evidence"][zone_key] == "CONFLICT"
    assert result["evidence_summary"]["conflicts"] >= 1
    assert "design_approval" not in result["decision_document"]


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


def test_duplicate_assignments_without_target_report_every_owner_including_auto():
    from dataclasses import replace
    from fwmigrate.conversion.fortigate_to_palo_alto.decisions import PANDecisionMode

    decisions = _confirmed(
        (("root", "interface", "port1", "target_interface"), "ethernet1/3"),
        (("branch", "interface", "port1", "target_interface"), "ethernet1/3"),
        (("root", "interface", "vlan201", "target_interface"), "ethernet1/3.201"),
        (("root", "interface", "vlan202", "target_interface"), "ethernet1/3.202"),
    )
    decisions = PANMigrationDecisionSet((replace(decisions.decisions[0], mode=PANDecisionMode.AUTO,
        review_state=PANDecisionReviewState.PENDING), *decisions.decisions[1:]))
    findings = validate_against_target(SimpleNamespace(interfaces=[]), decisions, None, None)
    assert {item.decision_key for item in findings} == {item.key for item in decisions.decisions[:2]}
    assert all(item.code == "TARGET_INTERFACE_ALREADY_ASSIGNED" and len(item.evidence) == 2 for item in findings)


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


def test_vdom_topology_checks_only_its_own_mapped_interfaces():
    scope = PANScope(kind="device", name="dev", device_name="dev")
    records = [SimpleNamespace(name=name, interface_family="ethernet", ipv4_addresses=[],
               scope=scope, tag=None, parent=None) for name in ("ethernet1/1", "ethernet1/2")]
    target = SimpleNamespace(config=SimpleNamespace(interfaces=records, interface_units=[],
        scopes=[], virtual_routers=[]), derived=SimpleNamespace(interface_topology=[
        PANInterfaceTopologyEntry(name, pan_scope_identity(scope), imported_vsys=(vsys,),
            virtual_routers=(router,)) for name, vsys, router in (
            ("ethernet1/1", "vsys1", "vr1"), ("ethernet1/2", "vsys2", "vr2"))]))
    source = SimpleNamespace(interfaces=[SimpleNamespace(vdom=vdom, name="port1", type="physical",
        vlanid=None, interface=None, ip=None) for vdom in ("root", "branch")])
    decisions = _confirmed(
        (("root", "interface", "port1", "target_interface"), "ethernet1/1"),
        (("root", "vdom", "root", "vsys"), "vsys1"),
        (("root", "vdom", "root", "virtual_router"), "vr1"),
        (("branch", "interface", "port1", "target_interface"), "ethernet1/2"),
        (("branch", "vdom", "branch", "vsys"), "vsys2"),
        (("branch", "vdom", "branch", "virtual_router"), "vr2"),
    )
    assert not [item for item in validate_against_target(source, decisions, target, "dev")
                if item.severity == "error"]

# --- test_target_evidence.py ---
TARGET_A = {"vendor": "palo_alto", "config_digest": "digest-a", "device": "fw-a"}
TARGET_B = {"vendor": "palo_alto", "config_digest": "digest-b", "device": "fw-a"}
TARGET_OTHER_DEVICE = {"vendor": "palo_alto", "config_digest": "digest-a", "device": "fw-b"}


def _evidence_confirmed(*, evidence_type="AUTOMATION_VERIFIED", digest="digest-a", device="fw-a"):
    return PANMigrationDecision(
        "root", "interface", "wan", "target_interface",
        value="ethernet1/1",
        review_state=PANDecisionReviewState.CONFIRMED,
        evidence_source="DERIVED",
        evidence_type=evidence_type,
        target_object="ethernet1/1",
        evidence_target_digest=digest,
        evidence_target_device=device,
    )


def test_target_evidence_changed_compares_digest_device_and_removal():
    assert target_evidence_changed(TARGET_A, TARGET_A) is False
    assert target_evidence_changed(TARGET_A, TARGET_B) is True
    assert target_evidence_changed(TARGET_A, TARGET_OTHER_DEVICE) is True
    assert target_evidence_changed(TARGET_A, None) is True
    assert target_evidence_changed(None, TARGET_A) is False


def test_reconcile_preserves_matching_and_invalidates_changed_or_removed_target_evidence():
    decisions = PANMigrationDecisionSet((_evidence_confirmed(),))
    same, same_invalidated = reconcile_target_evidence(decisions, TARGET_A)
    assert same == decisions
    assert same_invalidated == ()

    for evidence in (TARGET_B, TARGET_OTHER_DEVICE, None):
        reconciled, invalidated = reconcile_target_evidence(decisions, evidence)
        decision = reconciled.decisions[0]
        assert decision.review_state is PANDecisionReviewState.PENDING
        assert decision.value is None
        assert decision.target_object is None
        assert decision.evidence_target_digest is None
        assert decision.evidence_target_device is None
        assert invalidated[0]["old_value"] == "ethernet1/1"
        assert invalidated[0]["previous_target_digest"] == "digest-a"


def test_reconcile_does_not_invalidate_engineer_or_source_only_confirmations():
    engineer = PANMigrationDecision(
        "root", "vdom", "root", "vsys",
        value="vsys1",
        review_state=PANDecisionReviewState.CONFIRMED,
        evidence_source="ENGINEER",
        evidence_type="TARGET_INTENT",
        target_object="vsys1",
    )
    source_only = PANMigrationDecision(
        "root", "interface", "lan", "target_zone",
        value="TRUST",
        review_state=PANDecisionReviewState.CONFIRMED,
        evidence_source="DERIVED",
        evidence_type="AUTOMATION_DERIVED",
        target_object="TRUST",
    )
    decisions = PANMigrationDecisionSet((engineer, source_only))
    reconciled, invalidated = reconcile_target_evidence(decisions, TARGET_B)
    assert reconciled == decisions
    assert invalidated == ()


def test_legacy_auto_confirmations_bind_to_document_target_but_engineer_intent_does_not():
    auto = PANMigrationDecision(
        "root", "interface", "wan", "target_interface",
        value="ethernet1/1",
        review_state=PANDecisionReviewState.CONFIRMED,
        evidence_source="DERIVED",
        evidence_type="AUTOMATION_VERIFIED",
    )
    intent = PANMigrationDecision(
        "root", "vdom", "root", "vsys",
        value="vsys1",
        review_state=PANDecisionReviewState.CONFIRMED,
        evidence_source="ENGINEER",
        evidence_type="TARGET_INTENT",
    )
    upgraded = bind_legacy_target_evidence(PANMigrationDecisionSet((auto, intent)), TARGET_A)
    by_type = {item.evidence_type: item for item in upgraded.decisions}
    assert by_type["AUTOMATION_VERIFIED"].evidence_target_digest == "digest-a"
    assert by_type["AUTOMATION_VERIFIED"].evidence_target_device == "fw-a"
    assert by_type["TARGET_INTENT"].evidence_target_digest is None

# --- test_target_intent.py ---
def test_yaml_intent_confirms_only_existing_scoped_decisions_and_round_trips():
    config = FGConfig(interfaces=[FGInterface(name="agg1"), FGInterface(name="lan", vdom="blue")],
                      zones=[FGZone(name="LAN", vdom="blue")])
    decisions = PANMigrationDecisionSet((
        PANMigrationDecision("root", "interface", "agg1", "target_interface"),
        PANMigrationDecision("blue", "interface", "lan", "target_interface"),
        PANMigrationDecision("blue", "interface", "lan", "target_zone"),
        PANMigrationDecision("blue", "zone", "LAN", "target_zone"),
        PANMigrationDecision("blue", "vdom", "blue", "vsys"),
    ))
    text = "vdoms:\n  blue:\n    vsys: vsys2\ninterfaces:\n  agg1: ae1\n  blue/lan:\n    interface: ethernet1/2\n    zone: TRUST\nzones:\n  LAN: TRUST\n"
    updated = apply_target_intent(config, decisions, text)
    confirmed = {item.key: item for item in updated.decisions}
    assert all(item.review_state == PANDecisionReviewState.CONFIRMED for item in confirmed.values())
    assert confirmed[decisions.decisions[1].key].value == "ethernet1/2"
    assert all(item.evidence_target_digest is None and item.evidence_target_device is None
               for item in confirmed.values())
    exported = parse_target_intent(export_target_intent(updated))
    assert exported["interfaces"]["blue/lan"]["interface"] == "ethernet1/2"
    assert exported["interfaces"]["blue/lan"]["zone"] == "TRUST"


def test_target_intent_rejects_unknown_source_and_unsupported_decision():
    config = FGConfig(interfaces=[FGInterface(name="lan")])
    decisions = PANMigrationDecisionSet((PANMigrationDecision("root", "interface", "lan", "target_interface"),))
    with pytest.raises(ValueError, match="Unknown FortiGate interface"):
        apply_target_intent(config, decisions, {"interfaces": {"missing": "ethernet1/1"}})
    with pytest.raises(ValueError, match="only vdoms"):
        parse_target_intent({"target_config": {}})

# --- test_target_object_reuse.py ---
def test_zone_reuse_and_additive_delta_require_explicit_compatible_membership():
    plan = PANMigrationPlan(zones=(PlannedZone(source_vdom='root', source_kind='zone',
        source_object_type='zone', source_name='inside', target_name='trust', target_vsys='vsys1',
        status=PANMigrationStatus.SUPPORTED, interfaces=('ethernet1/1', 'ethernet1/1.10')),))
    zone = PANZone(name='trust', source_path='/zone',
        scope=PANScope(kind='vsys', name='vsys1', vsys='vsys1', device_name='dev'),
        network_type='layer3', members=['ethernet1/1'], explicit_fields={'network_type', 'members'})
    target = SimpleNamespace(config=SimpleNamespace(zones=[zone]))
    assert classify_target_object_reuse(plan, target, 'dev')[0]['status'] == 'NAME_CONFLICT'
    addition = classify_target_object_reuse(plan, target, 'dev', allow_additive=True)[0]
    assert addition['status'] == 'ADDITIVE'
    assert addition['configure_paths'] == [('vsys', 'zone', 'trust', 'network', 'layer3', '[', 'ethernet1/1.10', ']')]
    assert zone.members == ['ethernet1/1']
    zone.members.append('ethernet1/1.10')
    assert classify_target_object_reuse(plan, target, 'dev', allow_additive=True)[0]['status'] == 'EXACT_MATCH'
    zone.members = ['ethernet1/2']
    assert classify_target_object_reuse(plan, target, 'dev', allow_additive=True)[0]['status'] == 'NAME_CONFLICT'
    zone.raw_extra = {'unknown': 'setting'}
    assert classify_target_object_reuse(plan, target, 'dev', allow_additive=True)[0]['status'] == 'AMBIGUOUS'


def _target(address):
    return SimpleNamespace(config=SimpleNamespace(
        addresses=[address], address_groups=[], services=[], service_groups=[], schedules=[],
        scopes=[address.scope]), derived=SimpleNamespace(reference_index=None, scope_hierarchy=None))


def test_same_name_address_reuse_requires_exact_explicit_semantics():
    plan = PANMigrationPlan(addresses=(PlannedAddress(source_vdom="root", source_kind="address",
        source_object_type="address", source_name="lan-net", target_vsys="vsys1", target_name="lan-net",
        status=PANMigrationStatus.SUPPORTED, address_type="ip-netmask", value="192.0.2.0/24"),))
    scope = PANScope(kind="vsys", name="vsys1", vsys="vsys1", device_name="dev")
    target_address = PANAddress(name="lan-net", source_path="/config/devices/entry/vsys/entry/address/entry",
        scope=scope, ip_netmask="192.0.2.0/24", explicit_fields={"ip_netmask"})
    reuse = classify_target_object_reuse(plan, _target(target_address), "dev")
    assert reuse[0]["status"] == "EXACT_MATCH"

    target_address.ip_netmask = "198.51.100.0/24"
    conflict = classify_target_object_reuse(plan, _target(target_address), "dev")
    assert conflict[0]["status"] == "NAME_CONFLICT"


def test_missing_target_explicit_field_is_not_treated_as_exact():
    plan = PANMigrationPlan(addresses=(PlannedAddress(source_vdom="root", source_kind="address",
        source_object_type="address", source_name="lan-net", target_vsys="vsys1", target_name="lan-net",
        status=PANMigrationStatus.SUPPORTED, address_type="ip-netmask", value="192.0.2.0/24"),))
    scope = PANScope(kind="vsys", name="vsys1", vsys="vsys1", device_name="dev")
    target_address = PANAddress(name="lan-net", source_path="/config/devices/entry/vsys/entry/address/entry",
        scope=scope, ip_netmask="192.0.2.0/24", explicit_fields=set())
    result = classify_target_object_reuse(plan, _target(target_address), "dev")
    assert result[0]["status"] != "EXACT_MATCH"


def test_address_reuse_rejects_alternate_form_and_unknown_semantics():
    source = PlannedAddress(address_type="ip-netmask", value="192.0.2.1/32")
    alternate = PANAddress(source_path="/address", ip_netmask="192.0.2.1/32", ip_range="192.0.2.1-192.0.2.1",
                           explicit_fields={"ip_netmask", "ip_range"})
    assert _address(source, alternate)[2]
    unknown = PANAddress(source_path="/address", ip_netmask="192.0.2.1/32",
                         explicit_fields={"ip_netmask"}, raw_extra={"future": "value"})
    assert _address(source, unknown)[1]


def test_address_tags_prevent_unverified_exact_reuse():
    source = PlannedAddress(address_type="ip-netmask", value="192.0.2.1/32")
    target = PANAddress(source_path="/address", ip_netmask="192.0.2.1/32", tags=["dynamic-membership"],
                        explicit_fields={"ip_netmask", "tags"})
    assert _address(source, target)[0] == ()
    assert any("tags" in warning for warning in _address(source, target)[1])


def test_address_group_reuse_rejects_dynamic_or_unknown_semantics():
    source = PlannedAddressGroup(source_object_type="address_group", members=("a",))
    dynamic = PANAddressGroup(source_path="/group", static_members=["a"], dynamic_filter="tag eq x",
                              explicit_fields={"static_members", "dynamic_filter"})
    assert _members(source, dynamic)[1]
    unknown = PANAddressGroup(source_path="/group", static_members=["a"],
                              explicit_fields={"static_members"}, raw_extra={"future": "value"})
    assert _members(source, unknown)[1]


def test_shared_object_is_visible_to_the_selected_vsys_for_exact_reuse():
    plan = PANMigrationPlan(addresses=(PlannedAddress(source_vdom="root", source_object_type="address",
        source_name="lan-net", target_vsys="vsys1", target_name="lan-net",
        status=PANMigrationStatus.SUPPORTED, address_type="ip-netmask", value="192.0.2.0/24"),))
    shared = PANAddress(name="lan-net", source_path="/config/shared/address/entry",
        scope=PANScope(kind="shared", name="shared"), ip_netmask="192.0.2.0/24",
        explicit_fields={"ip_netmask"})
    target = SimpleNamespace(config=SimpleNamespace(addresses=[shared], scopes=[
        PANScope(kind="vsys", name="vsys1", vsys="vsys1", device_name="dev")]),
        derived=SimpleNamespace(reference_index=None, scope_hierarchy=None))
    assert classify_target_object_reuse(plan, target, "dev")[0]["status"] == "EXACT_MATCH"


def test_same_name_semantic_conflict_is_not_rendered():
    plan = PANMigrationPlan(addresses=(PlannedAddress(source_vdom="root", source_object_type="address", source_name="lan-net",
        target_vsys="vsys1", target_name="lan-net", status=PANMigrationStatus.SUPPORTED,
        address_type="ip-netmask", value="192.0.2.0/24"),))
    reuse = ({"family": "address", "source_vdom": "root", "source_kind": None, "target_vsys": "vsys1",
        "source_name": "lan-net", "target_name": "lan-net", "status": "NAME_CONFLICT"},)
    decisions = PANMigrationDecisionSet()
    dispositions, blockers = assess_target_plan(plan, reuse, (), decisions, build_plan_dependency_index(plan, decisions))
    assert plan.addresses[0].status == PANMigrationStatus.SUPPORTED
    rendered = PANSetRenderer().render(plan, dispositions=dispositions, render_blockers=blockers)
    assert rendered.commands == ()
    assert rendered.report["items"][0]["render_disposition"] == "BLOCK"


def test_target_validation_error_blocks_rendering_only_in_affected_vdom():
    plan = PANMigrationPlan(addresses=(
        PlannedAddress(source_vdom="root", source_name="root-net", target_vsys="vsys1",
            target_name="root-net", status=PANMigrationStatus.SUPPORTED,
            address_type="ip-netmask", value="192.0.2.0/24"),
        PlannedAddress(source_vdom="blue", source_name="blue-net", target_vsys="vsys2",
            target_name="blue-net", status=PANMigrationStatus.SUPPORTED,
            address_type="ip-netmask", value="198.51.100.0/24"),
    ))
    decision = PANMigrationDecision("root", "vdom", "root", "vsys", value="vsys1",
                                    review_state=PANDecisionReviewState.CONFIRMED)
    finding = PANTargetFinding(decision.key, "TARGET_VSYS_CONFLICT", "error", "missing")
    decisions = PANMigrationDecisionSet((decision,))
    dependencies = build_plan_dependency_index(plan, decisions)
    dispositions, _ = assess_target_plan(plan, (), (finding,), decisions, dependencies)
    assert dispositions[item_key(plan.addresses[0])] is PANRenderDisposition.BLOCK
    assert dispositions[item_key(plan.addresses[1])] is PANRenderDisposition.CREATE
    assert plan.addresses[0].status is plan.addresses[1].status is PANMigrationStatus.SUPPORTED


def test_interface_conflict_blocks_its_zone_dependents_only():
    plan = PANMigrationPlan(
        addresses=(PlannedAddress(source_vdom="root", source_object_type="address", source_name="web-net",
            target_vsys="vsys1", target_name="web-net", status=PANMigrationStatus.SUPPORTED,
            address_type="ip-netmask", value="192.0.2.0/24"),),
        services=(PlannedService(source_vdom="root", source_object_type="service", source_name="https",
            target_vsys="vsys1", target_name="https", status=PANMigrationStatus.SUPPORTED,
            protocol="tcp", destination_port="443"),),
        zones=(PlannedZone(source_vdom="root", source_kind="interface", source_name="lan",
            source_object_type="zone", target_vsys="vsys1", target_name="trust",
            status=PANMigrationStatus.SUPPORTED, interfaces=("ethernet1/1",)),),
        security_rules=(PlannedSecurityRule(applications=("any",), source_vdom="root", source_kind="policy", source_name="allow-web",
            source_object_type="security_rule", target_vsys="vsys1", target_name="allow-web",
            status=PANMigrationStatus.SUPPORTED, from_zones=("trust",), to_zones=("trust",),
            sources=("web-net",), destinations=("web-net",), services=("https",), action="allow"),),
    )
    decision = PANMigrationDecision("root", "interface", "lan", "target_interface", value="ethernet1/1",
                                    review_state=PANDecisionReviewState.CONFIRMED)
    finding = PANTargetFinding(decision.key, "TARGET_INTERFACE_FAMILY_MISMATCH", "error", "incompatible")
    decisions = PANMigrationDecisionSet((decision,))
    dependencies = build_plan_dependency_index(plan, decisions)
    dispositions, _ = assess_target_plan(plan, (), (finding,), decisions, dependencies)
    assert dispositions[item_key(plan.zones[0])] is PANRenderDisposition.BLOCK
    assert dispositions[item_key(plan.security_rules[0])] is PANRenderDisposition.BLOCK
    assert dispositions[item_key(plan.addresses[0])] is PANRenderDisposition.CREATE
    assert dispositions[item_key(plan.services[0])] is PANRenderDisposition.CREATE
    finding_result = validate_target_plan(plan, (), (finding,), decisions, dependencies)[0]
    assert finding_result.code == "TARGET_MAPPING_CONFLICT"
    assert finding_result.message == "incompatible"
    assert item_key(plan.security_rules[0]) in finding_result.affected_item_keys


def test_existing_route_destination_requires_exact_route_semantics_for_reuse():
    plan = PANMigrationPlan(static_routes=(PlannedStaticRoute(source_vdom="root", source_kind="static_route",
        source_object_type="static_route", source_name="10", target_name="10", status=PANMigrationStatus.SUPPORTED,
        destination="192.0.2.0/24", nexthop_type="ip-address", nexthop="192.0.2.1", admin_distance=10,
        virtual_router="vr-main"),))
    scope = PANScope(kind="device", name="dev", device_name="dev")
    existing = PANStaticRoute(name="10", source_path="/router/vr/static-route/entry", scope=scope,
        destination="192.0.2.0/24", nexthop_type="ip-address", nexthop_ip_address="192.0.2.1",
        admin_distance="10", explicit_fields={"destination", "nexthop_type", "nexthop_ip_address", "admin_distance"})
    target = SimpleNamespace(config=SimpleNamespace(virtual_routers=[PANVirtualRouter(name="vr-main",
        source_path="/router", scope=scope, static_routes=[existing])], interfaces=[], interface_units=[],
        zones=[], addresses=[], address_groups=[], services=[], service_groups=[], schedules=[]),
        derived=SimpleNamespace(reference_index=None, scope_hierarchy=None))
    collision = classify_target_object_reuse(plan, target, "dev")
    route = next(item for item in collision if item["family"] == "static_route")
    assert route["status"] == "AMBIGUOUS"
    existing.nexthop_ip_address = "198.51.100.1"
    collision = classify_target_object_reuse(plan, target, "dev")
    route = next(item for item in collision if item["family"] == "static_route")
    assert route["status"] == "NAME_CONFLICT"


def test_nat_overlap_is_reported_and_not_auto_reused():
    scope = PANScope(kind="vsys", name="vsys1", vsys="vsys1", device_name="dev")
    planned = PlannedNATRule(source_vdom="root", source_name="nat1", target_name="nat1",
        target_vsys="vsys1", status=PANMigrationStatus.SUPPORTED, from_zones=("TRUST",),
        to_zones=("UNTRUST",), source_addresses=("lan-net",), destination_addresses=("web-net",), service="https")
    target_rule = PANNATRule(name="existing-nat", source_path="/nat/rule", scope=scope,
        from_zones=["TRUST"], to_zones=["UNTRUST"], source=["lan-net"], destination=["web-net"],
        service="https", explicit_fields={"from_zones", "to_zones", "source", "destination", "service"})
    target = SimpleNamespace(config=SimpleNamespace(nat_rules=[target_rule]))
    collision = classify_target_object_reuse(PANMigrationPlan(nat_rules=(planned,)), target, "dev")
    assert collision[0]["status"] == "AMBIGUOUS"


def test_daily_schedule_reuse_compares_daily_fields_and_requires_explicit_target():
    planned = PlannedSchedule(schedule_type="recurring", daily=(("08:00", "17:00"),))
    target = PANSchedule(name="business-hours", source_path="/schedule", recurring=PANScheduleRecurring(
        daily=["08:00-17:00"], explicit_fields={"daily"}), explicit_fields={"recurring"})
    assert _schedule(planned, target)[0]
    target.recurring.explicit_fields.clear()
    assert not _schedule(planned, target)[0]


def test_weekly_and_non_recurring_schedule_comparisons_use_their_own_fields():
    weekly = PlannedSchedule(schedule_type="recurring", weekly=(("monday", "09:00", "17:00"),))
    target_weekly = PANSchedule(name="weekly", source_path="/schedule", recurring=PANScheduleRecurring(
        weekly={"monday": ["09:00-17:00"]}, explicit_fields={"weekly"}), explicit_fields={"recurring"})
    assert _schedule(weekly, target_weekly)[0]
    one_time = PlannedSchedule(schedule_type="one-time", non_recurring=(("2026/09/30@08:00", "2026/09/30@17:00"),))
    target_one_time = PANSchedule(name="one-time", source_path="/schedule",
        non_recurring=["2026/09/30@08:00-2026/09/30@17:00"], explicit_fields={"non_recurring"})
    assert _schedule(one_time, target_one_time)[0]


def test_schedule_reuse_rejects_additional_or_unknown_semantics():
    weekly = PlannedSchedule(schedule_type="recurring", weekly=(("monday", "09:00", "17:00"),))
    target = PANSchedule(source_path="/schedule", recurring=PANScheduleRecurring(
        daily=["09:00-17:00"], weekly={"monday": ["09:00-17:00"]}, explicit_fields={"daily", "weekly"}),
        explicit_fields={"recurring"})
    assert _schedule(weekly, target)[1]
    one_time = PlannedSchedule(schedule_type="one-time", non_recurring=(("start", "end"),))
    target_one_time = PANSchedule(source_path="/schedule", non_recurring=["start-end"],
        recurring=PANScheduleRecurring(daily=["08:00-09:00"], explicit_fields={"daily"}),
        explicit_fields={"non_recurring", "recurring"})
    assert _schedule(one_time, target_one_time)[1]


def test_service_reuse_rejects_overrides_and_unknown_protocol_semantics():
    source = PlannedService(protocol="tcp", destination_port="443")
    override = PANService(source_path="/service", tcp=PANServiceProtocol(port="443", source_port="",
        override=PANServiceOverride(timeout="3600"), explicit_fields={"port", "source_port", "override"}),
        explicit_fields={"tcp"})
    assert _service(source, override)[1]
    unknown = PANService(source_path="/service", tcp=PANServiceProtocol(port="443", source_port="",
        raw_extra={"future": "value"}, explicit_fields={"port", "source_port"}), explicit_fields={"tcp"})
    assert _service(source, unknown)[1]


def test_exact_object_reuse_skips_creation_command_and_keeps_plan_unchanged():
    plan = PANMigrationPlan(addresses=(PlannedAddress(source_vdom="root", source_kind="address",
        source_object_type="address", source_name="lan-net", target_vsys="vsys1", target_name="lan-net",
        status=PANMigrationStatus.SUPPORTED, address_type="ip-netmask", value="192.0.2.0/24"),))
    target_address = PANAddress(name="lan-net", source_path="/config/devices/entry/vsys/entry/address/entry",
        scope=PANScope(kind="vsys", name="vsys1", vsys="vsys1", device_name="dev"),
        ip_netmask="192.0.2.0/24", explicit_fields={"ip_netmask"})
    reuse = classify_target_object_reuse(plan, _target(target_address), "dev")
    decisions = PANMigrationDecisionSet()
    dispositions, _ = assess_target_plan(plan, reuse, (), decisions, build_plan_dependency_index(plan, decisions))
    rendered = PANSetRenderer().render(plan, dispositions=dispositions)
    assert plan.addresses[0].status is PANMigrationStatus.SUPPORTED
    assert rendered.commands == ()
    assert rendered.report["items"][0]["render_disposition"] == "REUSE"


def test_reused_address_remains_available_to_a_rendered_policy():
    address = PlannedAddress(source_vdom="root", source_object_type="address", source_name="lan-net",
        target_vsys="vsys1", target_name="lan-net", status=PANMigrationStatus.SUPPORTED,
        address_type="ip-netmask", value="192.0.2.0/24")
    service = PlannedService(source_vdom="root", source_object_type="service", source_name="https",
        target_vsys="vsys1", target_name="https", status=PANMigrationStatus.SUPPORTED,
        protocol="tcp", destination_port="443")
    zones = tuple(PlannedZone(source_vdom="root", source_object_type="zone", source_name=name,
        target_vsys="vsys1", target_name=name, status=PANMigrationStatus.SUPPORTED,
        interfaces=(f"ethernet1/{index}",)) for index, name in enumerate(("trust", "untrust"), 1))
    rule = PlannedSecurityRule(applications=("any",), source_vdom="root", source_object_type="security_rule", source_name="allow-web",
        target_vsys="vsys1", target_name="allow-web", status=PANMigrationStatus.SUPPORTED,
        from_zones=("trust",), to_zones=("untrust",), sources=("lan-net",), destinations=("any",),
        services=("https",), action="allow")
    plan = PANMigrationPlan(addresses=(address,), services=(service,), zones=zones, security_rules=(rule,))
    target_address = PANAddress(name="lan-net", source_path="/config/devices/entry/vsys/entry/address/entry",
        scope=PANScope(kind="vsys", name="vsys1", vsys="vsys1", device_name="dev"),
        ip_netmask="192.0.2.0/24", explicit_fields={"ip_netmask"})
    reuse = classify_target_object_reuse(plan, _target(target_address), "dev")
    decisions = PANMigrationDecisionSet()
    dispositions, _ = assess_target_plan(plan, reuse, (), decisions, build_plan_dependency_index(plan, decisions))
    rendered = PANSetRenderer().render(plan, dispositions=dispositions)
    assert not any("address lan-net" in command for command in rendered.commands)
    assert any("allow-web" in command for command in rendered.commands), rendered.commands
    assert any("lan-net" in command and "source" in command for command in rendered.commands), rendered.commands


def test_circular_group_dependencies_cannot_be_satisfied_by_reuse():
    groups = tuple(PlannedAddressGroup(source_vdom="root", source_kind="address_group",
        source_object_type="address_group", source_name=name, target_name=name, target_vsys="vsys1",
        status=PANMigrationStatus.SUPPORTED, members=members)
        for name, members in (("a", ("b",)), ("b", ("a",)), ("dependent", ("a",))))
    plan = PANMigrationPlan(address_groups=groups)
    decisions = PANMigrationDecisionSet()
    classifications = [{"family": "address_group", "source_vdom": "root", "source_kind": "address_group",
                        "source_name": "a", "target_vsys": "vsys1", "status": "EXACT_MATCH"}]
    dispositions, _ = assess_target_plan(plan, classifications, (), decisions, build_plan_dependency_index(plan, decisions))
    rendered = PANSetRenderer().render(plan, dispositions=dispositions)
    assert rendered.commands == ()
    assert all(row["render_disposition"] == "BLOCK" for row in rendered.report["items"])


def test_dependency_index_scopes_same_names_by_object_family():
    address = PlannedAddress(source_vdom="root", source_kind="address", source_object_type="address",
        source_name="web", target_vsys="vsys1", target_name="web", status=PANMigrationStatus.SUPPORTED,
        address_type="ip-netmask", value="192.0.2.1/32")
    group = PlannedAddressGroup(source_vdom="root", source_kind="address_group", source_object_type="address_group",
        source_name="group", target_vsys="vsys1", target_name="group", status=PANMigrationStatus.SUPPORTED,
        members=("web",))
    service = PlannedService(source_vdom="root", source_kind="service", source_object_type="service",
        source_name="web", target_vsys="vsys1", target_name="web", status=PANMigrationStatus.SUPPORTED,
        protocol="tcp", destination_port="443")
    rule = PlannedSecurityRule(applications=("any",), source_vdom="root", source_kind="policy", source_object_type="security_rule",
        source_name="allow-web", target_vsys="vsys1", target_name="allow-web", status=PANMigrationStatus.SUPPORTED,
        sources=("web",), services=("web",), action="allow")
    plan = PANMigrationPlan(addresses=(address,), address_groups=(group,), services=(service,), security_rules=(rule,))
    index = build_plan_dependency_index(plan, PANMigrationDecisionSet())
    assert item_key(group) in index.dependents_by_item[item_key(address)]
    assert item_key(rule) in index.dependents_by_item[item_key(address)]
    assert item_key(rule) in index.dependents_by_item[item_key(service)]
    assert item_key(service) not in index.dependents_by_item[item_key(address)]


def test_expanded_dependency_blocks_address_consumers_but_not_same_name_service():
    address = PlannedAddress(source_vdom="root", source_kind="address", source_object_type="address",
        source_name="web", target_vsys="vsys1", target_name="web", status=PANMigrationStatus.SUPPORTED,
        address_type="ip-netmask", value="192.0.2.1/32")
    group = PlannedAddressGroup(source_vdom="root", source_kind="address_group", source_object_type="address_group",
        source_name="group", target_vsys="vsys1", target_name="group", status=PANMigrationStatus.SUPPORTED,
        members=("web",))
    service = PlannedService(source_vdom="root", source_kind="service", source_object_type="service",
        source_name="web", target_vsys="vsys1", target_name="web", status=PANMigrationStatus.SUPPORTED,
        protocol="tcp", destination_port="443")
    rule = PlannedSecurityRule(applications=("any",), source_vdom="root", source_kind="policy", source_object_type="security_rule",
        source_name="allow-web", target_vsys="vsys1", target_name="allow-web", status=PANMigrationStatus.SUPPORTED,
        sources=("web",), services=("web",), action="allow")
    plan = PANMigrationPlan(addresses=(address,), address_groups=(group,), services=(service,), security_rules=(rule,))
    reuse = ({"status": "NAME_CONFLICT", "family": "address", "source_vdom": "root",
              "source_kind": "address", "target_vsys": "vsys1",
              "source_name": "web", "target_name": "web"},)
    dependencies = build_plan_dependency_index(plan, PANMigrationDecisionSet())
    dispositions, _ = assess_target_plan(plan, reuse, (), PANMigrationDecisionSet(), dependencies)
    assert dispositions[item_key(address)] is PANRenderDisposition.BLOCK
    assert dispositions[item_key(group)] is PANRenderDisposition.BLOCK
    assert dispositions[item_key(rule)] is PANRenderDisposition.BLOCK
    assert dispositions[item_key(service)] is PANRenderDisposition.CREATE


def test_target_conflicts_do_not_cross_associate_same_name_different_source_kinds():
    first = PlannedAddress(source_vdom="root", source_kind="address", source_object_type="address",
        source_name="web", target_vsys="vsys1", target_name="web", status=PANMigrationStatus.SUPPORTED,
        address_type="ip-netmask", value="192.0.2.1/32")
    second = PlannedAddress(source_vdom="root", source_kind="vip", source_object_type="address",
        source_name="web", target_vsys="vsys1", target_name="web", status=PANMigrationStatus.SUPPORTED,
        address_type="ip-netmask", value="192.0.2.2/32")
    plan = PANMigrationPlan(addresses=(first, second))
    decisions = PANMigrationDecisionSet()
    dependencies = build_plan_dependency_index(plan, decisions)
    conflict = ({"status": "NAME_CONFLICT", "family": "address", "source_vdom": "root",
                 "source_kind": "address", "target_vsys": "vsys1", "source_name": "web", "target_name": "web"},)
    dispositions, _ = assess_target_plan(plan, conflict, (), decisions, dependencies)
    finding = validate_target_plan(plan, conflict, (), decisions, dependencies)[0]
    assert dispositions[item_key(first)] is PANRenderDisposition.BLOCK
    assert dispositions[item_key(second)] is PANRenderDisposition.CREATE
    assert finding.affected_item_keys == (item_key(first),)


def _interface_target(ip="192.0.2.1/24"):
    scope = PANScope(kind="device", name="dev", device_name="dev")
    interface = PANInterface(
        name="ethernet1/1",
        source_path="/network/interface/ethernet/entry",
        scope=scope,
        interface_family="ethernet",
        mode="layer3",
        ipv4_addresses=[ip],
        explicit_fields={"mode", "ipv4_addresses"},
    )
    topology = PANInterfaceTopologyEntry(
        "ethernet1/1",
        pan_scope_identity(scope),
        imported_vsys=("vsys1",),
        virtual_routers=("vr-main",),
    )
    return SimpleNamespace(
        config=SimpleNamespace(
            interfaces=[interface], interface_units=[], virtual_routers=[],
            addresses=[], address_groups=[], services=[], service_groups=[],
            schedules=[], zones=[], nat_rules=[], security_rules=[], scopes=[scope],
        ),
        derived=SimpleNamespace(
            interface_topology=[topology],
            reference_index=None,
            scope_hierarchy=None,
        ),
    )


def test_exact_interface_reuse_skips_creation_and_conflicts_block_dependents():
    interface = PlannedInterface(
        source_vdom="root", source_kind="interface", source_object_type="interface",
        source_name="port1", target_vsys="vsys1", target_name="ethernet1/1",
        status=PANMigrationStatus.SUPPORTED, interface_family="ethernet",
        ipv4_addresses=("192.0.2.1/24",), virtual_router="vr-main",
    )
    zone = PlannedZone(
        source_vdom="root", source_kind="zone", source_object_type="zone",
        source_name="trust", target_vsys="vsys1", target_name="trust",
        status=PANMigrationStatus.SUPPORTED, interfaces=("ethernet1/1",),
    )
    rule = PlannedSecurityRule(applications=("any",),
        source_vdom="root", source_kind="policy", source_object_type="security_rule",
        source_name="allow", target_vsys="vsys1", target_name="allow",
        status=PANMigrationStatus.SUPPORTED, from_zones=("trust",), to_zones=("trust",),
        sources=("any",), destinations=("any",), services=("any",), action="allow",
    )
    plan = PANMigrationPlan(interfaces=(interface,), zones=(zone,), security_rules=(rule,))
    decisions = PANMigrationDecisionSet()

    reuse = classify_target_object_reuse(plan, _interface_target(), "dev")
    exact = next(item for item in reuse if item["family"] == "interface")
    assert exact["status"] == "EXACT_MATCH"
    index = build_plan_dependency_index(plan, decisions)
    dispositions, _ = assess_target_plan(plan, reuse, (), decisions, index)
    assert dispositions[item_key(interface)] is PANRenderDisposition.REUSE
    assert dispositions[item_key(zone)] is PANRenderDisposition.CREATE
    assert dispositions[item_key(rule)] is PANRenderDisposition.CREATE
    rendered = PANSetRenderer().render(plan, dispositions=dispositions)
    assert not any("network interface ethernet ethernet1/1 layer3" in command
                   for command in rendered.commands)
    assert any("set vsys vsys1 zone trust" in command for command in rendered.commands)

    conflict = classify_target_object_reuse(plan, _interface_target("198.51.100.1/24"), "dev")
    conflict_dispositions, _ = assess_target_plan(plan, conflict, (), decisions, index)
    assert conflict_dispositions[item_key(interface)] is PANRenderDisposition.BLOCK
    assert conflict_dispositions[item_key(zone)] is PANRenderDisposition.BLOCK
    assert conflict_dispositions[item_key(rule)] is PANRenderDisposition.BLOCK


def test_populated_target_rulebase_blocks_unverified_placement():
    scope = PANScope(kind="vsys", name="vsys1", vsys="vsys1", device_name="dev")
    planned = PlannedSecurityRule(applications=("any",), source_vdom="root", source_kind="policy", source_object_type="security_rule",
        source_name="new-policy", target_name="new-policy", target_vsys="vsys1", status=PANMigrationStatus.SUPPORTED,
        from_zones=("trust",), to_zones=("untrust",), sources=("any",), destinations=("any",), services=("any",), action="allow")
    plan = PANMigrationPlan(security_rules=(planned,))
    empty = SimpleNamespace(config=SimpleNamespace(security_rules=[], nat_rules=[]))
    assert classify_target_object_reuse(plan, empty, "dev") == ()

    unrelated = PANSecurityRule(name="unrelated", source_path="/rule", scope=PANScope(
        kind="vsys", name="vsys2", vsys="vsys2", device_name="dev"))
    target = SimpleNamespace(config=SimpleNamespace(security_rules=[unrelated], nat_rules=[]))
    assert classify_target_object_reuse(plan, target, "dev") == ()

    existing = PANSecurityRule(name="existing", source_path="/rule", scope=scope, source_order=1)
    target.config.security_rules = [existing]
    classification = classify_target_object_reuse(plan, target, "dev")
    assert len(classification) == 1
    assert classification[0]["status"] == "ORDER_UNVERIFIED"

    decisions = PANMigrationDecisionSet()
    dependencies = build_plan_dependency_index(plan, decisions)
    findings = validate_target_plan(plan, classification, (), decisions, dependencies)
    assert findings[0].code == "TARGET_RULE_PLACEMENT_UNVERIFIED"
    dispositions, blockers = assess_target_plan(plan, classification, (), decisions, dependencies)
    assert dispositions[item_key(planned)] is PANRenderDisposition.BLOCK
    assert "TARGET_RULE_PLACEMENT_UNVERIFIED" in blockers[item_key(planned)]


def test_target_rule_name_conflict_is_preserved_with_populated_rulebase():
    scope = PANScope(kind="vsys", name="vsys1", vsys="vsys1", device_name="dev")
    planned = PlannedSecurityRule(applications=("any",), source_vdom="root", source_kind="policy", source_object_type="security_rule",
        source_name="same", target_name="same", target_vsys="vsys1", status=PANMigrationStatus.SUPPORTED)
    existing = PANSecurityRule(name="same", source_path="/rule", scope=scope, source_order=1)
    target = SimpleNamespace(config=SimpleNamespace(security_rules=[existing], nat_rules=[]))
    statuses = [item["status"] for item in classify_target_object_reuse(PANMigrationPlan(security_rules=(planned,)), target, "dev")]
    assert "ORDER_UNVERIFIED" not in statuses
    assert statuses == ["AMBIGUOUS"]


def test_populated_target_nat_rulebase_blocks_unverified_placement():
    scope = PANScope(kind="vsys", name="vsys1", vsys="vsys1", device_name="dev")
    planned = PlannedNATRule(source_vdom="root", source_kind="source_nat", source_object_type="nat_rule",
        source_name="new-nat", target_name="new-nat", target_vsys="vsys1", status=PANMigrationStatus.SUPPORTED)
    existing = PANNATRule(name="existing-nat", source_path="/nat", scope=scope, source_order=1)
    target = SimpleNamespace(config=SimpleNamespace(nat_rules=[existing], security_rules=[]))
    result = classify_target_object_reuse(PANMigrationPlan(nat_rules=(planned,)), target, "dev")
    assert result[0]["family"] == "nat_rule"
    assert result[0]["status"] == "ORDER_UNVERIFIED"

# --- test_target_suggestions.py ---
def test_reservations_release_and_competing_strong_suggestions_stay_pending():
    scope = PANScope(kind="device", name="dev", device_name="dev")
    record = SimpleNamespace(name="ethernet1/1", interface_family="ethernet", ipv4_addresses=["192.0.2.1/24"],
                             scope=scope, tag=None, parent=None, comment=None)
    target = SimpleNamespace(config=SimpleNamespace(interfaces=[record], interface_units=[], zones=[]),
        derived=SimpleNamespace(interface_topology=[PANInterfaceTopologyEntry(record.name, pan_scope_identity(scope))]))
    source = FGConfig(interfaces=[FGInterface(name=name, type="physical", ip="192.0.2.1/24") for name in ("port1", "port2")])
    pending = PANMigrationDecisionSet(tuple(PANMigrationDecision("root", "interface", name, "target_interface") for name in ("port1", "port2")))
    reserved = PANMigrationDecisionSet((pending.decisions[0].confirm("ethernet1/1"), pending.decisions[1]))
    candidates = discover_target_candidates(source, reserved, target, "dev")
    assert candidates[pending.decisions[0].key][0]["available"]
    unavailable = candidates[pending.decisions[1].key][0]
    assert not unavailable["available"] and unavailable["assigned_to"] == [{"source_vdom": "root", "source_name": "port1"}]
    updated, _ = suggest_from_target(source, reserved, target, "dev")
    assert updated.decisions[1].suggested_value is None
    candidates = discover_target_candidates(source, pending, target, "dev")
    assert all(options[0]["available"] and options[0]["contested"] for options in candidates.values())
    updated, warnings = suggest_from_target(source, pending, target, "dev")
    assert len(warnings) == 2
    assert all(item.suggested_value is None for item in updated.decisions)
    assert all(item.value is None and item.review_state == PANDecisionReviewState.PENDING for item in updated.decisions)
    from fwmigrate.conversion.fortigate_to_palo_alto.auto_decisions import classify_auto_decisions
    auto = classify_auto_decisions(source, None, pending, target, "dev")
    assert all(auto[item.key]["status"] == "CONFLICT" for item in pending.decisions)


def test_explicit_physical_interfaces_do_not_match_target_units():
    source = SimpleNamespace(type="physical", vlanid=None, ip=None, name="port1")
    target = SimpleNamespace(interface_family="ethernet", tag="201", parent="ethernet1/1", ipv4_addresses=[])
    assert not _compatible(source, target)
    assert candidate_evidence(source, target)[2]


def test_redundant_source_interface_is_not_assumed_to_be_aggregate():
    source = SimpleNamespace(type="redundant", vlanid=None)
    target = SimpleNamespace(interface_family="aggregate-ethernet", tag=None)
    assert _compatible(source, target) is False


def test_tunnel_source_only_receives_tunnel_candidates():
    assert _compatible(SimpleNamespace(type="tunnel", vlanid=None),
                       SimpleNamespace(interface_family="ethernet")) is False
    assert _compatible(SimpleNamespace(type="tunnel", vlanid=None),
                       SimpleNamespace(interface_family="tunnel")) is True


def test_tunnel_candidates_exclude_physical_and_remain_competing_without_topology_evidence():
    scope = PANScope(kind="device", name="dev", device_name="dev")
    identity = pan_scope_identity(scope)
    source = FGConfig(interfaces=[FGInterface(name="AWS-MYRegion", type="tunnel")])
    physical = SimpleNamespace(name="ethernet1/1", interface_family="ethernet", scope=scope, tag=None,
                               ipv4_addresses=[], parent=None, comment=None)
    tunnels = [SimpleNamespace(name=name, interface_family="tunnel", scope=scope, tag=None,
                               ipv4_addresses=[], parent=None, comment=None)
               for name in ("tunnel.11", "tunnel.12")]
    target = SimpleNamespace(config=SimpleNamespace(interfaces=[physical, *tunnels], interface_units=[], zones=[]),
        derived=SimpleNamespace(interface_topology=[PANInterfaceTopologyEntry(item.name, identity)
            for item in (physical, *tunnels)]))
    decision = PANMigrationDecision("root", "interface", "AWS-MYRegion", "target_interface")
    candidates = discover_target_candidates(source, PANMigrationDecisionSet((decision,)), target, "dev")[decision.key]
    assert {item["value"] for item in candidates} == {"tunnel.11", "tunnel.12"}


def test_same_subnet_vlan_and_mapped_parent_is_a_unique_candidate():
    scope = PANScope(kind="device", name="dev", device_name="dev")
    identity = pan_scope_identity(scope)
    source = FGConfig(interfaces=[
        FGInterface(name="port1", ip="192.0.2.1/24"),
        FGInterface(name="vlan100", type="vlan", interface="port1", vlanid=100, ip="10.0.0.1/24"),
    ])
    target_parent = SimpleNamespace(name="ethernet1/1", interface_family="ethernet", ipv4_addresses=["192.0.2.1/24"], scope=scope, tag=None, parent=None)
    target_child = SimpleNamespace(name="ethernet1/1.100", interface_family="vlan", ipv4_addresses=["10.0.0.2/24"], scope=scope, tag="100", parent="ethernet1/1")
    target = SimpleNamespace(
        config=SimpleNamespace(interfaces=[target_parent], interface_units=[target_child], zones=[]),
        derived=SimpleNamespace(interface_topology=[
            PANInterfaceTopologyEntry("ethernet1/1", identity),
            PANInterfaceTopologyEntry("ethernet1/1.100", identity, parent="ethernet1/1"),
        ]),
    )
    decisions = PANMigrationDecisionSet((
        PANMigrationDecision("root", "interface", "port1", "target_interface", value="ethernet1/1",
                             review_state=PANDecisionReviewState.CONFIRMED),
        PANMigrationDecision("root", "interface", "vlan100", "target_interface"),
    ))
    updated, _ = suggest_from_target(source, decisions, target, "dev")
    values = {item.source_name: item.value or item.suggested_value for item in updated.decisions}
    assert values["port1"] == "ethernet1/1"
    assert values["vlan100"] == "ethernet1/1.100"


def test_unconfirmed_parent_does_not_unlock_vlan_child_suggestion():
    scope = PANScope(kind="device", name="dev", device_name="dev")
    identity = pan_scope_identity(scope)
    source = FGConfig(interfaces=[
        FGInterface(name="port1", ip="192.0.2.1/24"),
        FGInterface(name="vlan100", type="vlan", interface="port1", vlanid=100, ip="10.0.0.1/24"),
    ])
    parent = SimpleNamespace(name="ethernet1/1", interface_family="ethernet", ipv4_addresses=["192.0.2.1/24"], scope=scope, tag=None, parent=None)
    child = SimpleNamespace(name="ethernet1/1.100", interface_family="vlan", ipv4_addresses=["10.0.0.2/24"], scope=scope, tag="100", parent="ethernet1/1")
    target = SimpleNamespace(config=SimpleNamespace(interfaces=[parent], interface_units=[child], zones=[]),
        derived=SimpleNamespace(interface_topology=[PANInterfaceTopologyEntry("ethernet1/1", identity),
                                                     PANInterfaceTopologyEntry("ethernet1/1.100", identity, parent="ethernet1/1")]))
    decisions = PANMigrationDecisionSet(tuple(PANMigrationDecision("root", "interface", name, "target_interface") for name in ("port1", "vlan100")))
    updated, _ = suggest_from_target(source, decisions, target, "dev")
    assert {item.source_name: item.suggested_value for item in updated.decisions}["vlan100"] is None


def test_same_vlan_under_multiple_unmapped_parents_stays_required():
    scope = PANScope(kind="device", name="dev", device_name="dev")
    identity = pan_scope_identity(scope)
    source = FGConfig(interfaces=[
        FGInterface(name="port1"),
        FGInterface(name="vlan100", type="vlan", interface="port1", vlanid=100),
    ])
    children = [SimpleNamespace(name=f"ae{index}.100", interface_family="vlan", ipv4_addresses=[],
                                scope=scope, tag="100", parent=f"ae{index}") for index in (1, 2)]
    target = SimpleNamespace(config=SimpleNamespace(interfaces=[], interface_units=children, zones=[]),
        derived=SimpleNamespace(interface_topology=[PANInterfaceTopologyEntry(
            item.name, identity, parent=item.parent) for item in children]))
    decisions = PANMigrationDecisionSet(tuple(PANMigrationDecision("root", "interface", name, "target_interface")
                                               for name in ("port1", "vlan100")))
    updated, _ = suggest_from_target(source, decisions, target, "dev")
    assert {item.source_name: item.suggested_value for item in updated.decisions}["vlan100"] is None


def test_candidate_discovery_returns_strong_and_possible_evidence_without_suggesting_possible():
    scope = PANScope(kind="device", name="dev", device_name="dev")
    identity = pan_scope_identity(scope)
    source = FGConfig(interfaces=[FGInterface(name="finance", alias="Finance LAN", role="lan")])
    strong = SimpleNamespace(name="ethernet1/1", interface_family="ethernet", ipv4_addresses=["10.0.0.1/24"], scope=scope, tag=None, parent=None, comment=None)
    possible = SimpleNamespace(name="ethernet1/2", interface_family="ethernet", ipv4_addresses=[], scope=scope, tag=None, parent=None, comment="Finance LAN")
    target = SimpleNamespace(config=SimpleNamespace(interfaces=[strong, possible], interface_units=[], zones=[]),
        derived=SimpleNamespace(interface_topology=[PANInterfaceTopologyEntry("ethernet1/1", identity), PANInterfaceTopologyEntry("ethernet1/2", identity)]))
    decision = PANMigrationDecision("root", "interface", "finance", "target_interface")
    candidates = discover_target_candidates(source, PANMigrationDecisionSet((decision,)), target, "dev")[decision.key]
    assert [item["class"] for item in candidates] == ["POSSIBLE", "POSSIBLE"]
    alias_candidate = next(item for item in candidates if item["value"] == "ethernet1/2")
    assert "source alias/comment matches target name/comment" in alias_candidate["supporting_evidence"]
    assert candidate_evidence(FGInterface(name="vlan100", type="vlan", vlanid=100),
                             SimpleNamespace(interface_family="vlan", tag="200"))[2] == ("VLAN mismatch",)


def test_confirmed_interface_unlocks_pending_zone_suggestion():
    scope = PANScope(kind="device", name="dev", device_name="dev")
    identity = pan_scope_identity(scope)
    source = SimpleNamespace(interfaces=[FGInterface(name="finance")], zones=[])
    target_interface = SimpleNamespace(name="ethernet1/7", interface_family="ethernet", ipv4_addresses=[],
                                        scope=scope, tag=None, parent=None)
    target = SimpleNamespace(config=SimpleNamespace(interfaces=[target_interface], interface_units=[], zones=[]),
        derived=SimpleNamespace(interface_topology=[PANInterfaceTopologyEntry(
            "ethernet1/7", identity, imported_vsys=("vsys1",), zones=("FINANCE",), virtual_routers=("vr-main",))]))
    pending = PANMigrationDecisionSet((
        PANMigrationDecision("root", "interface", "finance", "target_interface"),
        PANMigrationDecision("root", "interface", "finance", "target_zone"),
    ))
    first, _ = suggest_from_target(source, pending, target, "dev")
    assert all(item.suggested_value is None for item in first.decisions)
    confirmed = PANMigrationDecisionSet(tuple(
        item if item.target_field == "target_zone" else PANMigrationDecision(
            item.source_vdom, item.source_kind, item.source_name, item.target_field,
            value="ethernet1/7", review_state=PANDecisionReviewState.CONFIRMED)
        for item in first.decisions
    ))
    refreshed, _ = suggest_from_target(source, confirmed, target, "dev")
    zone = next(item for item in refreshed.decisions if item.target_field == "target_zone")
    assert zone.suggested_value == "FINANCE"
    assert zone.review_state == PANDecisionReviewState.PENDING


def test_equally_valid_target_candidates_stay_pending_with_warning():
    scope = PANScope(kind="device", name="dev", device_name="dev")
    identity = pan_scope_identity(scope)
    source = FGConfig(interfaces=[FGInterface(name="lan", ip="10.0.0.1/24")])
    target_items = [SimpleNamespace(name=name, interface_family="ethernet", ipv4_addresses=["10.0.0.1/24"], scope=scope, tag=None, parent=None) for name in ("ethernet1/1", "ethernet1/2")]
    target = SimpleNamespace(
        config=SimpleNamespace(interfaces=target_items, interface_units=[], zones=[]),
        derived=SimpleNamespace(interface_topology=[PANInterfaceTopologyEntry(item.name, identity) for item in target_items]),
    )
    decision = PANMigrationDecision("root", "interface", "lan", "target_interface")
    updated, warnings = suggest_from_target(source, PANMigrationDecisionSet((decision,)), target, "dev")
    assert updated.decisions[0].suggested_value is None
    assert decision.key in warnings


def test_confirmed_vsys_limits_interface_candidates_to_imported_vsys():
    scope = PANScope(kind="device", name="dev", device_name="dev")
    identity = pan_scope_identity(scope)
    source = FGConfig(interfaces=[FGInterface(name="lan", ip="10.0.0.1/24")])
    target_items = [
        SimpleNamespace(name=name, interface_family="ethernet", ipv4_addresses=["10.0.0.1/24"],
                        scope=scope, tag=None, parent=None)
        for name in ("ethernet1/1", "ethernet1/2")
    ]
    target = SimpleNamespace(
        config=SimpleNamespace(interfaces=target_items, interface_units=[], zones=[]),
        derived=SimpleNamespace(interface_topology=[
            PANInterfaceTopologyEntry("ethernet1/1", identity, imported_vsys=("vsys1",)),
            PANInterfaceTopologyEntry("ethernet1/2", identity, imported_vsys=("vsys2",)),
        ]),
    )
    vsys = PANMigrationDecision("root", "vdom", "root", "vsys", value="vsys2",
                                review_state=PANDecisionReviewState.CONFIRMED)
    interface = PANMigrationDecision("root", "interface", "lan", "target_interface")
    updated, _ = suggest_from_target(source, PANMigrationDecisionSet((vsys, interface)), target, "dev")
    assert updated.decisions[1].suggested_value == "ethernet1/2"


def test_target_device_metadata_keeps_multiple_devices_separate():
    first = PANScope(kind="device", name="first", device_name="branch-01", vsys="vsys1")
    second = PANScope(kind="device", name="second", device_name="branch-02", vsys="vsys1")
    target = SimpleNamespace(config=SimpleNamespace(
        interfaces=[
            SimpleNamespace(name="ethernet1/1", scope=first),
            SimpleNamespace(name="ethernet1/1", scope=second),
        ],
        interface_units=[],
        zones=[],
    ))
    assert target_devices(target) == ["branch-01", "branch-02"]
    metadata = target_device_metadata(target)
    assert [(item["id"], item["interfaces"], item["vsys"]) for item in metadata] == [
        ("branch-01", 1, 1), ("branch-02", 1, 1),
    ]


def test_target_devices_returns_empty_without_device_scoped_interfaces():
    target = SimpleNamespace(config=SimpleNamespace(interfaces=[], interface_units=[], zones=[]))
    assert target_devices(target) == []


def test_target_device_can_be_selected_from_explicit_scope_and_virtual_router():
    scope = PANScope(kind="vsys", name="vsys2", device_name="branch-02", vsys="vsys2")
    target = SimpleNamespace(config=SimpleNamespace(interfaces=[], interface_units=[], zones=[], scopes=[scope],
        virtual_routers=[SimpleNamespace(name="vr2", scope=scope)]))
    assert target_devices(target) == ["branch-02"]


def test_scope_and_zone_candidates_keep_target_scope_and_confirmed_vsys():
    from fwmigrate.conversion.fortigate_to_palo_alto.target.target_suggestions import discover_target_candidates

    scopes = [PANScope(kind="vsys", name=f"{name}-scope", device_name="dev", vsys=name)
              for name in ("vsys1", "vsys2")]
    source = FGConfig()
    decisions = PANMigrationDecisionSet((
        PANMigrationDecision("root", "vdom", "root", "vsys", value="vsys2",
                             review_state=PANDecisionReviewState.CONFIRMED),
        PANMigrationDecision("root", "vdom", "root", "virtual_router"),
        PANMigrationDecision("root", "zone", "inside", "target_zone"),
    ))
    routers = [SimpleNamespace(name=f"vr-{index + 1}", scope=scope) for index, scope in enumerate(scopes)]
    zones = [SimpleNamespace(name="inside", scope=scope) for scope in scopes]
    target = SimpleNamespace(config=SimpleNamespace(scopes=scopes, interfaces=[], interface_units=[],
        zones=zones, virtual_routers=routers), derived=SimpleNamespace(interface_topology=[]))
    candidates = discover_target_candidates(source, decisions, target, "dev")
    router_key = PANMigrationDecision("root", "vdom", "root", "virtual_router").key
    zone_key = PANMigrationDecision("root", "zone", "inside", "target_zone").key
    assert [item["value"] for item in candidates[router_key]] == ["vr-2"]
    assert [item["value"] for item in candidates[zone_key]] == ["inside"]
    assert candidates[zone_key][0]["target_scope"] == pan_scope_identity(scopes[1])


@pytest.mark.parametrize("count", [1, 2])
def test_greenfield_explicit_architecture_prefills_only_unique_choices(count):
    scopes = [PANScope(kind="vsys", name=f"vsys{index}", device_name="dev", vsys=f"vsys{index}")
              for index in range(1, count + 1)]
    source = FGConfig(interfaces=[FGInterface(name="lan", type="physical")])
    decisions = PANMigrationDecisionSet((
        PANMigrationDecision("root", "vdom", "root", "vsys"),
        PANMigrationDecision("root", "vdom", "root", "virtual_router"),
        PANMigrationDecision("root", "interface", "lan", "target_interface"),
    ))
    target = SimpleNamespace(config=SimpleNamespace(scopes=scopes, interfaces=[], interface_units=[], zones=[],
        virtual_routers=[SimpleNamespace(name=f"vr{index}", scope=scope) for index, scope in enumerate(scopes, 1)]),
        derived=SimpleNamespace(interface_topology=[]))
    updated, _ = suggest_from_target(source, decisions, target, "dev")
    by_field = {item.target_field: item for item in updated.decisions}
    assert by_field["vsys"].suggested_value == ("vsys1" if count == 1 else None)
    assert by_field["virtual_router"].suggested_value == ("vr1" if count == 1 else None)
    assert by_field["target_interface"].suggested_value is None
    assert all(item.value is None and item.review_state == PANDecisionReviewState.PENDING for item in updated.decisions)
    assert updated.to_options().vdoms == {}
    assert len(discover_target_candidates(source, updated, target, "dev")[decisions.decisions[0].key]) == count


@pytest.mark.parametrize("router_count", [1, 2])
def test_greenfield_router_prefill_respects_confirmed_vsys_and_ambiguity(router_count):
    scopes = [PANScope(kind="vsys", name=name, device_name="dev", vsys=name) for name in ("vsys1", "vsys2")]
    decisions = PANMigrationDecisionSet((
        PANMigrationDecision("root", "vdom", "root", "vsys").confirm("vsys2"),
        PANMigrationDecision("root", "vdom", "root", "virtual_router"),
    ))
    routers = [SimpleNamespace(name="other", scope=scopes[0]),
        *(SimpleNamespace(name=f"vr{index}", scope=scopes[1]) for index in range(1, router_count + 1))]
    target = SimpleNamespace(config=SimpleNamespace(scopes=scopes, interfaces=[], interface_units=[], zones=[],
        virtual_routers=routers), derived=SimpleNamespace(interface_topology=[]))
    updated, _ = suggest_from_target(FGConfig(), decisions, target, "dev")
    assert updated.decisions[0] == decisions.decisions[0]
    assert updated.decisions[1].suggested_value == ("vr1" if router_count == 1 else None)
    assert updated.decisions[1].review_state == PANDecisionReviewState.PENDING


def test_same_name_target_zone_prefill_is_limited_to_confirmed_vsys():
    scopes = [PANScope(kind="vsys", name=name, device_name="dev", vsys=name) for name in ("vsys1", "vsys2")]
    source = FGConfig(zones=[FGZone(name="inside", vdom="root", members=[])])
    decisions = PANMigrationDecisionSet((
        PANMigrationDecision("root", "vdom", "root", "vsys").confirm("vsys2"),
        PANMigrationDecision("root", "zone", "inside", "target_zone"),
    ))
    target = SimpleNamespace(config=SimpleNamespace(scopes=scopes, interfaces=[], interface_units=[],
        zones=[SimpleNamespace(name="inside", scope=scope) for scope in scopes], virtual_routers=[]),
        derived=SimpleNamespace(interface_topology=[]))
    updated, _ = suggest_from_target(source, decisions, target, "dev")
    assert updated.decisions[1].suggested_value == "inside" and updated.decisions[1].evidence_source == "TARGET"
    target.config.zones = target.config.zones[:1]
    updated, _ = suggest_from_target(source, decisions, target, "dev")
    assert updated.decisions[1].suggested_value is None


def test_one_compatible_interface_without_strong_evidence_does_not_prefill():
    scope = PANScope(kind="device", name="dev", device_name="dev")
    source = FGConfig(interfaces=[FGInterface(name="lan", type="physical")])
    target = SimpleNamespace(config=SimpleNamespace(interfaces=[SimpleNamespace(name="ethernet1/7", scope=scope,
        interface_family="ethernet", tag=None, parent=None, ipv4_addresses=[], comment=None)], interface_units=[], zones=[]),
        derived=SimpleNamespace(interface_topology=[]))
    decision = PANMigrationDecision("root", "interface", "lan", "target_interface")
    decisions = PANMigrationDecisionSet((decision,))
    updated, _ = suggest_from_target(source, decisions, target, "dev")
    assert updated.decisions[0].suggested_value is None
    assert discover_target_candidates(source, decisions, target, "dev")[decision.key][0]["class"] == "POSSIBLE"

# --- test_target_candidate_scopes.py ---
def _scope(kind, name, *, device=None, vsys=None):
    return PANScope(kind=kind, name=name, device_name=device, vsys=vsys)


def _scope_target():
    device_vsys1 = _scope("vsys", "vsys1", device="fw-a", vsys="vsys1")
    device_vsys2 = _scope("vsys", "vsys2", device="fw-a", vsys="vsys2")
    other_device_vsys1 = _scope("vsys", "vsys1", device="fw-b", vsys="vsys1")
    shared = _scope("shared", "shared")
    config = PANOSConfig(
        scopes=[device_vsys1, device_vsys2, other_device_vsys1, shared],
        dhcp_servers=[
            PANDHCPServer(name="scope-test", source_path="vsys1/dhcp", scope=device_vsys1),
            PANDHCPServer(name="1", source_path="vsys1/dhcp-one", scope=device_vsys1),
            PANDHCPServer(name="scope-test", source_path="vsys2/dhcp", scope=device_vsys2),
            PANDHCPServer(name="scope-test", source_path="other-device/dhcp", scope=other_device_vsys1),
            PANDHCPServer(name="shared-server", source_path="shared/dhcp", scope=shared),
            PANDHCPServer(name="unrelated", source_path="vsys1/unrelated", scope=device_vsys1),
        ],
    )
    return type("Target", (), {"config": config, "derived": build_derived_views(config)})()


def test_same_name_candidate_is_limited_to_selected_device_and_confirmed_vsys():
    candidates = build_target_candidates(_scope_target(), "dhcp_servers", "dhcp-server", "scope-test",
                                         "fw-a", "vsys1")
    assert len(candidates) == 1
    assert candidates[0].source_path == "vsys1/dhcp"
    assert candidates[0].scope_identity == "vsys:vsys1:device:fw-a"
    assert candidates[0].match_class is PANTargetCandidateMatchClass.POSSIBLE
    assert candidates[0].supporting_evidence == ("same name and PAN-OS object family",)


def test_shared_target_candidate_is_visible_without_matching_device_identity():
    candidates = build_target_candidates(_scope_target(), "dhcp_servers", "dhcp-server", "shared-server",
                                         "fw-missing", "vsys1")
    assert len(candidates) == 1
    assert candidates[0].scope_identity == "shared:shared"


def test_unconfirmed_vsys_never_surfaces_same_name_from_other_vsys():
    candidates = build_target_candidates(_scope_target(), "dhcp_servers", "dhcp-server", "scope-test",
                                         "fw-a", None)
    assert candidates == ()


def test_candidate_comparison_classes_use_explainable_evidence():
    assert classify_candidate(strong_evidence=("matching gateway",)) is PANTargetCandidateMatchClass.LIKELY_REUSE
    assert classify_candidate(supporting_evidence=("same name",)) is PANTargetCandidateMatchClass.POSSIBLE
    assert classify_candidate(contradictions=("different subnet",)) is PANTargetCandidateMatchClass.CONFLICT
    assert classify_candidate(exact_equivalent=True) is PANTargetCandidateMatchClass.EXACT_EQUIVALENT

# --- test_plan_scope_validation.py ---
@pytest.mark.parametrize('family,item', [
    ('addresses', PlannedAddress(source_object_type='address', address_type='ip-netmask', value='192.0.2.1/32')),
    ('services', PlannedService(source_object_type='service', protocol='tcp', destination_port='443')),
    ('schedules', PlannedSchedule(source_object_type='schedule', schedule_type='recurring',
                                  weekly=(('monday', '09:00', '17:00'),))),
])
def test_vsys_scoped_objects_require_placement_before_counting_as_exported(family, item):
    item = replace(item, source_vdom='branch', source_kind=item.source_object_type,
                   source_name='example', target_name='example', status=PANMigrationStatus.SUPPORTED)
    plan = PANMigrationPlan(**{family: (item,)})
    validation = validate_plan(plan)
    assert any(issue.code == 'missing_target_vsys' for issue in validation.issues)
    assert not validation.renderable_item_keys
    rendered = PANSetRenderer().render(plan)
    assert not rendered.commands
    assert rendered.report['summary']['command_renderable'] == rendered.report['summary']['satisfied'] == 0
    row, = rendered.report['items']
    assert row['render_disposition'] == 'BLOCK'
    assert row['export_category'] == 'PREREQUISITE'
    assert not row['renderable'] and not row['rendered'] and not row['satisfied']
    assert 'missing_target_vsys' in row['render_blockers']

    mapped = PANMigrationPlan(**{family: (replace(item, target_vsys='vsys2'),)})
    rendered = PANSetRenderer().render(mapped)
    assert rendered.commands and all(command.startswith('set vsys vsys2 ') for command in rendered.commands)
    assert rendered.report['summary']['command_renderable'] == rendered.report['summary']['satisfied'] == 1


def test_duplicate_device_interfaces_across_vsys_block_both_and_dependents():
    from dataclasses import replace
    from fwmigrate.conversion.fortigate_to_palo_alto.models import PlannedInterface, PlannedZone
    from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import PANSetRenderer

    interfaces = tuple(PlannedInterface(source_object_type="interface", source_vdom=vdom,
        source_name="port1", target_name="ethernet1/3", target_vsys=vsys,
        status=PANMigrationStatus.SUPPORTED, interface_family="ethernet", virtual_router="default")
        for vdom, vsys in (("root", "vsys1"), ("branch", "vsys2")))
    zones = tuple(PlannedZone(source_object_type="zone", source_vdom=item.source_vdom,
        source_name="trust", target_name="trust", target_vsys=item.target_vsys,
        status=PANMigrationStatus.SUPPORTED, interfaces=(item.target_name,)) for item in interfaces)
    plan = PANMigrationPlan(interfaces=interfaces, zones=zones)
    validation = validate_plan(plan)
    assert len([item for item in validation.issues if item.code == "TARGET_INTERFACE_ALREADY_ASSIGNED"]) == 2
    assert not validation.renderable_item_keys
    assert not PANSetRenderer().render(plan).commands
    child = replace(interfaces[0], source_name="vlan201", target_name="ethernet1/3.201", parent="ethernet1/3", tag=201)
    assert not PANSetRenderer().render(PANMigrationPlan(interfaces=(*interfaces, child))).commands
    distinct = tuple(replace(item, target_name=f"ethernet1/3.{201 + index}", parent="ethernet1/3", tag=201 + index)
                     for index, item in enumerate(interfaces))
    assert not [item for item in validate_plan(PANMigrationPlan(interfaces=distinct)).issues
                if item.code == "TARGET_INTERFACE_ALREADY_ASSIGNED"]


def test_device_scoped_route_does_not_require_target_vsys():
    route = PlannedStaticRoute(
        source_object_type="static_route", source_name="default", target_name="default",
        target_vsys=None, status=PANMigrationStatus.SUPPORTED,
        destination="0.0.0.0/0", nexthop_type="ip-address", nexthop="192.0.2.1",
        virtual_router="default",
    )
    result = validate_plan(PANMigrationPlan(static_routes=(route,)))
    assert not result.issues
    assert result.renderable_item_keys


@pytest.mark.parametrize('mapped', [False, True])
def test_cli_scope_readiness_matches_actual_commands(tmp_path, mapped):
    import json
    from click.testing import CliRunner
    from fwmigrate.main import cli

    source = tmp_path / 'source.conf'
    source.write_text('''config firewall address
edit "host"
set type ipmask
set subnet 192.0.2.1 255.255.255.255
next
end
config firewall service custom
edit "web"
set protocol TCP/UDP/SCTP
set tcp-portrange 443
next
end
config firewall schedule recurring
edit "work"
set day monday
set start 09:00
set end 17:00
next
end
''')
    output = tmp_path / 'output'
    args = ['migrate', '--input', str(source), '--output', str(output),
            '--automation-mode', 'REVIEW_ONLY']
    if mapped:
        mapping = tmp_path / 'mapping.yaml'
        mapping.write_text('vdoms:\n  root:\n    vsys: vsys2\n')
        args.extend(['--zone-map', str(mapping)])
    result = CliRunner().invoke(cli, args)
    assert result.exit_code == 0, result.output
    report = json.loads((output / 'migration_report.json').read_text())
    commands = (output / 'palo_alto_config.set').read_text().splitlines()
    assert report['commands'] == len(commands)
    assert report['command_renderable'] == report['satisfied'] == (3 if mapped else 0)
    assert all(row['rendered'] == row['command_renderable'] == mapped for row in report['items'])
    assert all(command.startswith('set vsys vsys2 ') for command in commands)
    if not mapped:
        assert all('missing_target_vsys' in row['render_blockers'] for row in report['items'])

# --- test_explicit_mapping_scope.py ---
@pytest.mark.parametrize("options", [
    {"vdoms": {"ghost": {"vsys": "vsys1"}}},
    {"interfaces": {"root": {"ghost": {"target_zone": "trust"}}}},
    {"interfaces": {"blue": {"wan": {"target_interface": "ethernet1/1"}}}},
    {"zones": {"root": {"ghost": {"target_zone": "trust"}}}},
    {"interfaces": {"root": {"dmz": {"target_interface": "ethernet1/1"}}}},
])
def test_explicit_mapping_rejects_nonexistent_or_cross_scope_sources(options):
    source = FGConfig(interfaces=[FGInterface(name="wan")], zones=[FGZone(name="dmz")])
    with pytest.raises(ValueError, match="source"):
        apply_explicit_options(source, PANMigrationDecisionSet(), options)


def test_valid_optional_and_legacy_zone_mappings_remain_compatible():
    source = FGConfig(interfaces=[FGInterface(name="wan")], zones=[FGZone(name="dmz")])
    decisions = apply_explicit_options(source, PANMigrationDecisionSet(), PANMigrationOptions(
        vdoms={"root": {"vsys": "vsys1"}}, interfaces={"root": {
            "wan": {"target_interface": "ethernet1/1"}, "dmz": {"target_zone": "dmz"},
        }},
    ))
    assert decisions.to_options().zones["root"]["dmz"].target_zone == "dmz"
    assert all(item.review_state is PANDecisionReviewState.CONFIRMED for item in decisions.decisions)


def test_changed_mapping_clears_previous_operation_approval():
    source = FGConfig(interfaces=[FGInterface(name="wan")])
    old = PANMigrationDecision("root", "interface", "wan", "target_interface",
        value="ethernet1/1", review_state=PANDecisionReviewState.CONFIRMED,
        approved_operation="CONFIGURE", approval_context={"candidate": "old"})
    options = {"interfaces": {"root": {"wan": {"target_interface": "ethernet1/2"}}}}
    changed = apply_explicit_options(source, PANMigrationDecisionSet((old,)), options).decisions[0]
    assert changed.approved_operation is None
    assert changed.approval_context is None
    assert changed.evidence_source == "ENGINEER"
    unchanged = apply_explicit_options(source, PANMigrationDecisionSet((replace(old, value="ethernet1/2"),)), options).decisions[0]
    assert unchanged.approved_operation == "CONFIGURE"
