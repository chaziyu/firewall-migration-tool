from fwmigrate.conversion.fortigate_to_palo_alto import (
    PANDecisionMode, PANDecisionReviewState, PANMigrationDecision,
    PANMigrationDecisionSet, PANRecommendationMethod, build_recommendations,
)
from fwmigrate.conversion.fortigate_to_palo_alto.target_candidates import (
    PANTargetCandidateMatchClass, build_target_candidates, classify_candidate,
)
from fwmigrate.vendors.fortigate.model.dhcp import FGDHCPServer
from fwmigrate.vendors.fortigate.model.source import FGConfig
from fwmigrate.vendors.palo_alto.model.dhcp import PANDHCPServer
from fwmigrate.vendors.palo_alto.model.source import PANOSConfig
from fwmigrate.vendors.palo_alto.native import build_derived_views
from fwmigrate.vendors.palo_alto.source_model import PANScope


def _scope(kind, name, *, device=None, vsys=None):
    return PANScope(kind=kind, name=name, device_name=device, vsys=vsys)


def _target():
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


def _vsys_decision(value="vsys1"):
    return PANMigrationDecision(
        "root", "vdom", "root", "vsys", value=value, mode=PANDecisionMode.REQUIRED,
        review_state=PANDecisionReviewState.CONFIRMED,
    )


def test_same_name_candidate_is_limited_to_selected_device_and_confirmed_vsys():
    candidates = build_target_candidates(_target(), "dhcp_servers", "dhcp-server", "scope-test",
                                         "fw-a", "vsys1")
    assert len(candidates) == 1
    assert candidates[0].source_path == "vsys1/dhcp"
    assert candidates[0].scope_identity == "vsys:vsys1:device:fw-a"
    assert candidates[0].match_class is PANTargetCandidateMatchClass.POSSIBLE
    assert candidates[0].supporting_evidence == ("same name and PAN-OS object family",)


def test_shared_target_candidate_is_visible_without_matching_device_identity():
    candidates = build_target_candidates(_target(), "dhcp_servers", "dhcp-server", "shared-server",
                                         "fw-missing", "vsys1")
    assert len(candidates) == 1
    assert candidates[0].scope_identity == "shared:shared"


def test_unconfirmed_vsys_never_surfaces_same_name_from_other_vsys():
    candidates = build_target_candidates(_target(), "dhcp_servers", "dhcp-server", "scope-test",
                                         "fw-a", None)
    assert candidates == ()


def test_unrelated_target_inventory_does_not_change_recommendation_method():
    source = FGConfig(dhcp_servers=[FGDHCPServer(id=99, interface="port1")])
    decisions = PANMigrationDecisionSet((_vsys_decision(),))
    recommendation = build_recommendations(source, object(), decisions, _target(), "fw-a")[0]
    assert recommendation.method is PANRecommendationMethod.DETERMINISTIC
    assert recommendation.candidate_target_objects == ()
    assert recommendation.target_candidates == ()


def test_matching_scoped_object_is_serialized_as_typed_target_evidence():
    source = FGConfig(dhcp_servers=[FGDHCPServer(id=1, interface="port1")])
    decisions = PANMigrationDecisionSet((_vsys_decision(),))
    recommendation = build_recommendations(source, object(), decisions, _target(), "fw-a")[0]
    assert recommendation.method is PANRecommendationMethod.TARGET_EVIDENCE
    assert recommendation.candidate_target_objects == ("1",)
    assert recommendation.target_candidates[0].match_class is PANTargetCandidateMatchClass.POSSIBLE
    serialized = recommendation.to_dict()["target_candidates"][0]
    assert serialized["source_path"] == "vsys1/dhcp-one"
    assert serialized["scope_identity"] == "vsys:vsys1:device:fw-a"


def test_candidate_comparison_classes_use_explainable_evidence():
    assert classify_candidate(strong_evidence=("matching gateway",)) is PANTargetCandidateMatchClass.LIKELY_REUSE
    assert classify_candidate(supporting_evidence=("same name",)) is PANTargetCandidateMatchClass.POSSIBLE
    assert classify_candidate(contradictions=("different subnet",)) is PANTargetCandidateMatchClass.CONFLICT
    assert classify_candidate(exact_equivalent=True) is PANTargetCandidateMatchClass.EXACT_EQUIVALENT
