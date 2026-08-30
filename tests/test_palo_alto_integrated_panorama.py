from pathlib import Path

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.palo_alto.parser import PANOSSourceParser


FIXTURE = Path(__file__).parent / "fixtures" / "palo_alto" / "integrated_panorama.xml"


def _extract():
    parser = PANOSSourceParser()
    result = parser.extract(FIXTURE.read_text(encoding="utf-8"))
    return parser, result


def test_integrated_panorama_hierarchy_shadowing_and_profile_resolution():
    _, result = _extract()
    child = next(policy for policy in result.canonical_ir.policies if policy.name == "child-pre")
    parent = next(policy for policy in result.canonical_ir.policies if policy.name == "parent-pre")
    assert child.source == ["child::shadowed"]
    assert parent.source == ["parent::shadowed"]
    assert child.security_profile_group == "child-profiles"
    assert parent.security_profile_group == "parent-profiles"


def test_integrated_panorama_security_nat_defaults_and_profile_groups_have_terminal_outcomes():
    _, result = _extract()
    assert len([item for item in result.inventory_items if item.domain == "policies"]) == 6
    assert len([item for item in result.inventory_items if item.domain == "nat"]) == 2
    assert len([item for item in result.inventory_items if item.domain == "default_security_rules"]) == 3
    assert len([item for item in result.inventory_items if item.domain == "profile_groups"]) == 3
    assert len({item.source_record_id for item in result.inventory_items}) == len(result.inventory_items)


def test_integrated_panorama_effective_order_and_rulebase_provenance():
    _, result = _extract()
    context = "device-group:child"
    ordered = []
    for item in result.inventory_items:
        position = item.source_attributes.get("pan_effective_order_by_context", {}).get(context)
        if position and item.domain == "policies":
            ordered.append((position["effective_policy_rank"], item.name,
                            item.source_attributes["pan_rulebase_position"]))
    ordered.sort()
    assert [(name, position) for _, name, position in ordered] == [
        ("shared-pre", "pre"), ("parent-pre", "pre"), ("child-pre", "pre"),
        ("child-post", "post"), ("parent-post", "post"), ("shared-post", "post")]


def test_integrated_panorama_relationship_and_unsupported_evidence_are_visible():
    _, result = _extract()
    relation = next(item for item in result.inventory_items if item.domain == "panorama_hierarchy"
                    and item.name == "vsys1")
    assert relation.source_attributes["pan_device_group"] == "child"
    future = next(item for item in result.inventory_items if item.domain == "policy:future-policy")
    assert future.status == ExtractionStatus.UNSUPPORTED
    assert "retain-panorama-evidence" in str(future.source_attributes)


def test_integrated_panorama_no_missing_match_or_action_is_widened():
    _, result = _extract()
    for policy in result.canonical_ir.policies:
        assert policy.source_address_references
        assert policy.destination_address_references
        assert policy.source_action in {"allow", "deny"}
