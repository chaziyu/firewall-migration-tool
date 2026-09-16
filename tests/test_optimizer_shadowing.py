from fwmigrate.core.optimizer import RuleOptimizer
from fwmigrate.ir import IRConfig, IRMetadata, IRPolicy
from fwmigrate.ir.enums import PolicyAction


def _policy(name, **overrides):
    values = {
        "name": name,
        "from_zone": ["lan"],
        "to_zone": ["wan"],
        "source": ["src"],
        "destination": ["dst"],
        "service": ["https"],
        "action": PolicyAction.ALLOW,
    }
    values.update(overrides)
    return IRPolicy(**values)


def _optimizer(*policies):
    return RuleOptimizer(IRConfig(
        metadata=IRMetadata(source_vendor="test"),
        policies=list(policies),
    ))


def _reference_shadowed(policies):
    shadowed = []
    for i, current in enumerate(policies):
        if not current.safe_for_target_generation:
            continue
        for j, preceding in enumerate(policies[:i]):
            if not preceding.safe_for_target_generation:
                continue

            def is_subset(current_values, preceding_values, any_keywords):
                if not current_values:
                    return True
                if not preceding_values:
                    return False
                if any(keyword in preceding_values for keyword in any_keywords):
                    return True
                return set(current_values).issubset(set(preceding_values))

            if (
                is_subset(current.source, preceding.source, ["any", "all"])
                and is_subset(current.destination, preceding.destination, ["any", "all"])
                and is_subset(current.service, preceding.service, ["any", "ALL"])
                and (
                    (not preceding.from_zone or "any" in preceding.from_zone)
                    or set(current.from_zone).issubset(set(preceding.from_zone))
                )
                and (
                    (not preceding.to_zone or "any" in preceding.to_zone)
                    or set(current.to_zone).issubset(set(preceding.to_zone))
                )
            ):
                shadowed.append({
                    "rule": current.name,
                    "rule_index": i + 1,
                    "shadowed_by": preceding.name,
                    "shadowed_by_index": j + 1,
                    "action_match": preceding.action == current.action,
                })
                break
    return shadowed


def test_shadow_analysis_preserves_first_matching_rule_and_action_metadata():
    result = _optimizer(
        _policy("broad", source=["any"], destination=["any"], service=["ALL"]),
        _policy("also-broad", source=["any"], destination=["any"], service=["any"]),
        _policy("narrow", source=["src"], destination=["dst"], service=["https"], action=PolicyAction.DENY),
    ).find_shadowed_rules()

    assert result[-1] == {
        "rule": "narrow",
        "rule_index": 3,
        "shadowed_by": "broad",
        "shadowed_by_index": 1,
        "action_match": False,
    }


def test_shadow_analysis_handles_zone_and_object_subsets():
    result = _optimizer(
        _policy(
            "broad",
            from_zone=["lan", "dmz"],
            to_zone=["wan", "dmz"],
            source=["src", "src2"],
            destination=["dst", "dst2"],
            service=["https", "dns"],
        ),
        _policy("narrow", source=["src"], destination=["dst"], service=["https"]),
    ).find_shadowed_rules()

    assert result[0]["shadowed_by"] == "broad"


def test_shadow_analysis_handles_any_zones_and_skips_unsafe_policies():
    result = _optimizer(
        _policy("unsafe", source=["any"], destination=["any"], service=["any"], requires_manual_review=True),
        _policy("any-zones", from_zone=[], to_zone=[], source=["any"], destination=["any"], service=["any"]),
        _policy("narrow", source=["src"], destination=["dst"], service=["https"]),
    ).find_shadowed_rules()

    assert result == [{
        "rule": "narrow",
        "rule_index": 3,
        "shadowed_by": "any-zones",
        "shadowed_by_index": 2,
        "action_match": True,
    }]


def test_shadow_analysis_matches_reference_for_mixed_rulebase():
    policies = [
        _policy("any", from_zone=[], to_zone=[], source=["any"], destination=["any"], service=["any"]),
        _policy("subset", source=["src"], destination=["dst"], service=["https"]),
        _policy("different-action", source=["other"], action=PolicyAction.DENY),
        _policy("unsafe", source=["any"], requires_manual_review=True),
        _policy("later", source=["src"], destination=["dst"], service=["https"]),
    ]

    actual = RuleOptimizer(IRConfig(
        metadata=IRMetadata(source_vendor="test"),
        policies=policies,
    )).find_shadowed_rules()

    assert actual == _reference_shadowed(policies)
