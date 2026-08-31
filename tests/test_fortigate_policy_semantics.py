from pathlib import Path

from fwmigrate.parsers.fortigate.model import FGConfig, FGPolicy
from fwmigrate.parsers.fortigate.parser import parse_fortigate_config
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer


def _review_reasons(policy: FGPolicy, policy_based_contexts=None):
    transformer = FGToIRTransformer(FGConfig())
    return transformer._get_policy_semantic_review_reasons(policy)


def test_policy_without_special_semantics_has_no_review_reasons():
    assert _review_reasons(FGPolicy(id=1)) == []


def test_ipsec_action_requires_review():
    assert _review_reasons(FGPolicy(id=1, action="ipsec")) == [
        "policy-based IPsec action",
    ]


def test_unknown_action_requires_review():
    assert _review_reasons(FGPolicy(id=1, action="vendor-future-action")) == [
        "unrecognized action 'vendor-future-action'",
    ]


def test_proxy_inspection_requires_review():
    assert _review_reasons(FGPolicy(id=1, inspection_mode="proxy")) == [
        "FortiGate proxy inspection mode requires target-platform review",
    ]


def test_ztna_requires_review():
    assert _review_reasons(FGPolicy(id=1, ztna_status="enable")) == [
        "FortiGate ZTNA policy semantics require target-platform review",
    ]


def test_unknown_traffic_setting_requires_review():
    reasons = _review_reasons(
        FGPolicy(id=1, extra_settings={"timeout_send_rst": "enable"})
    )

    assert reasons == [
        "Retained unknown traffic-affecting FortiGate policy settings: timeout_send_rst",
    ]


def test_unknown_setting_values_preserve_their_original_shapes_in_ir():
    source_settings = {
        "single_string": "retain-me",
        "integer_value": 42,
        "list_value": ["first", "second"],
        "enabled_value": "enable",
        "disabled_value": "disable",
    }
    source_policy = FGPolicy(
        id=1,
        srcintf=["LAN"],
        dstintf=["WAN"],
        srcaddr=["LAN_NET"],
        dstaddr=["all"],
        service=["HTTPS"],
        action="accept",
        extra_settings=source_settings,
    )

    ir = FGToIRTransformer(FGConfig(policies=[source_policy])).transform()

    assert ir.policies[0].source_extra_settings == source_settings


def test_unknown_settings_keep_source_order_in_one_review_reason():
    reasons = _review_reasons(
        FGPolicy(
            id=1,
            extra_settings={
                "zeta_setting": "one",
                "alpha_setting": "two",
            },
        )
    )

    assert reasons == [
        "Retained unknown traffic-affecting FortiGate policy settings: "
        "zeta_setting, alpha_setting",
    ]


def test_cosmetic_settings_do_not_require_review():
    assert _review_reasons(
        FGPolicy(
            id=1,
            extra_settings={
                "color": "3",
                "label": "display-only",
                "global_label": "global-display-only",
            },
        )
    ) == []


def test_unsupported_nat_semantics_require_review():
    assert _review_reasons(FGPolicy(id=1, nat46="enable")) == [
        "FortiGate unsupported NAT behavior is retained in typed source settings: nat46",
    ]


def test_combined_review_reasons_are_unique_and_drive_policy_status():
    config = """
config firewall policy
    edit 1
        set action accept
        set inspection-mode proxy
        set ztna-status enable
        set timeout-send-rst enable
    next
end
"""

    ir = FGToIRTransformer(parse_fortigate_config(config)).transform()
    policy = ir.policies[0]

    expected = [
        "FortiGate proxy inspection mode requires target-platform review",
        "FortiGate ZTNA policy semantics require target-platform review",
        "Retained unknown traffic-affecting FortiGate policy settings: timeout_send_rst",
    ]
    assert policy.review_reasons == expected
    assert len(policy.review_reasons) == len(set(policy.review_reasons))
    assert policy.migration_status == "PARTIALLY_NORMALIZED"
    assert policy.requires_manual_review is True


def test_duplicate_source_references_do_not_duplicate_review_reasons():
    reasons = _review_reasons(
        FGPolicy(id=1, groups=["missing-group", "missing-group"])
    )

    assert len(reasons) == len(set(reasons))
    assert reasons.count("unresolved identity group reference(s): missing-group") == 1


def test_policy_based_ngfw_context_requires_review():
    config = """
config vdom
edit "tenant-a"
    config system settings
        set ngfw-mode policy-based
    end
    config firewall policy
        edit 7
            set action accept
        next
    end
next
end
"""

    ir = FGToIRTransformer(parse_fortigate_config(config)).transform()
    policy = ir.policies[0]

    assert policy.source_context == "tenant-a"
    assert (
        "VDOM uses policy-based NGFW mode; conventional firewall policy is not complete without security-policy semantics"
        in policy.review_reasons
    )
    assert policy.migration_status == "PARTIALLY_NORMALIZED"
    assert policy.requires_manual_review is True


def test_example_fortigate_policies_keep_existing_review_boundaries():
    fixture = Path(__file__).parent / "fixtures" / "example_fortigate.conf"
    ir = FGToIRTransformer(
        parse_fortigate_config(fixture.read_text(encoding="utf-8"))
    ).transform()
    policies = {policy.source_rule_id: policy for policy in ir.policies}

    assert policies["3"].migration_status == "NORMALIZED"
    assert policies["3"].requires_manual_review is False
    assert policies["3"].review_reasons == []
    assert all(
        len(policy.review_reasons) == len(set(policy.review_reasons))
        for policy in policies.values()
    )
