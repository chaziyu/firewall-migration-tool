from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config


FIELDS = (
    "utm_status",
    "inspection_mode",
    "ztna_status",
    "timeout_send_rst",
    "auto_asic_offload",
    "np_acceleration",
    "port_preserve",
)


def _policy(settings=""):
    config = f"""config firewall policy
    edit 1
        set action accept
{settings}    next
end
"""
    return extract_fortigate_config(config).canonical_ir.policies[0]


def test_all_policy_settings_use_documented_effective_defaults_when_omitted():
    policy = _policy()

    assert {field: getattr(policy, f"source_{field}") for field in FIELDS} == {
        field: None for field in FIELDS
    }
    assert {
        field: getattr(policy, f"source_effective_{field}") for field in FIELDS
    } == {
        "utm_status": "disable",
        "inspection_mode": "flow",
        "ztna_status": "disable",
        "timeout_send_rst": "disable",
        "auto_asic_offload": "enable",
        "np_acceleration": "enable",
        "port_preserve": "enable",
    }


def test_explicit_defaults_remain_distinguishable_from_omitted_values():
    policy = _policy(
        """        set utm-status disable
        set inspection-mode flow
        set ztna-status disable
        set timeout-send-rst disable
        set auto-asic-offload enable
        set np-acceleration enable
        set port-preserve enable
"""
    )

    assert {field: getattr(policy, f"source_{field}") for field in FIELDS} == {
        "utm_status": "disable",
        "inspection_mode": "flow",
        "ztna_status": "disable",
        "timeout_send_rst": "disable",
        "auto_asic_offload": "enable",
        "np_acceleration": "enable",
        "port_preserve": "enable",
    }
    assert {
        field: getattr(policy, f"source_effective_{field}") for field in FIELDS
    } == {
        field: getattr(policy, f"source_{field}") for field in FIELDS
    }


def test_explicit_non_defaults_override_effective_defaults():
    policy = _policy(
        """        set utm-status enable
        set inspection-mode proxy
        set ztna-status enable
        set timeout-send-rst enable
        set auto-asic-offload disable
        set np-acceleration disable
        set port-preserve disable
"""
    )

    assert {
        field: getattr(policy, f"source_effective_{field}") for field in FIELDS
    } == {
        field: getattr(policy, f"source_{field}") for field in FIELDS
    }


def test_unknown_typed_value_is_preserved_and_requires_review():
    policy = _policy("        set np-acceleration future-mode\n")

    assert policy.source_np_acceleration == "future-mode"
    assert policy.source_effective_np_acceleration == "future-mode"
    assert policy.requires_manual_review is True
    assert "future-mode" in " ".join(policy.review_reasons)
