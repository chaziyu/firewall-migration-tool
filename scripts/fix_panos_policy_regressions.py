from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    target = Path(path)
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{path}: expected one occurrence, found {count}: {old[:100]!r}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


# A policy cannot simultaneously use PAN profile-group and direct-profile
# assignment branches.  Keep this fail-closed even for manually constructed IR.
replace_once(
    "src/fwmigrate/generators/policy_capabilities.py",
    '''        if self._exceeds(policy.security_profile_groups, self.max_profile_groups):
            reasons.append(
                f"{len(policy.security_profile_groups)} security profile groups"
            )

        for field_name, label in PROFILE_FIELDS:
''',
    '''        if self._exceeds(policy.security_profile_groups, self.max_profile_groups):
            reasons.append(
                f"{len(policy.security_profile_groups)} security profile groups"
            )

        has_direct_profiles = any(
            bool(getattr(policy, field_name, []) or [])
            for field_name, _ in PROFILE_FIELDS
        )
        if policy.security_profile_groups and has_direct_profiles:
            reasons.append("mixed profile-group and direct profile assignment")

        for field_name, label in PROFILE_FIELDS:
''',
)

# If a profile group exists in the source IR but was withheld, do not synthesize
# an empty group and then emit a policy that references weakened semantics.
replace_once(
    "src/fwmigrate/generators/palo_alto/transformer.py",
    '''        # 5.5 Transform Security Profile Groups
        existing_groups = set()
        for pg in self.ir.security_profile_groups:
''',
    '''        # 5.5 Transform Security Profile Groups
        existing_groups = set()
        source_profile_group_names = {pg.name for pg in self.ir.security_profile_groups}
        for pg in self.ir.security_profile_groups:
''',
)
replace_once(
    "src/fwmigrate/generators/palo_alto/transformer.py",
    '''            rule_name = p.name
            action = p.action.value
            disabled = "yes" if p.disabled else "no"

            # Preserve every referenced profile group.  Missing definitions are
''',
    '''            withheld_profile_groups = [
                name for name in p.security_profile_groups
                if name in source_profile_group_names and name not in existing_groups
            ]
            if withheld_profile_groups:
                self.ir.audit_entries.append(IRAuditEntry(
                    id=f"panos-policy-profile-group:{p.source_rule_id or p.name}",
                    category="PAN-OS Policy",
                    message=(
                        f"Policy '{p.name}' was withheld because referenced security "
                        "profile groups were not safe to emit: "
                        + ", ".join(withheld_profile_groups)
                    ),
                    confidence=MigrationConfidence.MANUAL,
                ))
                continue

            rule_name = p.name
            action = p.action.value
            disabled = "yes" if p.disabled else "no"

            # Preserve every referenced profile group.  A reference with no IR
            # definition may denote a pre-existing target object; a source IR
            # group that was withheld is handled above and cannot be weakened.
''',
)

# Existing policy regressions now assert exact canonical action/category values.
replace_once(
    "tests/test_palo_alto_policies.py",
    '''def test_drop_source_action_preserved():
    policy = _policy(_extract(), "Drop-Rule")
    assert policy.action == PolicyAction.DENY
    assert policy.source_action == "drop"


def test_reset_client_source_action_preserved():
    assert _policy(_extract(), "Reset-Client").source_action == "reset-client"


def test_reset_server_source_action_preserved():
    assert _policy(_extract(), "Reset-Server").source_action == "reset-server"


def test_reset_both_source_action_preserved():
    assert _policy(_extract(), "Reset-Both").source_action == "reset-both"
''',
    '''def test_drop_source_action_preserved():
    policy = _policy(_extract(), "Drop-Rule")
    assert policy.action == PolicyAction.DROP
    assert policy.source_action == "drop"


def test_reset_client_source_action_preserved():
    policy = _policy(_extract(), "Reset-Client")
    assert policy.action == PolicyAction.RESET_CLIENT
    assert policy.source_action == "reset-client"


def test_reset_server_source_action_preserved():
    policy = _policy(_extract(), "Reset-Server")
    assert policy.action == PolicyAction.RESET_SERVER
    assert policy.source_action == "reset-server"


def test_reset_both_source_action_preserved():
    policy = _policy(_extract(), "Reset-Both")
    assert policy.action == PolicyAction.RESET_BOTH
    assert policy.source_action == "reset-both"
''',
)
replace_once(
    "tests/test_palo_alto_policies.py",
    '''def test_category_preserved():
    policy = _policy(_extract(), "Identity-Category-HIP")
    assert policy.source_extra_settings["pan_category"] == ["adult", "malware"]
    assert "category" in policy.review_reasons
''',
    '''def test_category_preserved():
    policy = _policy(_extract(), "Identity-Category-HIP")
    assert policy.source_extra_settings["pan_category"] == ["adult", "malware"]
    assert policy.url_categories == ["adult", "malware"]
    assert policy.url_category_reference_statuses == {
        "category[0]": "predefined",
        "category[1]": "predefined",
    }
    assert "category" not in policy.review_reasons
''',
)

# Schema-version tests follow the additive 1.50 update.
replace_once(
    "tests/test_ir_schema_version.py",
    '    assert IR_SCHEMA_VERSION == "1.49"',
    '    assert IR_SCHEMA_VERSION == "1.50"',
)
replace_once(
    "tests/test_ir_schema_version.py",
    '@pytest.mark.parametrize("value", ["0.9", "1.50", "2.0"])',
    '@pytest.mark.parametrize("value", ["0.9", "1.51", "2.0"])',
)

# FortiGate now withholds these groups via explicit target capability checks.
replace_once(
    "tests/test_fortigate_generator_safety.py",
    '''    assert "Security profile group With_Child_AV withheld: referenced child security profiles are not generated" in cli_content
    assert "Security profile group With_Anti_Spyware withheld: unsupported profile semantics" in cli_content
''',
    '''    assert "Security profile group With_Child_AV withheld: target capability does not support 1 antivirus members" in cli_content
    assert "Security profile group With_Anti_Spyware withheld: target capability does not support 1 anti-spyware members" in cli_content
''',
)

# Legacy scalar fields are compatibility projections; canonical lists are
# authoritative after construction and must be cleared when isolating a test.
replace_once(
    "tests/test_multi_vendor_matrix.py",
    '''        grp.antivirus = None
        grp.vulnerability = None
        grp.url_filtering = None
        grp.ssl_decryption = None
''',
    '''        grp.antivirus = None
        grp.vulnerability = None
        grp.url_filtering = None
        grp.antivirus_profiles = []
        grp.vulnerability_profiles = []
        grp.antispyware_profiles = []
        grp.url_filtering_profiles = []
        grp.file_blocking_profiles = []
        grp.wildfire_analysis_profiles = []
        grp.data_filtering_profiles = []
        grp.ssl_decryption = None
''',
)
replace_once(
    "tests/test_multi_vendor_matrix.py",
    '''def test_palo_alto_generator_applies_target_defaults_for_partial_ir_profiles():
    """Verify that IR with partial profiles receives target-required defaults from PAN-OS transformer."""
''',
    '''def test_palo_alto_generator_withholds_partial_profiles_without_fabricated_defaults():
    """Partial profile semantics must be withheld instead of filled with target defaults."""
''',
)
replace_once(
    "tests/test_multi_vendor_matrix.py",
    '''    # Profile group XML contains target defaults for unset IR fields
    assert '<entry name="SPG_IPS_default">' in xml_content
    assert "<vulnerability>" in xml_content
    assert "<virus>" in xml_content
    assert "<spyware>" in xml_content
    assert "<file-blocking>" in xml_content
    assert "<wildfire-analysis>" in xml_content
    assert "<member>basic-file-blocking</member>" in xml_content
''',
    '''    # The source group is partial and the policy mixes group/direct profile
    # assignment.  Neither condition may be repaired with invented defaults.
    assert '<entry name="SPG_IPS_default">' not in xml_content
    assert '<entry name="Allow_Web">' not in xml_content
    assert "<member>basic-file-blocking</member>" not in xml_content
    assert any(
        "mixed profile-group and direct profile assignment" in entry.message
        for entry in ir.audit_entries
    )
''',
)

print("Aligned regression expectations with schema 1.50 lossless semantics")
