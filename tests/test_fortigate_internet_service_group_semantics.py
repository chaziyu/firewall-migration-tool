from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config


def _extract(direction: str | None, field: str = "internet-service-src-group"):
    direction_line = f"set direction {direction}" if direction else ""
    section = "firewall local-in-policy6" if field.endswith("6-src-group") else "firewall local-in-policy"
    return extract_fortigate_config(f'''config firewall internet-service-group
    edit "GROUP-A"
        {direction_line}
        set member "IS-A" "IS-B"
    next
end
config {section}
    edit 1
        set {field} "GROUP-A"
    next
end
''')


def _extract_reference(source_path: str, field: str, direction: str | None, reference: str = "GROUP-A"):
    direction_line = f"set direction {direction}" if direction else ""
    group = f'''config firewall internet-service-group
    edit "GROUP-A"
        {direction_line}
    next
end
''' if reference == "GROUP-A" else ""
    return extract_fortigate_config(group + f'''config {source_path}
    edit 1
        set {field} "{reference}"
    next
end
''')


def test_inventory_preserves_group_direction_and_members():
    result = _extract("source")
    item = next(item for item in result.inventory_items if item.source_path == "firewall internet-service-group")
    assert [(command.key, command.values) for command in item.commands] == [
        ("direction", ["source"]), ("member", ["IS-A", "IS-B"])
    ]


def test_source_and_both_are_compatible():
    for direction in ("source", "both", None):
        result = _extract(direction)
        assert result.dependencies[0].result == "RESOLVED"
        assert not any(entry.category == "FortiGate Semantic Validation" for entry in result.canonical_ir.audit_entries)


def test_destination_is_resolved_but_requires_semantic_review():
    result = _extract("destination")
    dependency = result.dependencies[0]
    assert dependency.result == "RESOLVED"
    assert dependency.target_path == "firewall internet-service-group"
    assert any(entry.category == "FortiGate Semantic Validation" for entry in result.canonical_ir.audit_entries)
    item = next(item for item in result.inventory_items if item.source_path == "firewall local-in-policy")
    assert "incompatible-internet-service-group-direction:GROUP-A" in item.notes
    assert not any("unresolved-reference:GROUP-A" in note for note in item.notes)


def test_ipv6_direction_mismatch_keeps_exact_field_name():
    result = _extract("destination", "internet-service6-src-group")
    audit = next(entry for entry in result.canonical_ir.audit_entries if entry.category == "FortiGate Semantic Validation")
    assert "internet-service6-src-group" in audit.message


def test_unknown_direction_is_manual_review_without_coercion():
    result = _extract("future")
    assert "direction 'future'" in next(
        entry.message for entry in result.canonical_ir.audit_entries
        if entry.category == "FortiGate Semantic Validation"
    )


def test_supported_policy_fields_apply_direction_compatibility_and_rule_review():
    cases = [
        ("firewall local-in-policy", "internet-service-src-group", "source", "destination", "local_in_policies"),
        ("firewall local-in-policy6", "internet-service6-src-group", "source", "destination", "local_in_policies"),
        ("firewall policy", "internet-service-group", "destination", "source", "policies"),
        ("firewall policy", "internet-service-src-group", "source", "destination", "policies"),
        ("firewall policy", "internet-service6-group", "destination", "source", "policies"),
        ("firewall policy", "internet-service6-src-group", "source", "destination", "policies"),
        ("firewall security-policy", "internet-service-group", "destination", "source", "security_policies"),
        ("firewall security-policy", "internet-service-src-group", "source", "destination", "security_policies"),
        ("firewall security-policy", "internet-service6-group", "destination", "source", "security_policies"),
        ("firewall security-policy", "internet-service6-src-group", "source", "destination", "security_policies"),
    ]
    for source_path, field, valid_direction, invalid_direction, collection in cases:
        valid = _extract_reference(source_path, field, valid_direction)
        assert valid.dependencies[0].result == "RESOLVED"
        assert not any(entry.category == "FortiGate Semantic Validation" for entry in valid.canonical_ir.audit_entries)

        invalid = _extract_reference(source_path, field, invalid_direction)
        assert invalid.dependencies[0].result == "RESOLVED"
        assert any(entry.category == "FortiGate Semantic Validation" for entry in invalid.canonical_ir.audit_entries)
        rule = getattr(invalid.canonical_ir, collection)[0]
        assert rule.requires_manual_review
        assert any("requires" in reason and field in reason for reason in rule.review_reasons)


def test_both_and_default_direction_are_compatible_for_source_and_destination():
    for source_path, field in (
        ("firewall local-in-policy", "internet-service-src-group"),
        ("firewall policy", "internet-service-group"),
        ("firewall security-policy", "internet-service6-src-group"),
    ):
        for direction in ("both", None):
            result = _extract_reference(source_path, field, direction)
            assert result.dependencies[0].result == "RESOLVED"
            assert not any(entry.category == "FortiGate Semantic Validation" for entry in result.canonical_ir.audit_entries)


def test_unknown_direction_stays_resolved_but_requires_review():
    result = _extract_reference("firewall policy", "internet-service-group", "future")
    assert result.dependencies[0].result == "RESOLVED"
    assert result.canonical_ir.internet_service_groups[0].direction == "future"
    assert result.canonical_ir.policies[0].requires_manual_review
    assert any("direction 'future'" in entry.message for entry in result.canonical_ir.audit_entries)


def test_missing_group_is_unresolved_without_direction_mismatch():
    result = _extract_reference("firewall policy", "internet-service-group", "destination", "MISSING")
    assert result.dependencies[0].result == "UNRESOLVED"
    assert not any(entry.category == "FortiGate Semantic Validation" for entry in result.canonical_ir.audit_entries)
